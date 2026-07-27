from __future__ import annotations

import hashlib
import ipaddress
import secrets
import socket
import string
import struct
import zlib
from typing import Any

from backend.acp import ACPEncryptedTransport
from backend.acp import ACPPlainTransport
from backend.acp import ACP_STREAM_SIZE
from backend.acp import connect_acp
from backend.cfb0 import cfb0_dumps


PRINTABLE = set(string.printable)
ACP_PORT = 5009
ACP_VERSION = 0x00030001
SUPPORTED_ACP_RESPONSE_VERSIONS = frozenset((0x00000001, 0x00030000, ACP_VERSION))
ACP_MAGIC = b"acpp"
ACP_STATIC_KEY = bytes.fromhex("5b6faf5d9d5b0e1351f2da1de7e8d673")
COMMAND_GETPROP = 0x14
COMMAND_SETPROP = 0x15
COMMAND_LEGACY_KEY_EXCHANGE = 0x17
COMMAND_REBOOT = 0x1E
STREAMING_BODY_CHECKSUM = 1
HEADER = struct.Struct("!4s8i12x32s48x")
PROPERTY_HEADER = struct.Struct("!4s2I")

# AirPort Utility 5.6.1 uses this two-channel Diffie-Hellman exchange before
# reading or configuring the original (product 3) AirPort Extreme. Each
# exchange supplies one AES-CTR direction for the rest of the connection.
LEGACY_DH_MODULUS_BYTES = bytes.fromhex(
    "cf96f97faafc78931fb198eb589daf5f"
    "ed0196a383b9f152c497effc347ed92f"
    "da4a30ed6c7e17d4cb9305c19c1ab97c"
    "1793735fbbd0bb89eaca19945685bd3d"
    "7d0b58c908eb8462095f80689335006e"
    "8c7b36c122f2ad5eb15f5f46667efcd1"
    "78510446231e815f15575cc6595ac921"
    "2d4be233950f746e36cdf7601479afab"
)
LEGACY_DH_MODULUS = int.from_bytes(LEGACY_DH_MODULUS_BYTES, "big")
LEGACY_DH_GENERATOR = 2
LEGACY_KEY_EXCHANGE_SIZE = 304


class ACPError(RuntimeError):
    pass


class ACPProtocolError(ACPError):
    pass


class ACPAuthError(ACPError):
    pass


class ACPPropertyError(ACPError):
    pass


def signed_i32(value: int) -> int:
    value &= 0xFFFFFFFF
    if value >= 0x80000000:
        value -= 0x100000000
    return value


def adler32_i32(data: bytes) -> int:
    return signed_i32(zlib.adler32(data))


def format_error_code(error_code: int) -> str:
    if error_code < 0:
        return f"-0x{-error_code:x}"
    return f"0x{error_code:x}"


def generate_acp_keystream(length: int) -> bytes:
    return bytes(
        ((idx + 0x55) & 0xFF) ^ ACP_STATIC_KEY[idx % len(ACP_STATIC_KEY)]
        for idx in range(length)
    )


def generate_acp_header_key(password: str) -> bytes:
    password_bytes = password.encode("utf-8")[:32].ljust(32, b"\x00")
    key = generate_acp_keystream(32)
    return bytes(key[idx] ^ password_bytes[idx] for idx in range(32))


def compose_header(command: int, password: str, payload: bytes, *, flags: int = 0) -> bytes:
    body_checksum = adler32_i32(payload)
    key = generate_acp_header_key(password)
    checksum_input = HEADER.pack(
        ACP_MAGIC,
        ACP_VERSION,
        0,
        body_checksum,
        len(payload),
        flags,
        0,
        command,
        0,
        key,
    )
    return HEADER.pack(
        ACP_MAGIC,
        ACP_VERSION,
        adler32_i32(checksum_input),
        body_checksum,
        len(payload),
        flags,
        0,
        command,
        0,
        key,
    )


def compose_property_element(name: str | None, value: bytes | None, *, flags: int = 0) -> bytes:
    name_bytes = b"\x00\x00\x00\x00" if name is None else name.encode("ascii")
    if len(name_bytes) != 4:
        raise ACPPropertyError(f"ACP property names must be exactly 4 bytes: {name!r}")
    value_bytes = b"\x00\x00\x00\x00" if value is None else value
    return PROPERTY_HEADER.pack(name_bytes, flags, len(value_bytes)) + value_bytes


def _legacy_dh_key(peer_public: bytes, private: int) -> bytes:
    if len(peer_public) != len(LEGACY_DH_MODULUS_BYTES):
        raise ACPProtocolError("ACP17 peer public key has an invalid size")
    peer = int.from_bytes(peer_public, "big")
    if peer <= 1 or peer >= LEGACY_DH_MODULUS - 1:
        raise ACPProtocolError("ACP17 peer public key is outside the valid range")
    shared = pow(peer, private, LEGACY_DH_MODULUS).to_bytes(
        len(LEGACY_DH_MODULUS_BYTES), "big"
    )
    return hashlib.sha1(shared).digest()[:16]


def open_legacy_encrypted_transport(
    host: str,
    password: str,
    timeout: float = 25.0,
    *,
    private_a: int | None = None,
    private_b: int | None = None,
    request_iv: bytes | None = None,
    response_iv: bytes | None = None,
) -> ACPEncryptedTransport:
    """Negotiate the ACP17 encrypted transport used by product 3."""

    private_a = private_a or secrets.randbelow(LEGACY_DH_MODULUS - 3) + 2
    private_b = private_b or secrets.randbelow(LEGACY_DH_MODULUS - 3) + 2
    request_iv = request_iv or secrets.token_bytes(16)
    response_iv = response_iv or secrets.token_bytes(16)
    if len(request_iv) != 16 or len(response_iv) != 16:
        raise ValueError("ACP17 IVs must be exactly 16 bytes")

    body = bytearray(LEGACY_KEY_EXCHANGE_SIZE)
    body[0] = 1
    body[0x10:0x90] = pow(
        LEGACY_DH_GENERATOR, private_a, LEGACY_DH_MODULUS
    ).to_bytes(len(LEGACY_DH_MODULUS_BYTES), "big")
    body[0x90:0xA0] = request_iv
    body[0xA0:0x120] = pow(
        LEGACY_DH_GENERATOR, private_b, LEGACY_DH_MODULUS
    ).to_bytes(len(LEGACY_DH_MODULUS_BYTES), "big")
    body[0x120:0x130] = response_iv

    sock = connect_acp(host, timeout)
    try:
        sock.settimeout(timeout)
        plain = ACPPlainTransport(sock)
        plain.send(bytes(body), flags=4, command=COMMAND_LEGACY_KEY_EXCHANGE)
        header, response = plain.recv()
        if header.command != COMMAND_LEGACY_KEY_EXCHANGE:
            raise ACPProtocolError(
                f"ACP17 response command mismatch: got {header.command:#x}, "
                f"expected {COMMAND_LEGACY_KEY_EXCHANGE:#x}"
            )
        if header.status != 0:
            raise ACPAuthError(
                f"ACP17 key exchange failed with error_code "
                f"{format_error_code(header.status)}"
            )
        if len(response) != LEGACY_KEY_EXCHANGE_SIZE or response[0] != 1:
            raise ACPProtocolError("ACP17 key exchange returned an invalid response")
        return ACPEncryptedTransport(
            sock,
            _legacy_dh_key(response[0x10:0x90], private_a),
            _legacy_dh_key(response[0xA0:0x120], private_b),
            request_iv,
            response_iv,
            client_token=generate_acp_header_key(password),
            align_calls=True,
        )
    except Exception:
        sock.close()
        raise


def recv_exact(sock: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ACPProtocolError(f"ACP connection closed while reading {size} bytes")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def legacy_parse_header(data: bytes) -> tuple[int, int, int, int]:
    if len(data) != HEADER.size:
        raise ACPProtocolError(f"ACP header has {len(data)} bytes, expected {HEADER.size}")
    (
        magic,
        version,
        header_checksum,
        body_checksum,
        body_size,
        flags,
        unused,
        command,
        error_code,
        key,
    ) = HEADER.unpack(data)
    if magic != ACP_MAGIC:
        raise ACPProtocolError("ACP response had invalid magic")
    if version not in SUPPORTED_ACP_RESPONSE_VERSIONS:
        raise ACPProtocolError(f"ACP response had unsupported version {version:#x}")
    checksum_input = HEADER.pack(
        magic,
        version,
        0,
        body_checksum,
        body_size,
        flags,
        unused,
        command,
        error_code,
        key,
    )
    expected_checksum = adler32_i32(checksum_input)
    if header_checksum != expected_checksum:
        raise ACPProtocolError(
            f"ACP response header checksum mismatch: got {header_checksum:#x}, "
            f"expected {expected_checksum:#x}"
        )
    return command, error_code, body_size, body_checksum


def legacy_parse_property_header(data: bytes) -> tuple[str | None, int, int]:
    if len(data) != PROPERTY_HEADER.size:
        raise ACPProtocolError(
            f"ACP property header has {len(data)} bytes, expected {PROPERTY_HEADER.size}"
        )
    raw_name, flags, size = PROPERTY_HEADER.unpack(data)
    name = None if raw_name == b"\x00\x00\x00\x00" else raw_name.decode(
        "ascii",
        errors="replace",
    )
    return name, flags, size


def parse_property_results(body: bytes) -> list[tuple[str | None, int, bytes]]:
    results: list[tuple[str | None, int, bytes]] = []
    offset = 0
    while offset < len(body):
        end_header = offset + PROPERTY_HEADER.size
        if end_header > len(body):
            raise ACPProtocolError(
                f"ACP property header at offset {offset} extends past body size {len(body)}"
            )
        name, flags, size = legacy_parse_property_header(body[offset:end_header])
        end_value = end_header + size
        if end_value > len(body):
            raise ACPProtocolError(
                f"ACP property {name or '<end>'} value extends past body size {len(body)}"
            )
        data = body[end_header:end_value]
        if flags & 1:
            if len(data) == 4:
                error_code = struct.unpack(">i", data)[0]
                raise ACPPropertyError(
                    f"ACP property {name or '<end>'} failed with error_code "
                    f"{format_error_code(error_code)}"
                )
            raise ACPPropertyError(f"ACP property {name or '<end>'} failed")
        results.append((name, flags, data))
        offset = end_value
    return results


def read_property_result(sock: socket.socket) -> tuple[str | None, int, bytes]:
    name, flags, size = legacy_parse_property_header(recv_exact(sock, PROPERTY_HEADER.size))
    data = recv_exact(sock, size)
    if flags & 1:
        if len(data) == 4:
            error_code = struct.unpack(">i", data)[0]
            raise ACPPropertyError(
                f"ACP property {name or '<end>'} failed with error_code "
                f"{format_error_code(error_code)}"
            )
        raise ACPPropertyError(f"ACP property {name or '<end>'} failed")
    return name, flags, data


def get_property_raw(host: str, password: str, name: str, *, timeout: float = 25.0) -> bytes:
    payload = compose_property_element(name, None)
    message = compose_header(COMMAND_GETPROP, password, payload, flags=4) + payload
    with socket.create_connection((host, ACP_PORT), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(message)
        command, error_code, body_size, body_checksum = legacy_parse_header(
            recv_exact(sock, HEADER.size)
        )
        if command != COMMAND_GETPROP:
            raise ACPProtocolError(
                f"ACP response command mismatch: got {command:#x}, expected {COMMAND_GETPROP:#x}"
            )
        if error_code != 0:
            raise ACPAuthError(
                f"ACP command failed with error_code {format_error_code(error_code)} "
                "(likely wrong AirPort admin password)"
            )
        if body_size == -1:
            while True:
                prop_name, _flags, data = read_property_result(sock)
                if prop_name is None and data == b"\x00\x00\x00\x00":
                    raise ACPPropertyError(f"ACP property {name} was not returned")
                if prop_name == name:
                    return data
        if body_size == 0:
            raise ACPPropertyError(f"ACP property {name} was not returned")
        if body_size < -1:
            raise ACPProtocolError(f"ACP response had invalid body_size {body_size}")
        body = recv_exact(sock, body_size)
        checksum = adler32_i32(body)
        if checksum != body_checksum:
            raise ACPProtocolError(
                f"ACP response body checksum mismatch: got {checksum:#x}, "
                f"expected {body_checksum:#x}"
            )
    for prop_name, _flags, data in parse_property_results(body):
        if prop_name is None and data == b"\x00\x00\x00\x00":
            break
        if prop_name == name:
            return data
    raise ACPPropertyError(f"ACP property {name} was not returned")


def decode_auto(value: bytes) -> str:
    if len(value) == 4:
        integer = struct.unpack(">I", value)[0]
        return f"{integer} (0x{integer:08x})"

    stripped = value.rstrip(b"\x00")
    try:
        text = stripped.decode("utf-8")
    except UnicodeDecodeError:
        return value.hex()
    if text and all(ch in PRINTABLE for ch in text):
        return text
    if not text:
        return ""
    return value.hex()


def legacy_format_value(value: bytes) -> str:
    stripped = value.rstrip(b"\x00")
    try:
        text = stripped.decode("utf-8")
    except UnicodeDecodeError:
        text = ""
    if text and all(ch.isprintable() or ch in "\r\n\t" for ch in text):
        return text
    if len(value) == 4:
        return str(struct.unpack(">I", value)[0])
    return value.hex()


def legacy_setting_json_record(raw_value: bytes) -> dict[str, Any]:
    return {
        "type": "bytes",
        "hex": raw_value.hex(),
        "length": len(raw_value),
        "value": legacy_format_value(raw_value),
    }


def legacy_read_settings_bytes(
    host: str, password: str, settings: list[str], timeout: float
) -> tuple[dict[str, bytes], dict[str, str]]:
    values: dict[str, bytes] = {}
    errors: dict[str, str] = {}
    for setting in settings:
        try:
            values[setting] = get_property_raw(host, password, setting, timeout=timeout)
        except Exception as exc:
            errors[setting] = str(exc)
    return values, errors


def legacy_read_settings_bytes_acp17(
    host: str, password: str, settings: list[str], timeout: float
) -> tuple[dict[str, bytes], dict[str, str]]:
    """Batch-read properties through the encrypted product-3 transport."""

    payload = b"".join(compose_property_element(setting, None) for setting in settings)
    transport = open_legacy_encrypted_transport(host, password, timeout)
    values: dict[str, bytes] = {}
    errors: dict[str, str] = {}
    try:
        transport.send(payload, flags=4, command=COMMAND_GETPROP)
        header, body = transport.recv()
        if header.command != COMMAND_GETPROP:
            raise ACPProtocolError(
                f"ACP response command mismatch: got {header.command:#x}, "
                f"expected {COMMAND_GETPROP:#x}"
            )
        if header.status != 0:
            raise ACPAuthError(
                f"ACP get-property command failed with error_code "
                f"{format_error_code(header.status)}"
            )
        if header.body_size == ACP_STREAM_SIZE:
            while True:
                name, flags, size = legacy_parse_property_header(
                    transport.recv_decrypted(PROPERTY_HEADER.size)
                )
                data = transport.recv_decrypted(size)
                if name is None:
                    break
                if flags & 1:
                    status = struct.unpack(">i", data)[0] if len(data) == 4 else -1
                    errors[name] = (
                        f"ACP property {name} returned status {format_error_code(status)}"
                    )
                else:
                    values[name] = data
        else:
            for name, flags, data in parse_property_results(body):
                if name is not None and not (flags & 1):
                    values[name] = data
        for setting in settings:
            if setting not in values and setting not in errors:
                errors[setting] = f"ACP property {setting} was not returned"
        return values, errors
    finally:
        transport.sock.close()


def int32_value(value: int) -> bytes:
    return struct.pack(">I", value & 0xFFFFFFFF)


def int16_value(value: int) -> bytes:
    return struct.pack(">H", value & 0xFFFF)


def bool_value(value: bool) -> bytes:
    return b"\x01" if value else b"\x00"


LEGACY_IPV4_VALUE_SETTINGS = {
    "dhBg",
    "dhDB",
    "dhDE",
    "dhDS",
    "dhEn",
    "dhRo",
    "dhSN",
    "laIP",
    "laSM",
    "nDMZ",
    "raI1",
    "raI2",
    "slCl",
    "waD1",
    "waD2",
    "waD3",
    "waIP",
    "waRA",
    "waSM",
}


def encode_setting_value(setting: str, value: Any) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bool):
        if setting == "auRR":
            return int16_value(1 if value else 0)
        return bool_value(value)
    if isinstance(value, int):
        if setting in {"raMd", "raPo"}:
            return int16_value(value)
        return int32_value(value)
    if isinstance(value, str):
        if setting in LEGACY_IPV4_VALUE_SETTINGS:
            return ipaddress.IPv4Address(value).packed
        return value.encode("utf-8")
    if isinstance(value, (dict, list)):
        return cfb0_dumps(value)
    raise TypeError(f"unsupported value for {setting}: {type(value).__name__}")


def send_property_write(
    host: str,
    password: str,
    dirty: dict[str, Any],
    timeout: float,
    request_flags: int = 4,
) -> list[dict[str, Any]]:
    payload = b"".join(
        compose_property_element(setting, encode_setting_value(setting, value))
        for setting, value in dirty.items()
    )
    payload += compose_property_element(None, int32_value(0))
    message = compose_header(COMMAND_SETPROP, password, payload, flags=request_flags) + payload
    statuses: list[dict[str, Any]] = []
    with socket.create_connection((host, ACP_PORT), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(message)
        command, error_code, body_size, _body_checksum = legacy_parse_header(
            recv_exact(sock, 128)
        )
        if command != COMMAND_SETPROP:
            raise RuntimeError(
                f"ACP response command mismatch: got {command:#x}, expected {COMMAND_SETPROP:#x}"
            )
        if error_code != 0:
            raise RuntimeError(
                f"ACP set-property command failed with error_code {format_error_code(error_code)}"
            )
        if body_size == -1:
            while True:
                try:
                    name, flags, size = legacy_parse_property_header(
                        recv_exact(sock, PROPERTY_HEADER.size)
                    )
                except socket.timeout:
                    break
                data = recv_exact(sock, size)
                status = struct.unpack(">i", data)[0] if len(data) == 4 else 0
                statuses.append(
                    {
                        "setting": name,
                        "flags": flags,
                        "status": status,
                    }
                )
                if (flags & 1 or status) and not legacy_property_status_is_accepted(name, status):
                    label = name or "<end>"
                    raise RuntimeError(
                        f"ACP property {label} returned status {format_error_code(status)}"
                    )
                if name is None:
                    break
        elif body_size > 0:
            recv_exact(sock, body_size)
    return statuses


def compose_streaming_header(command: int, password: str, *, flags: int = 4) -> bytes:
    key = generate_acp_header_key(password)
    checksum_input = HEADER.pack(
        ACP_MAGIC,
        ACP_VERSION,
        0,
        STREAMING_BODY_CHECKSUM,
        -1,
        flags,
        0,
        command,
        0,
        key,
    )
    return HEADER.pack(
        ACP_MAGIC,
        ACP_VERSION,
        adler32_i32(checksum_input),
        STREAMING_BODY_CHECKSUM,
        -1,
        flags,
        0,
        command,
        0,
        key,
    )


def legacy_apply_dirty(dirty: dict[str, Any]) -> dict[str, Any]:
    apply_dirty = dict(dirty)
    apply_dirty["acFN"] = b""
    apply_dirty["acRB"] = b""
    return apply_dirty


def legacy_property_status_is_accepted(setting: str | None, status: int) -> bool:
    """Match advisory write statuses AirPort Utility accepts on legacy hardware."""

    return status == 0 or (setting == "ra1C" and status == -0xB)


def send_property_write_streaming(
    host: str,
    password: str,
    dirty: dict[str, Any],
    timeout: float,
    request_flags: int = 4,
) -> list[dict[str, Any]]:
    payloads = [
        compose_property_element(setting, encode_setting_value(setting, value))
        for setting, value in dirty.items()
    ]
    payloads.append(compose_property_element(None, int32_value(0)))
    statuses: list[dict[str, Any]] = []
    with socket.create_connection((host, ACP_PORT), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(compose_streaming_header(COMMAND_SETPROP, password, flags=request_flags))
        for payload in payloads:
            sock.sendall(payload)
        command, error_code, body_size, _body_checksum = legacy_parse_header(
            recv_exact(sock, 128)
        )
        if command != COMMAND_SETPROP:
            raise RuntimeError(
                f"ACP response command mismatch: got {command:#x}, expected {COMMAND_SETPROP:#x}"
            )
        if error_code != 0:
            raise RuntimeError(
                f"ACP set-property command failed with error_code {format_error_code(error_code)}"
            )
        if body_size == -1:
            while True:
                try:
                    name, flags, size = legacy_parse_property_header(
                        recv_exact(sock, PROPERTY_HEADER.size)
                    )
                except socket.timeout:
                    break
                data = recv_exact(sock, size)
                status = struct.unpack(">i", data)[0] if len(data) == 4 else 0
                statuses.append(
                    {
                        "setting": name,
                        "flags": flags,
                        "status": status,
                    }
                )
                if (flags & 1 or status) and not legacy_property_status_is_accepted(name, status):
                    label = name or "<end>"
                    raise RuntimeError(
                        f"ACP property {label} returned status {format_error_code(status)}"
                    )
                if name is None:
                    break
        elif body_size > 0:
            recv_exact(sock, body_size)
    return statuses


def send_property_write_streaming_acp17(
    host: str,
    password: str,
    dirty: dict[str, Any],
    timeout: float,
    request_flags: int = 4,
) -> list[dict[str, Any]]:
    """Write properties through the encrypted transport used by product 3."""

    payloads = [
        compose_property_element(setting, encode_setting_value(setting, value))
        for setting, value in dirty.items()
    ]
    payloads.append(compose_property_element(None, int32_value(0)))
    transport = open_legacy_encrypted_transport(host, password, timeout)
    statuses: list[dict[str, Any]] = []
    try:
        transport.send_stream_header(request_flags, COMMAND_SETPROP)
        for payload in payloads:
            transport.send_encrypted_stream(payload[:PROPERTY_HEADER.size])
            transport.send_encrypted_stream(payload[PROPERTY_HEADER.size:])
        header, body = transport.recv()
        if header.command != COMMAND_SETPROP:
            raise ACPProtocolError(
                f"ACP response command mismatch: got {header.command:#x}, "
                f"expected {COMMAND_SETPROP:#x}"
            )
        if header.status != 0:
            raise ACPAuthError(
                f"ACP set-property command failed with error_code "
                f"{format_error_code(header.status)}"
            )
        if header.body_size == ACP_STREAM_SIZE:
            while True:
                name, flags, size = legacy_parse_property_header(
                    transport.recv_decrypted(PROPERTY_HEADER.size)
                )
                data = transport.recv_decrypted(size)
                status = struct.unpack(">i", data)[0] if len(data) == 4 else 0
                statuses.append({"setting": name, "flags": flags, "status": status})
                if (flags & 1 or status) and not legacy_property_status_is_accepted(name, status):
                    raise ACPPropertyError(
                        f"ACP property {name or '<end>'} returned status "
                        f"{format_error_code(status)}"
                    )
                if name is None:
                    break
        elif body:
            for name, flags, data in parse_property_results(body):
                status = struct.unpack(">i", data)[0] if len(data) == 4 else 0
                statuses.append({"setting": name, "flags": flags, "status": status})
        return statuses
    finally:
        transport.sock.close()


def send_reboot(host: str, password: str, timeout: float) -> None:
    message = compose_header(COMMAND_REBOOT, password, b"", flags=4)
    with socket.create_connection((host, ACP_PORT), timeout=timeout) as sock:
        sock.settimeout(timeout)
        sock.sendall(message)
        command, error_code, body_size, _body_checksum = legacy_parse_header(
            recv_exact(sock, 128)
        )
        if command != COMMAND_REBOOT:
            raise RuntimeError(
                f"ACP response command mismatch: got {command:#x}, expected {COMMAND_REBOOT:#x}"
            )
        if error_code != 0:
            raise RuntimeError(
                f"ACP reboot command failed with error_code {format_error_code(error_code)}"
            )
        if body_size > 0:
            recv_exact(sock, body_size)
