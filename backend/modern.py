from __future__ import annotations

import argparse
import json
import re
import struct
import sys
from typing import Any

from backend.acp import ACPEncryptedTransport
from backend.acp import ACPPlainTransport
from backend.acp import ACP_MAX_BODY_SIZE
from backend.acp import ACP_PROPERTY_HEADER
from backend.acp import ACP_STREAM_SIZE
from backend.acp import connect_acp
from backend.cfb0 import CFB0_MAGIC
from backend.cfb0 import CFB0Integer
from backend.cfb0 import cfb0_loads
from backend.srp import authenticate
from backend.srp import derive_keys


def property_request(setting: str) -> bytes:
    """Build the 12-byte ACP get-property request body."""

    code = setting.encode("ascii")
    if len(code) != 4:
        raise ValueError("setting name must be exactly four ASCII characters")
    return ACP_PROPERTY_HEADER.pack(code, 0, 0)


def parse_property_record(record: bytes) -> tuple[str | None, int, int]:
    """Decode a 12-byte ACP property record header."""

    raw_name, flags, size = ACP_PROPERTY_HEADER.unpack(record)
    name = None if raw_name == b"\x00\x00\x00\x00" else raw_name.decode("ascii", "replace")
    return name, flags, size


def is_property_stream_terminator(name: str | None, value: bytes) -> bool:
    """Return True for the anonymous zero record that ends streamed results."""

    return name is None and value == b"\x00\x00\x00\x00"


def property_error_description(name: str | None, value: bytes) -> str:
    """Format a failed ACP property record as a readable exception string."""

    label = name or "<anonymous>"
    if len(value) == 4:
        code = struct.unpack(">i", value)[0]
        return f"property {label} failed with ACP status {code}"
    return f"property {label} failed"


def next_unreturned_setting(
    requested: list[str], results: dict[str, bytes], errors: dict[str, str]
) -> str | None:
    """Return the next requested setting without a response record."""

    for setting in requested:
        if setting not in results and setting not in errors:
            return setting
    return None


def handle_property_result(
    requested: list[str],
    results: dict[str, bytes],
    errors: dict[str, str],
    name: str | None,
    flags: int,
    value: bytes,
) -> bool:
    """Record one property result."""

    if is_property_stream_terminator(name, value):
        return True

    setting = name or next_unreturned_setting(requested, results, errors)
    if setting is None:
        return False

    if flags & 1:
        errors[setting] = property_error_description(setting, value)
    else:
        results[setting] = value
    return False


def read_properties(
    transport: ACPEncryptedTransport, settings: list[str], flags: int = 0
) -> tuple[dict[str, bytes], dict[str, str]]:
    """Read one or more ACP properties with a single get-property command."""

    if not settings:
        return {}, {}

    body = b"".join(property_request(setting) for setting in settings)
    transport.send(body, flags=flags, command=0x14)
    header, response_body = transport.recv()
    if header.command != 0x14:
        raise RuntimeError(
            f"property response command mismatch: got {header.command:#x}, expected 0x14"
        )
    if header.status:
        raise RuntimeError(f"property request failed with ACP status {header.status}")

    results: dict[str, bytes] = {}
    errors: dict[str, str] = {}

    if header.body_size == ACP_STREAM_SIZE:
        while True:
            name, flags, size = parse_property_record(
                transport.recv_decrypted(ACP_PROPERTY_HEADER.size)
            )
            if size > ACP_MAX_BODY_SIZE:
                raise RuntimeError(f"implausible property size {size}")
            value = transport.recv_decrypted(size)
            if handle_property_result(settings, results, errors, name, flags, value):
                break
        return results, errors

    offset = 0
    while offset < len(response_body):
        if len(response_body) - offset < ACP_PROPERTY_HEADER.size:
            raise RuntimeError(
                f"truncated property record header at offset {offset}"
            )
        name, flags, size = parse_property_record(
            response_body[offset:offset + ACP_PROPERTY_HEADER.size]
        )
        offset += ACP_PROPERTY_HEADER.size
        if size > ACP_MAX_BODY_SIZE:
            raise RuntimeError(f"implausible property size {size}")
        if size > len(response_body) - offset:
            raise RuntimeError(
                f"truncated value for property {name or '<anonymous>'}: "
                f"expected {size} bytes, received {len(response_body) - offset}"
            )
        value = response_body[offset:offset + size]
        offset += size
        if handle_property_result(settings, results, errors, name, flags, value):
            break
    return results, errors


def read_property(transport: ACPEncryptedTransport, setting: str, flags: int = 0) -> bytes:
    """Read one ACP property value by four-character setting name."""

    results, errors = read_properties(transport, [setting], flags=flags)
    if setting in results:
        return results[setting]
    if setting in errors:
        raise RuntimeError(errors[setting])
    raise RuntimeError(f"setting {setting!r} was not present in the response")


def json_safe_cfb0(value: Any) -> Any:
    """Convert decoded CFB0 values into JSON-serializable values."""

    if isinstance(value, bytes):
        item: dict[str, Any] = {
            "type": "bytes",
            "length": len(value),
        }
        stripped = value.rstrip(b"\x00")
        try:
            text = stripped.decode("utf-8")
        except UnicodeDecodeError:
            text = ""
        if text and all(ch.isprintable() for ch in text):
            item["text"] = text
        item["hex"] = value.hex()
        return item
    if isinstance(value, CFB0Integer):
        return {"type": "integer", "decimal": str(value), "width": value.width}
    if isinstance(value, int) and not isinstance(value, bool) and abs(value) > (1 << 53) - 1:
        return {"type": "integer", "decimal": str(value)}
    if isinstance(value, dict):
        return {str(key): json_safe_cfb0(item) for key, item in value.items()}
    if isinstance(value, list):
        return [json_safe_cfb0(item) for item in value]
    return value


def format_value(value: bytes) -> str:
    """Format an ACP property value for command-line output."""

    if value.startswith(CFB0_MAGIC):
        return json.dumps(json_safe_cfb0(cfb0_loads(value)), indent=2, sort_keys=True)

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


PROFILE_PATH_TOKEN = re.compile(r"([A-Za-z0-9_]+)((?:\[\d+\])*)$")


def profile_path_parts(path: str) -> list[str | int]:
    """Parse a dotted profile path such as ``restoreProfile.WiFi.radios[0].raNm``."""

    parts: list[str | int] = []
    for token in path.split("."):
        if not token:
            raise ValueError("profile path contains an empty component")
        match = PROFILE_PATH_TOKEN.fullmatch(token)
        if not match:
            raise ValueError(f"invalid profile path component {token!r}")
        parts.append(match.group(1))
        for index in re.findall(r"\[(\d+)\]", match.group(2)):
            parts.append(int(index))
    return parts


def profile_path_get(value: Any, path: str) -> Any:
    """Return a nested value from a decoded profile path."""

    current = value
    for part in profile_path_parts(path):
        if isinstance(part, int):
            if not isinstance(current, list):
                raise KeyError(f"profile path expected a list before index {part}")
            current = current[part]
        else:
            if not isinstance(current, dict):
                raise KeyError(f"profile path expected a dictionary before key {part!r}")
            current = current[part]
    return current


def format_python_value(value: Any, json_output: bool = False) -> str:
    """Format a decoded Python value for command-line output."""

    if json_output or isinstance(value, (dict, list, bytes)):
        return json.dumps(json_safe_cfb0(value), indent=2, sort_keys=True)
    if isinstance(value, bool):
        return "true" if value else "false"
    if value is None:
        return "null"
    return str(value)


def setting_json_record(raw_value: bytes) -> dict[str, Any]:
    """Build a structured JSON-safe record for a raw property value."""

    record: dict[str, Any] = {
        "hex": raw_value.hex(),
        "length": len(raw_value),
        "value": format_value(raw_value),
    }
    if raw_value.startswith(CFB0_MAGIC):
        record["decoded"] = json_safe_cfb0(cfb0_loads(raw_value))
    return record


def read_settings_bytes(
    host: str, password: str, settings: list[str]
) -> tuple[dict[str, bytes], dict[str, str]]:
    """Connect, authenticate, and read multiple settings in one ACP command."""

    with connect_acp(host) as sock:
        auth = authenticate(ACPPlainTransport(sock), password)
        request_key, response_key = derive_keys(auth.session_key)
        encrypted = ACPEncryptedTransport(
            sock,
            request_key,
            response_key,
            auth.request_iv,
            auth.response_iv,
        )
        return read_properties(encrypted, settings)


def read_setting_bytes(host: str, password: str, setting: str) -> bytes:
    """Connect, authenticate, read one setting, and return its raw bytes."""

    results, errors = read_settings_bytes(host, password, [setting])
    if setting in results:
        return results[setting]
    if setting in errors:
        raise RuntimeError(errors[setting])
    raise RuntimeError(f"setting {setting!r} was not present in the response")


def read_setting(host: str, password: str, setting: str) -> str:
    """Connect, authenticate, read one setting, and format it as text."""

    return format_value(read_setting_bytes(host, password, setting))


def read_profile_path(host: str, password: str, setting: str, path: str) -> Any:
    """Read a CFB0 profile setting and return a nested path from it."""

    raw_value = read_setting_bytes(host, password, setting)
    if not raw_value.startswith(CFB0_MAGIC):
        raise ValueError(f"{setting} is not a CFB0 setting")
    return profile_path_get(cfb0_loads(raw_value), path)


def modern_read_main(argv: list[str] | None = None) -> int:
    """Command-line entry point for modern ACP reads."""

    parser = argparse.ArgumentParser(description="Read an AirPort/Time Capsule ACP setting.")
    parser.add_argument("host", help="Time Capsule IP address or hostname")
    parser.add_argument("--password", required=True, help="admin password")
    parser.add_argument(
        "--setting",
        action="append",
        help="four-character ACP setting name, e.g. sySN; repeat to batch-read settings",
    )
    parser.add_argument(
        "--profile-path",
        help="extract a dotted path from a decoded CFB0 setting; defaults --setting to Prof",
    )
    parser.add_argument("--json", action="store_true", help="print decoded/structured output as JSON")
    args = parser.parse_args(argv)

    try:
        if args.profile_path:
            if args.setting and len(args.setting) > 1:
                parser.error("--profile-path can be used with at most one --setting")
            setting = args.setting[0] if args.setting else "Prof"
            value = read_profile_path(args.host, args.password, setting, args.profile_path)
            print(format_python_value(value, json_output=args.json))
        else:
            if not args.setting:
                parser.error("--setting is required unless --profile-path is used")
            if len(args.setting) > 1:
                if not args.json:
                    parser.error("--json is required when reading multiple settings")
                values, errors = read_settings_bytes(args.host, args.password, args.setting)
                print(json.dumps(
                    {
                        "settings": {
                            setting: setting_json_record(values[setting])
                            for setting in args.setting
                            if setting in values
                        },
                        "errors": errors,
                    },
                    indent=2,
                    sort_keys=True,
                ))
            else:
                raw_value = read_setting_bytes(args.host, args.password, args.setting[0])
                if args.json:
                    if raw_value.startswith(CFB0_MAGIC):
                        print(format_python_value(cfb0_loads(raw_value), json_output=True))
                    else:
                        print(json.dumps(setting_json_record(raw_value), indent=2, sort_keys=True))
                else:
                    print(format_value(raw_value))
        return 0
    except Exception as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
