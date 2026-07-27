from __future__ import annotations

from typing import Any, Callable

from backend.acp import ACPEncryptedTransport
from backend.acp import ACPPlainTransport
from backend.acp import connect_acp as default_connect_acp
from backend.cfb0 import cfb0_dumps
from backend.cfb0 import cfb0_loads
from backend.modern import read_property
from backend.srp import authenticate as default_authenticate
from backend.srp import derive_keys as default_derive_keys

RPC_COMMAND = 0x19
HEADER_TOKEN_XOR_KEY = bytes.fromhex("5b6faf5d9d5b0e1351f2da1de7e8d673")


def acp_header_token(text: str) -> bytes:
    """Return AirPort Utility's obfuscated 32-byte ACP header token."""

    plain = text.encode("utf-8")[:32].ljust(32, b"\x00")
    return bytes(
        plain[index] ^ HEADER_TOKEN_XOR_KEY[index & 0x0F] ^ ((0x55 + index) & 0xFF)
        for index in range(32)
    )


def rpc_call(
    transport: ACPEncryptedTransport,
    function: str,
    inputs: dict[str, Any],
    flags: int,
) -> dict[str, Any]:
    """Call one AirPort ``acpd`` RPC and return its decoded response."""

    request = {
        "function": function,
        "inputs": inputs,
    }
    transport.send(cfb0_dumps(request), flags=flags, command=RPC_COMMAND)
    header, body = transport.recv()
    if header.command != RPC_COMMAND:
        raise RuntimeError(
            f"{function} response command mismatch: "
            f"got {header.command:#x}, expected {RPC_COMMAND:#x}"
        )
    if header.status:
        raise RuntimeError(f"{function} failed with ACP status {header.status}")
    if not body:
        return {}

    decoded = cfb0_loads(body)
    if not isinstance(decoded, dict):
        raise RuntimeError(f"{function} returned non-dictionary response")
    status = decoded.get("status", 0)
    if status:
        raise RuntimeError(f"{function} returned status {status}: {decoded!r}")
    return decoded


def open_encrypted_transport(
    host: str,
    password: str,
    *,
    connect: Callable[[str], Any] = default_connect_acp,
    authenticate_func: Callable[[ACPPlainTransport, str], Any] = default_authenticate,
    derive_keys_func: Callable[[bytes], tuple[bytes, bytes]] = default_derive_keys,
) -> tuple[Any, ACPEncryptedTransport]:
    """Connect, authenticate, and return the socket plus encrypted transport."""

    sock = connect(host)
    try:
        auth = authenticate_func(ACPPlainTransport(sock), password)
        request_key, response_key = derive_keys_func(auth.session_key)
    except Exception:
        sock.close()
        raise
    return sock, ACPEncryptedTransport(
        sock,
        request_key,
        response_key,
        auth.request_iv,
        auth.response_iv,
        acp_header_token(password),
    )


def read_cfb0_setting(host: str, password: str, setting: str) -> Any:
    """Read and decode one CFB0 setting."""

    sock, transport = open_encrypted_transport(host, password)
    with sock:
        value = read_property(transport, setting)
    if not value.startswith(b"CFB0"):
        raise ValueError(f"{setting} is not a CFB0 setting")
    return cfb0_loads(value)
