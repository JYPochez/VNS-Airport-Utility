from __future__ import annotations

import ipaddress
import os
import socket
import struct
import subprocess
from typing import Any

from backend.acp import ACP_MAX_BODY_SIZE
from backend.acp import ACP_PORT
from backend.acp import acp_adler32


FIRMWARE_UPLOAD_CAPABILITY = "afup"
FIRMWARE_UPLOAD_PROPERTY = "fuup"
FIRMWARE_START_PROPERTY = "fust"
FIRMWARE_PROGRESS_PROPERTY = "fugp"
FIRMWARE_REBOOT_PROPERTY = "acRB"
FIRMWARE_MAGIC = b"APPLE-FIRMWARE"
FIRMWARE_MAX_STREAM_SIZE = 64 * 1024 * 1024
FIRMWARE_REQUEST_FLAGS = 4
FIRMWARE_PROGRESS_TIMEOUT_SECONDS = 180.0
FIRMWARE_PROGRESS_POLL_SECONDS = 1.0
FIRMWARE_PROGRESS_OUTPUT_PREFIX = "firmware-upload progress: "


def firmware_source_summary(source: str) -> str:
    """Validate and describe a firmware source path or URL."""

    text = source.strip()
    if not text:
        raise ValueError("firmware image cannot be empty")
    if "://" in text:
        return f"firmware URL {text}"
    if not os.path.isfile(text):
        raise ValueError(f"firmware image does not exist: {text}")
    return f"firmware file {text} ({os.path.getsize(text)} bytes)"


def firmware_source_bytes(source: str, max_size: int | None = ACP_MAX_BODY_SIZE) -> bytes:
    """Load a local firmware image into memory."""

    text = source.strip()
    if "://" in text:
        raise ValueError("download firmware URL before uploading it")
    with open(text, "rb") as firmware_file:
        data = firmware_file.read()
    if not data:
        raise ValueError("firmware image is empty")
    if max_size is not None and len(data) > max_size:
        raise ValueError(
            f"firmware image is too large for one ACP transfer: {len(data)} bytes"
        )
    return data


def parse_firmware_image_info(firmware_data: bytes) -> dict[str, Any]:
    """Validate an Apple base station firmware envelope and return header facts."""

    if len(firmware_data) < 0x24:
        raise ValueError("firmware image is too small")
    if (
        firmware_data[:len(FIRMWARE_MAGIC)] != FIRMWARE_MAGIC
        or firmware_data[len(FIRMWARE_MAGIC)] != 0
    ):
        raise ValueError("firmware image is not an APPLE-FIRMWARE base station image")

    expected_checksum = struct.unpack(">I", firmware_data[-4:])[0]
    actual_checksum = acp_adler32(firmware_data[:-4])
    if actual_checksum != expected_checksum:
        raise ValueError(
            "firmware checksum mismatch: "
            f"expected 0x{expected_checksum:08x}, computed 0x{actual_checksum:08x}"
        )

    return {
        "productID": struct.unpack(">I", firmware_data[0x10:0x14])[0],
        "sourceVersionRaw": struct.unpack(">I", firmware_data[0x14:0x18])[0],
        "versionByte": firmware_data[0x0F],
        "metadataByte": firmware_data[0x1B],
        "checksum": expected_checksum,
        "size": len(firmware_data),
    }


def format_mac_address(value: bytes) -> str:
    """Return a colon-separated MAC address string."""

    if len(value) != 6:
        raise ValueError("MAC address must contain exactly 6 bytes")
    return ":".join(f"{byte:02x}" for byte in value)


def parse_mac_address(value: str | bytes) -> bytes:
    """Parse a MAC address from bytes or colon/dash-separated text."""

    if isinstance(value, bytes):
        if len(value) != 6:
            raise ValueError("MAC address must contain exactly 6 bytes")
        return value
    text = value.strip().replace("-", ":").lower()
    parts = text.split(":")
    if len(parts) != 6:
        raise ValueError(f"invalid MAC address: {value!r}")
    try:
        parsed = bytes(int(part, 16) for part in parts)
    except ValueError as exc:
        raise ValueError(f"invalid MAC address: {value!r}") from exc
    if len(parsed) != 6:
        raise ValueError(f"invalid MAC address: {value!r}")
    return parsed


def firmware_link_local_address_from_mac(value: str | bytes) -> str:
    """Derive the AirPort IPv6 link-local address from the base station MAC."""

    mac = parse_mac_address(value)
    eui64 = bytes(
        [
            mac[0] ^ 0x02,
            mac[1],
            mac[2],
            0xFF,
            0xFE,
            mac[3],
            mac[4],
            mac[5],
        ]
    )
    return str(ipaddress.IPv6Address(b"\xfe\x80" + (b"\x00" * 6) + eui64))


def is_ipv6_link_local_host(host: str) -> bool:
    """Return whether ``host`` is a numeric IPv6 link-local address."""

    text = host.strip().strip("[]")
    if "%" in text:
        text, _scope = text.rsplit("%", 1)
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return False
    return address.version == 6 and address.is_link_local


def route_interface_for_host(host: str) -> str | None:
    """Return the outbound macOS interface used for an IPv4 host."""

    text = host.strip()
    try:
        address = ipaddress.ip_address(text)
    except ValueError:
        return None
    if address.version != 4:
        return None

    commands = [
        ["/sbin/route", "-n", "get", text],
        ["route", "-n", "get", text],
    ]
    for command in commands:
        try:
            result = subprocess.run(
                command,
                text=True,
                capture_output=True,
                check=False,
                timeout=5,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if result.returncode != 0:
            continue
        for line in result.stdout.splitlines():
            key, separator, value = line.strip().partition(":")
            if separator and key == "interface":
                interface = value.strip()
                if interface:
                    return interface
    return None


def resolved_ipv6_link_local_hosts(host: str) -> list[str]:
    """Return scoped IPv6 link-local addresses from system resolution."""

    candidates: list[str] = []
    try:
        infos = socket.getaddrinfo(host, ACP_PORT, socket.AF_INET6, socket.SOCK_STREAM)
    except OSError:
        return candidates

    for _family, _socktype, _proto, _canon, sockaddr in infos:
        address, _port, _flowinfo, scope_id = sockaddr
        if "%" in address:
            candidate = address
            address_text, _scope = address.rsplit("%", 1)
        else:
            address_text = address
            if not scope_id:
                continue
            try:
                scope_name = socket.if_indextoname(scope_id)
            except OSError:
                continue
            candidate = f"{address}%{scope_name}"
        try:
            parsed = ipaddress.ip_address(address_text)
        except ValueError:
            continue
        if parsed.version == 6 and parsed.is_link_local:
            candidates.append(candidate)
    return candidates


def firmware_upload_host_candidates(host: str, preflight: dict[str, Any]) -> list[str]:
    """Return preferred ACP hosts for firmware upload, mirroring AirPort Utility."""

    candidates: list[str] = []
    seen: set[str] = set()

    def add(candidate: str | None) -> None:
        if candidate is None:
            return
        candidate = candidate.strip()
        if not candidate:
            return
        key = candidate.lower()
        if key in seen:
            return
        seen.add(key)
        candidates.append(candidate)

    if is_ipv6_link_local_host(host):
        add(host)

    host_for_resolution = host.strip().strip("[]")
    if "%" in host_for_resolution:
        host_for_resolution, _scope = host_for_resolution.rsplit("%", 1)
    try:
        is_numeric_host = bool(ipaddress.ip_address(host_for_resolution))
    except ValueError:
        is_numeric_host = False
    if not is_numeric_host and "." in host:
        for candidate in resolved_ipv6_link_local_hosts(host):
            add(candidate)

    mac_address = preflight.get("wanMACAddress")
    interface = route_interface_for_host(host)
    if isinstance(mac_address, str) and interface:
        try:
            add(f"{firmware_link_local_address_from_mac(mac_address)}%{interface}")
        except ValueError:
            pass

    add(host)
    return candidates


def parse_firmware_progress(value: bytes) -> dict[str, Any]:
    """Parse the `fugp` progress string returned while firmware is programmed."""

    text = value.rstrip(b"\x00").decode("ascii", errors="replace").strip()
    parts = text.split("/")
    if len(parts) != 2 or not parts[0].isdigit() or not parts[1].isdigit():
        raise RuntimeError(f"unexpected firmware progress value {text!r}")
    current = int(parts[0])
    total = int(parts[1])
    return {
        "current": current,
        "total": total,
        "raw": text,
        "complete": total > 0 and current >= total,
    }
