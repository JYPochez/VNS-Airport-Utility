from __future__ import annotations

"""Wireless-client discovery shared by modern ACP and legacy SNMP devices."""

import ipaddress
import re
import subprocess
from concurrent.futures import ThreadPoolExecutor, wait
from typing import Any, Callable, Iterable


APPLE_BASE_STATION_3_MIB = "1.3.6.1.4.1.63.501.3"
WIRELESS_PHYS_ADDRESS_OID = APPLE_BASE_STATION_3_MIB + ".2.2.1.1"
WIRELESS_TYPE_OID = APPLE_BASE_STATION_3_MIB + ".2.2.1.2"
DHCP_PHYS_ADDRESS_OID = APPLE_BASE_STATION_3_MIB + ".3.2.1.1"
DHCP_IP_ADDRESS_OID = APPLE_BASE_STATION_3_MIB + ".3.2.1.2"

_MAC_PATTERN = re.compile(
    r"(?i)(?<![0-9a-f])(?:[0-9a-f]{1,2}[:-]){5}[0-9a-f]{1,2}(?![0-9a-f])"
)
_ARP_PATTERN = re.compile(
    r"\((?P<ip>[^)]+)\)\s+at\s+(?P<mac>(?:[0-9a-f]{1,2}:){5}[0-9a-f]{1,2})\b",
    re.IGNORECASE,
)
_NDP_PATTERN = re.compile(
    r"^(?P<ip>\S+)\s+(?P<mac>(?:[0-9a-f]{1,2}:){5}[0-9a-f]{1,2})\b",
    re.IGNORECASE,
)
_IPV4_PATTERN = re.compile(
    r"(?<!\d)(?:25[0-5]|2[0-4]\d|1?\d?\d)"
    r"(?:\.(?:25[0-5]|2[0-4]\d|1?\d?\d)){3}(?!\d)"
)
_HOSTNAME_LOOKUP_BUDGET_SECONDS = 1.0
_HOSTNAME_LOOKUP_MAX_WORKERS = 8


def normalize_mac(value: Any) -> str | None:
    """Return a canonical uppercase MAC address, or ``None``."""

    if isinstance(value, (bytes, bytearray)) and len(value) == 6:
        octets = list(value)
    elif isinstance(value, str):
        match = _MAC_PATTERN.search(value.strip())
        if match is not None:
            parts = re.split(r"[:-]", match.group(0))
        else:
            compact = re.sub(r"[^0-9a-f]", "", value, flags=re.IGNORECASE)
            if len(compact) != 12:
                return None
            parts = [compact[index:index + 2] for index in range(0, 12, 2)]
        try:
            octets = [int(part, 16) for part in parts]
        except ValueError:
            return None
    else:
        return None
    if len(octets) != 6 or any(not 0 <= octet <= 255 for octet in octets):
        return None
    return ":".join(f"{octet:02X}" for octet in octets)


def _append_unique_mac(macs: list[str], value: Any) -> None:
    mac = normalize_mac(value)
    if mac is not None and mac not in macs:
        macs.append(mac)


def modern_wireless_macs(
    radio_station_list: Any,
    system_interfaces_response: Any,
) -> list[str]:
    """Extract wireless station MACs while excluding Ethernet bridge caches."""

    macs: list[str] = []
    if isinstance(radio_station_list, dict):
        for stations in radio_station_list.values():
            if not isinstance(stations, list):
                continue
            for station in stations:
                if not isinstance(station, dict):
                    continue
                opmode = str(station.get("opmode", "sta")).strip().lower()
                if opmode == "sta":
                    _append_unique_mac(
                        macs, station.get("macAddress", station.get("MAC"))
                    )

    interfaces = system_interfaces_response
    for key in ("outputs", "data", "LAN", "interfaces"):
        if not isinstance(interfaces, dict):
            interfaces = []
            break
        interfaces = interfaces.get(key, [])
    if isinstance(interfaces, list):
        for interface in interfaces:
            if not isinstance(interface, dict):
                continue
            interface_type = str(interface.get("type", "")).lower()
            # The interfaces RPC also returns Ethernet Cache/SwitchCache
            # entries. Only clients attached to an 802.11 interface belong
            # in the AirPort Utility wireless-client list.
            if "802.11" not in interface_type and "wireless" not in interface_type:
                continue
            clients = interface.get("clients", [])
            if not isinstance(clients, list):
                continue
            for client in clients:
                if isinstance(client, dict):
                    _append_unique_mac(
                        macs, client.get("MAC", client.get("macAddress"))
                    )
                else:
                    _append_unique_mac(macs, client)
    return macs


def _numeric_oid(text: str) -> str | None:
    token = text.strip().split(maxsplit=1)[0].lstrip(".")
    return token if token and all(part.isdigit() for part in token.split(".")) else None


def _snmp_value(line: str) -> str:
    parts = line.strip().split(maxsplit=1)
    if len(parts) < 2:
        return ""
    value = parts[1].strip()
    if value.startswith("="):
        value = value[1:].strip()
    if ":" in value:
        kind, candidate = value.split(":", 1)
        if kind.strip().replace("-", " ").replace("_", " ").isupper():
            value = candidate.strip()
    return value.strip().strip('"')


def _mac_from_oid_index(oid: str, column_oid: str) -> str | None:
    prefix = column_oid + "."
    if not oid.startswith(prefix):
        return None
    try:
        suffix = [int(part) for part in oid[len(prefix):].split(".")]
    except ValueError:
        return None
    # PhysAddress is an OCTET STRING index and normally carries a leading
    # length component. Accept an implied six-octet index as well.
    if len(suffix) >= 7 and suffix[-7] == 6:
        suffix = suffix[-6:]
    elif len(suffix) >= 6:
        suffix = suffix[-6:]
    else:
        return None
    if any(not 0 <= octet <= 255 for octet in suffix):
        return None
    return normalize_mac(bytes(suffix))


def parse_legacy_snmp_walk(output: str) -> tuple[list[str], dict[str, str]]:
    """Return associated STA MACs and DHCP IPv4 addresses keyed by MAC."""

    wireless_order: list[str] = []
    wireless_types: dict[str, int] = {}
    dhcp_addresses: dict[str, str] = {}

    for line in output.splitlines():
        oid = _numeric_oid(line)
        if oid is None:
            continue
        value = _snmp_value(line)

        mac = _mac_from_oid_index(oid, WIRELESS_PHYS_ADDRESS_OID)
        if mac is not None:
            _append_unique_mac(wireless_order, mac)
            continue

        mac = _mac_from_oid_index(oid, WIRELESS_TYPE_OID)
        if mac is not None:
            match = re.search(r"-?\d+", value)
            if match is not None:
                wireless_types[mac] = int(match.group(0))
            continue

        mac = _mac_from_oid_index(oid, DHCP_IP_ADDRESS_OID)
        if mac is not None:
            match = _IPV4_PATTERN.search(value)
            if match is not None:
                dhcp_addresses[mac] = match.group(0)
            continue

        # Some net-snmp output formats make the value easier to consume than
        # the OCTET STRING index. Record the DHCP row's MAC column so later
        # columns can still be correlated through their shared index.
        mac = _mac_from_oid_index(oid, DHCP_PHYS_ADDRESS_OID)
        if mac is not None:
            continue

    # Type 1 is a station; type 2 is a WDS peer. Include a row when an older
    # agent omits the type column, but never expose a confirmed WDS node.
    wireless_order = [
        mac for mac in wireless_order if wireless_types.get(mac, 1) == 1
    ]
    return wireless_order, dhcp_addresses


def run_legacy_snmp_walk(
    host: str,
    community: str,
    *,
    run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> str:
    result = run(
        [
            "/usr/bin/snmpwalk",
            "-v",
            "2c",
            "-On",
            "-OQ",
            "-t",
            "2",
            "-r",
            "1",
            "-c",
            community,
            host,
            APPLE_BASE_STATION_3_MIB,
        ],
        capture_output=True,
        text=True,
        errors="replace",
        timeout=8,
        check=False,
    )
    if result.returncode:
        message = result.stderr.strip() or result.stdout.strip() or "SNMP walk failed"
        raise RuntimeError(message)
    output = result.stdout.strip()
    lowered = output.lower()
    if (
        not output
        or lowered.startswith("timeout")
        or lowered.startswith("no such object")
        or "no such object available" in lowered
        or lowered.startswith("no hostname specified")
        or lowered.startswith("error")
    ):
        raise RuntimeError(output or "SNMP walk returned no data")
    return result.stdout


def read_neighbor_cache(
    *,
    run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> dict[str, list[str]]:
    """Read the Mac's existing ARP/NDP mappings without scanning the subnet."""

    mappings: dict[str, list[str]] = {}
    commands = [
        (["/usr/sbin/arp", "-an"], _ARP_PATTERN),
        (["/usr/sbin/ndp", "-an"], _NDP_PATTERN),
    ]
    for command, pattern in commands:
        try:
            result = run(
                command,
                capture_output=True,
                text=True,
                timeout=2,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired):
            continue
        if result.returncode:
            continue
        for line in result.stdout.splitlines():
            match = pattern.search(line)
            if match is None:
                continue
            mac = normalize_mac(match.group("mac"))
            raw_ip = match.group("ip").split("%", 1)[0]
            try:
                ip = str(ipaddress.ip_address(raw_ip))
            except ValueError:
                continue
            if mac is not None and ip not in mappings.setdefault(mac, []):
                mappings[mac].append(ip)
    return mappings


def reverse_hostname(
    ip: str,
    *,
    run: Callable[..., subprocess.CompletedProcess[str]] = subprocess.run,
) -> str:
    """Perform a bounded Directory Services reverse lookup, including mDNS."""

    try:
        result = run(
            ["/usr/bin/dscacheutil", "-q", "host", "-a", "ip_address", ip],
            capture_output=True,
            text=True,
            timeout=1,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    if result.returncode:
        return ""
    for line in result.stdout.splitlines():
        key, separator, value = line.partition(":")
        if separator and key.strip().lower() == "name":
            hostname = value.strip().rstrip(".")
            if hostname and hostname != ip:
                return hostname
    return ""


def resolved_client_records(
    macs: Iterable[str],
    *,
    addresses_by_mac: dict[str, str] | None = None,
    neighbor_addresses: dict[str, list[str]] | None = None,
    hostname_lookup: Callable[[str], str] | None = None,
    hostname_lookup_budget_seconds: float = _HOSTNAME_LOOKUP_BUDGET_SECONDS,
    hostname_lookup_max_workers: int = _HOSTNAME_LOOKUP_MAX_WORKERS,
) -> list[dict[str, str]]:
    """Resolve associated stations while retaining MAC-only associations."""

    addresses_by_mac = addresses_by_mac or {}
    neighbor_addresses = neighbor_addresses or {}
    hostname_lookup = hostname_lookup or reverse_hostname
    records: list[dict[str, str]] = []
    for raw_mac in macs:
        mac = normalize_mac(raw_mac)
        if mac is None:
            continue
        candidates: list[str] = []
        device_ip = addresses_by_mac.get(mac, "")
        if device_ip:
            candidates.append(device_ip)
        for ip in neighbor_addresses.get(mac, []):
            if ip not in candidates:
                candidates.append(ip)
        if not candidates:
            records.append(
                {
                    "macAddress": mac,
                    "ipAddress": "",
                    "hostname": "",
                }
            )
            continue
        # Prefer IPv4, as AirPort Utility does when both address families are
        # available, while retaining IPv6 as a fallback.
        def address_preference(candidate: str) -> tuple[int, int]:
            address = ipaddress.ip_address(candidate)
            return (
                0 if address.version == 4 else 1,
                1 if address.is_link_local else 0,
            )

        candidates.sort(key=address_preference)
        ip = candidates[0]
        records.append(
            {
                "macAddress": mac,
                "ipAddress": ip,
                "hostname": "",
            }
        )

    ips = list(
        dict.fromkeys(
            record["ipAddress"] for record in records if record["ipAddress"]
        )
    )
    if not ips or hostname_lookup_budget_seconds <= 0:
        return records

    executor = ThreadPoolExecutor(
        max_workers=max(1, min(hostname_lookup_max_workers, len(ips)))
    )
    futures = {executor.submit(hostname_lookup, ip): ip for ip in ips}
    try:
        completed, pending = wait(
            futures,
            timeout=hostname_lookup_budget_seconds,
        )
        hostnames: dict[str, str] = {}
        for future in completed:
            try:
                hostname = future.result()
            except Exception:
                continue
            if isinstance(hostname, str) and hostname:
                hostnames[futures[future]] = hostname
        for future in pending:
            future.cancel()
    finally:
        # Each production lookup also has its own one-second subprocess
        # timeout. Do not make the caller wait serially for unfinished lookups
        # after the shared budget expires.
        executor.shutdown(wait=False, cancel_futures=True)

    for record in records:
        record["hostname"] = hostnames.get(record["ipAddress"], "")
    return records
