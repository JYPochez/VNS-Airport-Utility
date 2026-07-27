from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import struct
import time
from typing import Any

from backend.disk import ERASE_METHOD_VALUES
from backend.firmware import parse_mac_address

CORE_FOUNDATION_EPOCH_OFFSET = 978307200

CONNECT_USING_VALUES = {
    "dhcp": 0x8300,
    "static": 0x8400,
    "pppoe": 0x8900,
    "modem": 0x0900,
}
PPPOE_CONNECTION_VALUES = {
    "always-on": {"peAC": True, "peSC": True, "peID": 0},
    "automatic": {"peAC": True, "peSC": False},
    "manual": {"peAC": False, "peSC": False},
}
IPV6_CONFIG_VALUES = {
    "link-local": {"6cfg": 0},
    "automatic": {"6aut": True},
    "manual": {"6aut": False},
}
IPV6_MODE_VALUES = {
    "link-local": 0,
    "host": 1,
    "tunnel": 3,
    "router": 5,
}
WIRELESS_MODE_VALUES = {
    "create": 0,
    "join": 1,
    "wds": 10,
    "extend": 20,
    "off": 3,
}
WDS_MODE_VALUES = {
    "off": 0,
    "main": 1,
    "relay": 2,
    "remote": 3,
}
WIRELESS_SECURITY_VALUES = {
    "none": 1,
    "wep-40": 2,
    "wep-128": 3,
    "wpa-personal": 4,
    "wpa-wpa2-personal": 5,
    "wpa2-personal": 7,
    "wpa-enterprise": 9,
    "wpa-wpa2-enterprise": 10,
    "wpa2-enterprise": 12,
}
WPA_PERSONAL_SECURITY_MODES = {
    "wpa-personal",
    "wpa-wpa2-personal",
    "wpa2-personal",
}
WEP_SECURITY_MODES = {"wep-40", "wep-128"}
WDS_NODE_LIST_SIZE = 16
RADIO_MODE_VALUES = {
    "80211b": 1,
    "80211bg": 2,
    "80211g": 3,
    "80211a": 4,
    "80211n-a": 5,
    "80211n-bg": 6,
    "80211n-only-24": 7,
    "80211n-only-5": 8,
}
ROUTER_MODE_VALUES = {
    "dhcp-and-nat": 0,
    "dhcp-only": 1,
    "nat-only": 2,
    "bridge": 3,
}
DISK_SECURITY_VALUES = {
    "accounts": 0,
    "disk-password": 1,
    "device-password": 2,
}
GUEST_DISK_ACCESS_VALUES = {
    "not-allowed": 0,
    "read-only": 1,
    "read-write": 2,
}
PROFILE_TOP_LEVEL_DIRTY_KEYS = {
    "acEn",
    "acTa",
    "bsRM",
    "dh95",
    "dhBg",
    "dhEn",
    "dhLe",
    "dhMg",
    "nDMZ",
    "naFl",
    "ntSV",
    "raAu",
    "raCi",
    "raF2",
    "raFl",
    "raI1",
    "raI2",
    "raKT",
    "raMu",
    "raPo",
    "raRo",
    "raS2",
    "raSe",
    "raU2",
    "raWB",
    "syCt",
    "syLo",
    "syNm",
    "syRe",
}
PROFILE_RADIO_DIRTY_KEYS = {"dWDS", "raCh", "raCl", "raCr", "raMd", "raNm", "raSt", "raWE", "raWM"}
LEGACY_ROUTER_MODE_VALUES = {
    "dhcp-and-nat": 0,
    "bridge": 0xFFFFFFFF,
}
DHCP_LEASE_UNITS = {
    "second": 1,
    "seconds": 1,
    "minute": 60,
    "minutes": 60,
    "hour": 3600,
    "hours": 3600,
    "day": 86400,
    "days": 86400,
    "week": 604800,
    "weeks": 604800,
}

def validate_setting_name(setting: str) -> None:
    """Validate a four-character ACP setting name."""

    try:
        code = setting.encode("ascii")
    except UnicodeEncodeError:
        raise ValueError("setting name must contain only ASCII characters") from None
    if len(code) != 4:
        raise ValueError("setting name must be exactly four ASCII characters")

def ipv4_text(label: str, value: str) -> str:
    """Return a normalized IPv4 address string or raise a friendly error."""

    text = value.strip()
    if not text:
        raise ValueError(f"{label} cannot be empty")
    octets = text.split(".")
    if len(octets) == 4 and any(
        len(octet) > 1 and octet.startswith("0") and octet.isdigit() for octet in octets
    ):
        raise ValueError(f"{label} must be an IPv4 address")
    try:
        return str(ipaddress.IPv4Address(text))
    except ValueError:
        raise ValueError(f"{label} must be an IPv4 address") from None

def subnet_mask_text(value: str, label: str = "Subnet Mask") -> str:
    """Return a normalized dotted IPv4 netmask string."""

    mask = ipaddress.IPv4Address(ipv4_text(label, value))
    bits = f"{int(mask):032b}"
    if "01" in bits:
        raise ValueError(f"{label} must contain contiguous one bits")
    if bits.count("1") not in range(1, 32):
        raise ValueError(f"{label} must be between 255.0.0.0 and 255.255.255.254")
    return str(mask)

def ipv6_text(label: str, value: str) -> str:
    """Return a normalized IPv6 address string or raise a friendly error."""

    text = value.strip()
    if not text:
        raise ValueError(f"{label} cannot be empty")
    try:
        return str(ipaddress.IPv6Address(text))
    except ValueError:
        raise ValueError(f"{label} must be an IPv6 address") from None

def required_text(label: str, value: str) -> str:
    """Return a trimmed required text value or raise a friendly error."""

    if not isinstance(value, str):
        raise ValueError(f"{label} must be text")
    text = value.strip()
    if not text:
        raise ValueError(f"{label} cannot be empty")
    return text

def wpa_preshared_key(password: str, network_name: str) -> bytes:
    """Return the 32-byte WPA PSK stored by AirPort radio profiles as raWE."""

    passphrase = required_text("Wireless Password", password)
    ssid = required_text("Wireless Network Name", network_name)
    if len(passphrase) == 64:
        try:
            return bytes.fromhex(passphrase)
        except ValueError:
            pass
    if not 8 <= len(passphrase) <= 63:
        raise ValueError(
            "Wireless Password for WPA Personal must be 8 to 63 characters, "
            "or 64 hexadecimal characters"
        )
    return hashlib.pbkdf2_hmac(
        "sha1",
        passphrase.encode("utf-8"),
        ssid.encode("utf-8"),
        4096,
        32,
    )

def raw_text_setting_value(setting: str, value: str) -> str:
    """Validate raw text writes for settings the app writes directly."""

    if setting == "syNm":
        return required_text("Base Station Name", value)
    if setting == "syPW":
        return required_text("Admin Password", value)
    return value

def int_in_range(label: str, value: int, minimum: int, maximum: int) -> int:
    """Validate an integer falls in a closed range."""

    if not minimum <= value <= maximum:
        raise ValueError(f"{label} must be between {minimum} and {maximum}")
    return value

def radio_channel_value(value: str) -> int:
    """Return an AirPort radio channel value."""

    if value == "automatic":
        return 1000
    try:
        return int_in_range("radio channel", int(value), 1, 200)
    except ValueError:
        raise ValueError("radio channel must be 'automatic' or a channel number") from None

def dhcp_lease_seconds(value: int, unit: str) -> int:
    """Return a DHCP lease duration in seconds."""

    if value < 1:
        raise ValueError("DHCP lease must be at least 1")
    seconds = value * DHCP_LEASE_UNITS[unit]
    int_in_range("DHCP lease seconds", seconds, 1, 10 * 365 * 86400)
    return seconds

def validate_dhcp_range(start: str, end: str) -> None:
    """Validate the supported AirPort DHCP range shape."""

    start_address = ipaddress.IPv4Address(ipv4_text("DHCP Range Beginning", start))
    end_address = ipaddress.IPv4Address(ipv4_text("DHCP Range Ending", end))
    start_octets = str(start_address).split(".")
    end_octets = str(end_address).split(".")
    prefix = ".".join(start_octets[:2])
    valid = (
        prefix in {"10.0", "172.16", "192.168"}
        and prefix == ".".join(end_octets[:2])
        and start_octets[2] == end_octets[2]
        and int(start_octets[3]) <= int(end_octets[3])
    )
    if not valid:
        raise ValueError(
            "DHCP Range Beginning and Ending must use the same supported private subnet, "
            "with Ending not before Beginning."
        )

def split_repeated_values(option: str, values: list[str] | None) -> list[str]:
    """Accept repeated flags and comma-separated lists for DNS options."""

    if not values:
        return []

    out: list[str] = []
    for value in values:
        for item in value.split(","):
            item = item.strip()
            if not item:
                raise ValueError(f"{option} contains an empty value")
            out.append(item)
    return out

def parse_disk_account_json(value: str) -> dict[str, Any]:
    """Parse one disk file-sharing account object for the usrd setting."""

    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise ValueError(f"--disk-account-json is not valid JSON: {exc.msg}") from None
    if not isinstance(parsed, dict):
        raise ValueError("--disk-account-json must be a JSON object")
    name = required_text("Disk account name", parsed.get("name"))
    password = parsed.get("password", "")
    if not isinstance(password, str):
        raise ValueError("Disk account password must be a string")
    access = parsed.get("fileSharingAccess")
    if not isinstance(access, int) or access not in {0, 1, 2}:
        raise ValueError("Disk account fileSharingAccess must be 0, 1, or 2")
    return {
        "name": name,
        "password": password,
        "fileSharingAccess": access,
    }

def wds_node_list_value(values: list[str] | None) -> bytes:
    nodes: list[bytes] = []
    for value in values or []:
        for item in value.replace(",", " ").split():
            if item:
                nodes.append(parse_mac_address(item))
    if len(nodes) > 2:
        raise ValueError("--wds-peer-airport-id accepts at most two AirPort IDs")
    data = b"".join(node.ljust(8, b"\x00") for node in nodes)
    return data.ljust(WDS_NODE_LIST_SIZE, b"\x00")

def access_control_entries_value(value: str) -> bytes:
    """Encode the product-3 local access-control table (acTa)."""

    try:
        parsed = json.loads(value)
    except json.JSONDecodeError as exc:
        raise ValueError(
            f"--access-control-entries-json is not valid JSON: {exc.msg}"
        ) from None
    if not isinstance(parsed, list):
        raise ValueError("--access-control-entries-json must be a JSON array")

    records: list[bytes] = []
    for item in parsed:
        if not isinstance(item, dict):
            raise ValueError("each access-control entry must be a JSON object")
        mac = item.get("macAddress")
        description = item.get("description", "")
        if not isinstance(mac, str):
            raise ValueError("each access-control entry requires a MAC address")
        if not isinstance(description, str):
            raise ValueError("access-control entry descriptions must be strings")
        description_bytes = description.encode("utf-8")
        if len(description_bytes) > 34:
            raise ValueError(
                "access-control entry descriptions may contain at most 34 UTF-8 bytes"
            )
        records.append(
            parse_mac_address(mac) + description_bytes.ljust(34, b"\x00")
        )
    return (b"\x00" * 8) + struct.pack(">Q", len(records)) + b"".join(records)

def build_network_dirty_plist(args: argparse.Namespace) -> dict[str, Any]:
    """Translate friendly screenshot/UI options into AirPort setting keys."""

    dirty: dict[str, Any] = {}

    if args.clear_dns and args.dns_server is not None:
        raise ValueError("use either --dns-server or --clear-dns, not both")
    if args.clear_ipv6_dns and args.ipv6_dns_server is not None:
        raise ValueError("use either --ipv6-dns-server or --clear-ipv6-dns, not both")
    if args.clear_default_host and args.default_host is not None:
        raise ValueError("use either --default-host or --clear-default-host, not both")
    if args.airplay_speaker_password is not None and args.clear_airplay_speaker_password:
        raise ValueError(
            "use either --airplay-speaker-password or --clear-airplay-speaker-password, not both"
        )
    if getattr(args, "setup_complete", False):
        timestamp = getattr(args, "setup_complete_timestamp", None)
        if timestamp is None:
            timestamp = int(time.time() - CORE_FOUNDATION_EPOCH_OFFSET)
        dirty["ctim"] = timestamp

    # Internet tab and Internet Options sheet.
    if args.connect_using == "pppoe" and args.pppoe_account is None:
        raise ValueError("PPPoE Account Name cannot be empty")
    if args.dynamic_global_hostname is True and args.global_hostname is None:
        raise ValueError("Global Hostname cannot be empty")
    if args.router_mode in {"dhcp-and-nat", "dhcp-only"}:
        if args.dhcp_range_start is None:
            raise ValueError("DHCP Range Beginning cannot be empty")
        if args.dhcp_range_end is None:
            raise ValueError("DHCP Range Ending cannot be empty")
        if args.dhcp_lease is None:
            raise ValueError("DHCP Lease cannot be empty")
        validate_dhcp_range(args.dhcp_range_start, args.dhcp_range_end)
    elif args.dhcp_range_start is not None and args.dhcp_range_end is not None:
        validate_dhcp_range(args.dhcp_range_start, args.dhcp_range_end)
    elif args.dhcp_range_start is not None:
        raise ValueError("DHCP Range Ending cannot be empty")
    elif args.dhcp_range_end is not None:
        raise ValueError("DHCP Range Beginning cannot be empty")
    if args.connect_using is not None:
        dirty["waCV"] = CONNECT_USING_VALUES[args.connect_using]
    if args.lan_ip_address is not None:
        dirty["laIP"] = ipv4_text("LAN IP Address", args.lan_ip_address)
    if args.ipv4_address is not None:
        dirty["waIP"] = ipv4_text("IPv4 Address", args.ipv4_address)
    if args.subnet_mask is not None:
        if args.connect_using == "dhcp" and args.subnet_mask == "0.0.0.0":
            dirty["waSM"] = "0.0.0.0"
        else:
            dirty["waSM"] = subnet_mask_text(args.subnet_mask)
    if args.router_address is not None:
        dirty["waRA"] = ipv4_text("Router Address", args.router_address)
    if args.domain_name is not None:
        dirty["waDN"] = args.domain_name
    if args.dhcp_client_id is not None:
        dirty["waDC"] = args.dhcp_client_id
    if args.ipv6_address is not None:
        dirty["6Wad"] = ipv6_text("IPv6 Address", args.ipv6_address)
    if args.pppoe_account is not None:
        dirty["peUN"] = required_text("PPPoE Account Name", args.pppoe_account)
    if args.pppoe_password is not None:
        dirty["pePW"] = args.pppoe_password
    if args.pppoe_service is not None:
        dirty["peSN"] = args.pppoe_service
    if args.pppoe_connection is not None:
        dirty.update(PPPOE_CONNECTION_VALUES[args.pppoe_connection])
    if args.pppoe_idle_seconds is not None:
        dirty["peID"] = int_in_range("PPPoE idle timeout", args.pppoe_idle_seconds, 0, 86400)
    if getattr(args, "modem_phone_number", None) is not None:
        dirty["moPN"] = args.modem_phone_number
    if getattr(args, "modem_alternate_number", None) is not None:
        dirty["moAP"] = args.modem_alternate_number
    if getattr(args, "modem_account", None) is not None:
        dirty["moUN"] = args.modem_account
    if getattr(args, "modem_password", None) is not None:
        dirty["moPW"] = args.modem_password
    if getattr(args, "modem_idle_seconds", None) is not None:
        dirty["moID"] = int_in_range(
            "modem idle timeout", args.modem_idle_seconds, 0, 86400
        )
    if getattr(args, "modem_country_code", None) is not None:
        dirty["moCI"] = int_in_range(
            "modem country code", args.modem_country_code, 0, 36
        )
    if getattr(args, "modem_protocol", None) is not None:
        dirty["moMP"] = {"v34": 1, "v90": 2}[args.modem_protocol]
    if getattr(args, "modem_pulse_dialing", None) is not None:
        dirty["moPD"] = args.modem_pulse_dialing
    if getattr(args, "modem_automatically_dial", None) is not None:
        dirty["moAD"] = args.modem_automatically_dial
    if getattr(args, "modem_ignore_dial_tone", None) is not None:
        dirty["moDT"] = args.modem_ignore_dial_tone
    if getattr(args, "modem_use_aol", None) is not None:
        dirty["moMF"] = 1 if args.modem_use_aol else 0

    # Advanced logging, SNMP, and PPP dial-in settings.
    if getattr(args, "syslog_destination", None) is not None:
        dirty["slCl"] = ipv4_text(
            "Syslog Destination Address", args.syslog_destination
        )
    if getattr(args, "syslog_level", None) is not None:
        dirty["slvl"] = int_in_range("Syslog Level", args.syslog_level, 0, 7)
    if getattr(args, "snmp_access_flags", None) is not None:
        dirty["snAF"] = int_in_range(
            "SNMP access flags", args.snmp_access_flags, 0, 3
        )
    if getattr(args, "ppp_dial_in_enabled", None) is not None:
        dirty["pdFl"] = 1 if args.ppp_dial_in_enabled else 0
    if getattr(args, "ppp_dial_in_account", None) is not None:
        dirty["pdUN"] = args.ppp_dial_in_account
    if getattr(args, "ppp_dial_in_password", None) is not None:
        dirty["pdPW"] = args.ppp_dial_in_password
    if getattr(args, "ppp_dial_in_answer_on_ring", None) is not None:
        dirty["pdAR"] = int_in_range(
            "PPP Dial-in Answer on ring", args.ppp_dial_in_answer_on_ring, 1, 255
        )
    if getattr(args, "ppp_dial_in_idle_seconds", None) is not None:
        dirty["pdID"] = int_in_range(
            "PPP Dial-in idle timeout", args.ppp_dial_in_idle_seconds, 0, 86400
        )
    if getattr(args, "ppp_dial_in_maximum_connect_seconds", None) is not None:
        dirty["pdMC"] = int_in_range(
            "PPP Dial-in maximum connect time",
            args.ppp_dial_in_maximum_connect_seconds,
            0,
            86400,
        )

    # Base Station metadata plus product-specific wireless, DHCP, and
    # access-control options.
    if getattr(args, "base_station_contact", None) is not None:
        dirty["syCt"] = args.base_station_contact
    if getattr(args, "base_station_location", None) is not None:
        dirty["syLo"] = args.base_station_location
    if getattr(args, "time_server", None) is not None:
        dirty["ntSV"] = args.time_server
    if getattr(args, "multicast_rate", None) is not None:
        allowed_rates = {1, 2, 85, 6, 9, 17, 18, 24, 36, 1000, 2000, 3000}
        if args.multicast_rate not in allowed_rates:
            raise ValueError("Multicast Rate is not supported")
        dirty["raMu"] = args.multicast_rate
    if getattr(args, "transmit_power", None) is not None:
        if args.transmit_power not in {10, 25, 50, 100}:
            raise ValueError("Transmit Power must be 10, 25, 50, or 100 percent")
        dirty["raPo"] = args.transmit_power
    if getattr(args, "group_key_timeout_seconds", None) is not None:
        dirty["raKT"] = int_in_range(
            "WPA Group Key Timeout",
            args.group_key_timeout_seconds,
            60,
            86400,
        )
    if getattr(args, "interference_robustness", None) is not None:
        dirty["raRo"] = args.interference_robustness
    if getattr(args, "dhcp_message", None) is not None:
        dirty["dhMg"] = args.dhcp_message
    if getattr(args, "ldap_server", None) is not None:
        dirty["dh95"] = args.ldap_server
    if getattr(args, "access_control_mode", None) is not None:
        dirty["acEn"] = args.access_control_mode == "local"
        dirty["raFl"] = 1 if args.access_control_mode == "radius" else 0
    if getattr(args, "access_control_entries_json", None) is not None:
        dirty["acTa"] = access_control_entries_value(
            args.access_control_entries_json
        )
    if getattr(args, "radius_type", None) is not None:
        dirty["raCi"] = args.radius_type == "alternate"
    if getattr(args, "radius_primary_address", None) is not None:
        dirty["raI1"] = ipv4_text(
            "Primary RADIUS Server", args.radius_primary_address
        )
    if getattr(args, "radius_primary_secret", None) is not None:
        dirty["raSe"] = args.radius_primary_secret
    if getattr(args, "radius_primary_port", None) is not None:
        dirty["raAu"] = int_in_range(
            "Primary RADIUS Port", args.radius_primary_port, 1, 65535
        )
    if getattr(args, "radius_secondary_address", None) is not None:
        secondary = args.radius_secondary_address.strip()
        dirty["raF2"] = 1 if secondary else 0
        dirty["raI2"] = (
            ipv4_text("Secondary RADIUS Server", secondary)
            if secondary
            else "0.0.0.0"
        )
    if getattr(args, "radius_secondary_secret", None) is not None:
        dirty["raS2"] = args.radius_secondary_secret
    if getattr(args, "radius_secondary_port", None) is not None:
        secondary_address = getattr(args, "radius_secondary_address", None)
        dirty["raU2"] = (
            int_in_range(
                "Secondary RADIUS Port", args.radius_secondary_port, 1, 65535
            )
            if secondary_address is None or secondary_address.strip()
            else 0
        )
    if args.configure_ipv6 is not None:
        dirty.update(IPV6_CONFIG_VALUES[args.configure_ipv6])
    if args.ipv6_mode is not None:
        dirty["6cfg"] = IPV6_MODE_VALUES[args.ipv6_mode]
    if args.ipv6_default_route is not None:
        dirty["6Wgw"] = ipv6_text("IPv6 default route", args.ipv6_default_route)
    if args.ipv6_firewall is not None:
        dirty["6sfw"] = args.ipv6_firewall
    if args.remote_ipv4_address is not None:
        dirty["6Wte"] = ipv4_text("remote IPv4 address", args.remote_ipv4_address)
    if args.ipv6_lan_address is not None:
        dirty["6Lad"] = ipv6_text("IPv6 LAN address", args.ipv6_lan_address)
    if args.ipv6_lan_prefix_length is not None:
        dirty["6Lfx"] = int_in_range("IPv6 LAN prefix length", args.ipv6_lan_prefix_length, 0, 128)
    if args.ipv6_delegated_prefix is not None:
        dirty["6PDa"] = ipv6_text("IPv6 delegated prefix", args.ipv6_delegated_prefix)
    if args.ipv6_delegated_prefix_length is not None:
        dirty["6PDl"] = int_in_range(
            "IPv6 delegated prefix length",
            args.ipv6_delegated_prefix_length,
            0,
            128,
        )
    if args.ipv6_wan_prefix_length is not None:
        dirty["6Wfx"] = int_in_range("IPv6 WAN prefix length", args.ipv6_wan_prefix_length, 0, 128)
    if args.ipv6_connection_sharing is not None:
        dirty["6Lfw"] = args.ipv6_connection_sharing
    if args.dynamic_global_hostname is not None:
        dirty["wbEn"] = args.dynamic_global_hostname
    if args.dynamic_global_hostname_auto_config is not None:
        dirty["wbAC"] = args.dynamic_global_hostname_auto_config
    if args.global_hostname is not None:
        dirty["wbHN"] = required_text("Global Hostname", args.global_hostname)
    if args.global_hostname_user is not None:
        dirty["wbHU"] = args.global_hostname_user
    if args.global_hostname_password is not None:
        dirty["wbHP"] = args.global_hostname_password

    if args.clear_dns or args.dns_server is not None:
        dns_servers = [] if args.clear_dns else split_repeated_values("--dns-server", args.dns_server)
        if len(dns_servers) > 2:
            raise ValueError("--dns-server accepts at most two IPv4 DNS servers")
        normalized = [ipv4_text("DNS Server", server) for server in dns_servers]
        normalized += ["0.0.0.0"] * (2 - len(normalized))
        dirty["waD1"] = normalized[0]
        dirty["waD2"] = normalized[1]
        dirty["waD3"] = "0.0.0.0"
    if args.dns_server_1 is not None:
        dirty["waD1"] = ipv4_text("DNS Server", args.dns_server_1)
    if args.dns_server_2 is not None:
        dirty["waD2"] = ipv4_text("DNS Server", args.dns_server_2)
    if args.dns_server_3 is not None:
        dirty["waD3"] = ipv4_text("DNS Server", args.dns_server_3)

    if args.clear_ipv6_dns or args.ipv6_dns_server is not None:
        dns_servers = (
            []
            if args.clear_ipv6_dns
            else split_repeated_values("--ipv6-dns-server", args.ipv6_dns_server)
        )
        if len(dns_servers) > 2:
            raise ValueError("--ipv6-dns-server accepts at most two IPv6 DNS servers")
        normalized = [ipv6_text("IPv6 DNS Server", server) for server in dns_servers]
        normalized += ["::"] * (2 - len(normalized))
        dirty["6NS1"] = normalized[0]
        dirty["6NS2"] = normalized[1]

    # Wireless tab and Wireless Options sheet.
    if args.wireless_security is not None and args.wireless_security != "none":
        if args.wireless_password is None:
            raise ValueError("Wireless Password cannot be empty")
    if args.wireless_mode is not None:
        dirty["raSt"] = WIRELESS_MODE_VALUES[args.wireless_mode]
    if args.wireless_name is not None:
        dirty["raNm"] = required_text("Wireless Network Name", args.wireless_name)
    if args.wireless_security is not None:
        dirty["raWM"] = WIRELESS_SECURITY_VALUES[args.wireless_security]
        if args.wireless_security == "none":
            dirty["raCr"] = b""
            dirty["raWE"] = b""
    if args.wireless_password is not None:
        password = required_text("Wireless Password", args.wireless_password)
        dirty["raCr"] = password.encode("utf-8")
        if args.wireless_security not in WEP_SECURITY_MODES:
            if args.wireless_name is None:
                raise ValueError("Wireless Network Name is required when setting Wireless Password")
            dirty["raWE"] = wpa_preshared_key(password, args.wireless_name)
    if args.allow_network_extension is not None:
        dirty["dWDS"] = args.allow_network_extension
    if args.wds_mode is not None:
        dirty["bsWM"] = WDS_MODE_VALUES[args.wds_mode]
    if args.wds_peer_airport_id is not None:
        dirty["wdLs"] = wds_node_list_value(args.wds_peer_airport_id)
    if args.region_code is not None:
        dirty["syRe"] = int_in_range("region code", args.region_code, 0, 255)
    if args.hidden_network is not None:
        dirty["raCl"] = args.hidden_network
    if args.radio_mode is not None:
        dirty["raMd"] = RADIO_MODE_VALUES[args.radio_mode]
    if args.radio_channel is not None:
        dirty["raCh"] = radio_channel_value(args.radio_channel)

    # AirPlay tab.
    if args.airplay_enabled is not None:
        dirty["auRR"] = args.airplay_enabled
    if args.airplay_speaker_name is not None:
        dirty["auNN"] = required_text("AirPlay Speaker Name", args.airplay_speaker_name)
    if args.airplay_speaker_password is not None:
        dirty["auNP"] = args.airplay_speaker_password
    if args.clear_airplay_speaker_password:
        dirty["auNP"] = ""
    if args.airplay_over_wan is not None:
        dirty["aWan"] = args.airplay_over_wan

    # Base Station tab.
    if args.allow_setup_over_wan is not None:
        dirty["raWB"] = args.allow_setup_over_wan
        dirty["raNA"] = not args.allow_setup_over_wan
        dirty["waNM"] = not args.allow_setup_over_wan
        dirty["raDS"] = not args.allow_setup_over_wan

    # Network tab and Network Options sheet.
    if args.router_mode is not None:
        dirty["bsRM"] = ROUTER_MODE_VALUES[args.router_mode]
    if args.dhcp_range_start is not None:
        dirty["dhBg"] = ipv4_text("DHCP Range Beginning", args.dhcp_range_start)
    if args.dhcp_range_end is not None:
        dirty["dhEn"] = ipv4_text("DHCP Range Ending", args.dhcp_range_end)
    if args.dhcp_lease is not None:
        dirty["dhLe"] = dhcp_lease_seconds(args.dhcp_lease, args.dhcp_lease_unit)
    if args.nat_pmp is not None:
        dirty["naFl"] = 1 if args.nat_pmp else 0
    if args.default_host is not None:
        dirty["nDMZ"] = ipv4_text("Default Host", args.default_host)
    if args.clear_default_host:
        dirty["nDMZ"] = "0.0.0.0"

    # Disks tab.
    if args.file_sharing is not None:
        dirty["bsFS"] = 1 if args.file_sharing else 0
    if args.share_disks_over_wan is not None:
        dirty["bsRF"] = 1 if args.share_disks_over_wan else 0
    if args.disk_security == "disk-password" and args.disk_password is None:
        raise ValueError("Disk Password cannot be empty")
    if args.disk_security is not None:
        dirty["bsFM"] = DISK_SECURITY_VALUES[args.disk_security]
    if args.disk_password is not None:
        dirty["fssp"] = required_text("Disk Password", args.disk_password)
    if args.guest_disk_access is not None:
        dirty["bsGA"] = GUEST_DISK_ACCESS_VALUES[args.guest_disk_access]
    if args.share_disks_global_hostname is not None:
        dirty["bsWF"] = 1 if args.share_disks_global_hostname else 0
    if args.wins_server is not None:
        dirty["SMBs"] = (
            "" if not args.wins_server.strip() else ipv4_text("WINS Server", args.wins_server)
        )
    if args.windows_workgroup is not None:
        dirty["SMBw"] = args.windows_workgroup
    if args.usb_file_sharing_flags is not None:
        dirty["usbF"] = int_in_range(
            "USB file sharing flags", args.usb_file_sharing_flags, 0, 0xFFFFFFFF
        )
    if args.disk_account_json:
        dirty["usrd"] = {
            "users": [parse_disk_account_json(value) for value in args.disk_account_json]
        }

    return dirty

def has_friendly_setting_options(args: argparse.Namespace) -> bool:
    """Return whether any friendly setting flag that writes a setting was supplied."""

    setting_fields = [
        "connect_using",
        "lan_ip_address",
        "ipv4_address",
        "subnet_mask",
        "router_address",
        "dns_server",
        "dns_server_1",
        "dns_server_2",
        "dns_server_3",
        "domain_name",
        "dhcp_client_id",
        "ipv6_dns_server",
        "ipv6_address",
        "pppoe_account",
        "pppoe_password",
        "pppoe_service",
        "pppoe_connection",
        "pppoe_idle_seconds",
        "modem_phone_number",
        "modem_alternate_number",
        "modem_account",
        "modem_password",
        "modem_idle_seconds",
        "modem_country_code",
        "modem_protocol",
        "modem_pulse_dialing",
        "modem_automatically_dial",
        "modem_ignore_dial_tone",
        "modem_use_aol",
        "syslog_destination",
        "syslog_level",
        "snmp_access_flags",
        "ppp_dial_in_enabled",
        "ppp_dial_in_account",
        "ppp_dial_in_password",
        "ppp_dial_in_answer_on_ring",
        "ppp_dial_in_idle_seconds",
        "ppp_dial_in_maximum_connect_seconds",
        "base_station_contact",
        "base_station_location",
        "time_server",
        "multicast_rate",
        "transmit_power",
        "group_key_timeout_seconds",
        "interference_robustness",
        "dhcp_message",
        "ldap_server",
        "access_control_mode",
        "access_control_entries_json",
        "radius_type",
        "radius_primary_address",
        "radius_primary_secret",
        "radius_primary_port",
        "radius_secondary_address",
        "radius_secondary_secret",
        "radius_secondary_port",
        "configure_ipv6",
        "ipv6_mode",
        "ipv6_default_route",
        "ipv6_firewall",
        "remote_ipv4_address",
        "ipv6_lan_address",
        "ipv6_lan_prefix_length",
        "ipv6_delegated_prefix",
        "ipv6_delegated_prefix_length",
        "ipv6_wan_prefix_length",
        "ipv6_connection_sharing",
        "dynamic_global_hostname",
        "dynamic_global_hostname_auto_config",
        "global_hostname",
        "global_hostname_user",
        "global_hostname_password",
        "wireless_mode",
        "wireless_name",
        "wireless_security",
        "wireless_password",
        "allow_network_extension",
        "wds_mode",
        "wds_peer_airport_id",
        "region_code",
        "hidden_network",
        "radio_mode",
        "radio_channel",
        "airplay_enabled",
        "airplay_speaker_name",
        "airplay_speaker_password",
        "airplay_over_wan",
        "allow_setup_over_wan",
        "router_mode",
        "dhcp_range_start",
        "dhcp_range_end",
        "dhcp_lease",
        "nat_pmp",
        "default_host",
        "file_sharing",
        "share_disks_over_wan",
        "disk_security",
        "disk_password",
        "guest_disk_access",
        "share_disks_global_hostname",
        "wins_server",
        "windows_workgroup",
        "usb_file_sharing_flags",
        "disk_account_json",
    ]
    if any(getattr(args, field, None) is not None for field in setting_fields):
        return True
    return bool(
        args.setup_complete
        or args.clear_dns
        or args.clear_ipv6_dns
        or args.clear_default_host
        or args.clear_airplay_speaker_password
    )

def add_advanced_arguments(parser: argparse.ArgumentParser) -> None:
    """Install command-line flags for logging, SNMP, and PPP dial-in."""

    advanced = parser.add_argument_group("Advanced settings")
    advanced.add_argument(
        "--syslog-destination",
        help="set Syslog Destination Address (slCl); use 0.0.0.0 to clear",
    )
    advanced.add_argument(
        "--syslog-level",
        type=int,
        help="set Syslog Level from 0 (Emergency) through 7 (Debug) (slvl)",
    )
    advanced.add_argument(
        "--snmp-access-flags",
        type=int,
        help="set SNMP access flags (snAF): bit 1 disables SNMP, bit 0 blocks WAN",
    )
    advanced.add_argument(
        "--ppp-dial-in-enabled",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="enable or disable PPP Dial-in (pdFl)",
    )
    advanced.add_argument(
        "--ppp-dial-in-account",
        help="set PPP Dial-in Account Name (pdUN)",
    )
    advanced.add_argument(
        "--ppp-dial-in-password",
        help="set PPP Dial-in Password (pdPW)",
    )
    advanced.add_argument(
        "--ppp-dial-in-answer-on-ring",
        type=int,
        help="set the ring number on which PPP Dial-in answers (pdAR)",
    )
    advanced.add_argument(
        "--ppp-dial-in-idle-seconds",
        type=int,
        help="set PPP Dial-in idle disconnect timeout in seconds (pdID)",
    )
    advanced.add_argument(
        "--ppp-dial-in-maximum-connect-seconds",
        type=int,
        help="set PPP Dial-in maximum connect time in seconds (pdMC)",
    )
    advanced.add_argument(
        "--access-control-mode",
        choices=("not-enabled", "local", "radius"),
        help="set wireless access-control mode (acEn/raFl)",
    )
    advanced.add_argument(
        "--access-control-entries-json",
        help="set local access-control entries (acTa)",
    )
    advanced.add_argument(
        "--radius-type",
        choices=("default", "alternate"),
        help="set RADIUS type (raCi)",
    )
    advanced.add_argument("--radius-primary-address", help="set primary RADIUS server (raI1)")
    advanced.add_argument("--radius-primary-secret", help="set primary RADIUS secret (raSe)")
    advanced.add_argument("--radius-primary-port", type=int, help="set primary RADIUS port (raAu)")
    advanced.add_argument("--radius-secondary-address", help="set secondary RADIUS server (raI2)")
    advanced.add_argument("--radius-secondary-secret", help="set secondary RADIUS secret (raS2)")
    advanced.add_argument("--radius-secondary-port", type=int, help="set secondary RADIUS port (raU2)")


def add_network_arguments(parser: argparse.ArgumentParser) -> None:
    """Install command-line flags for the Internet pane settings."""

    network = parser.add_argument_group("Internet pane network settings")
    network.add_argument(
        "--connect-using",
        choices=sorted(CONNECT_USING_VALUES),
        help="set Connect Using (waCV): dhcp, static, pppoe, or modem",
    )
    network.add_argument("--ipv4-address", help="set IPv4 Address (waIP)")
    network.add_argument("--lan-ip-address", help="set LAN IP Address (laIP)")
    network.add_argument("--subnet-mask", help="set Subnet Mask (waSM)")
    network.add_argument("--router-address", help="set Router Address (waRA)")
    network.add_argument(
        "--dns-server",
        action="append",
        help="replace IPv4 DNS Servers (waD1/waD2); repeat or comma-separate",
    )
    network.add_argument("--dns-server-1", help="set first IPv4 DNS Server slot only (waD1)")
    network.add_argument("--dns-server-2", help="set second IPv4 DNS Server slot only (waD2)")
    network.add_argument("--dns-server-3", help="set third IPv4 DNS Server slot only (waD3)")
    network.add_argument("--clear-dns", action="store_true", help="clear IPv4 DNS Servers")
    network.add_argument(
        "--ipv6-dns-server",
        action="append",
        help="replace IPv6 DNS Servers (6NS1/6NS2); repeat or comma-separate",
    )
    network.add_argument("--clear-ipv6-dns", action="store_true", help="clear IPv6 DNS Servers")
    network.add_argument("--domain-name", help="set Domain Name (waDN)")
    network.add_argument("--dhcp-client-id", help="set DHCP Client ID (waDC)")
    network.add_argument("--ipv6-address", help="set IPv6 Address (6Wad)")
    network.add_argument("--pppoe-account", help="set PPPoE Account Name (peUN)")
    network.add_argument("--pppoe-password", help="set PPPoE Password (pePW)")
    network.add_argument("--pppoe-service", help="set PPPoE Service Name (peSN)")
    network.add_argument(
        "--pppoe-connection",
        choices=sorted(PPPOE_CONNECTION_VALUES),
        help="set PPPoE Connection policy (peAC/peSC/peID)",
    )
    network.add_argument("--pppoe-idle-seconds", type=int, help="set PPPoE idle timeout in seconds (peID)")
    network.add_argument("--modem-phone-number", help="set modem primary phone number (moPN)")
    network.add_argument("--modem-alternate-number", help="set modem alternate phone number (moAP)")
    network.add_argument("--modem-account", help="set modem account name (moUN)")
    network.add_argument("--modem-password", help="set modem account password (moPW)")
    network.add_argument("--modem-idle-seconds", type=int, help="set modem idle timeout (moID)")
    network.add_argument("--modem-country-code", type=int, help="set modem country index (moCI)")
    network.add_argument("--modem-protocol", choices=("v34", "v90"), help="set modem protocol (moMP)")
    network.add_argument(
        "--modem-pulse-dialing",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="use pulse rather than tone dialing (moPD)",
    )
    network.add_argument(
        "--modem-automatically-dial",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="automatically dial the modem (moAD)",
    )
    network.add_argument(
        "--modem-ignore-dial-tone",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="ignore the modem dial tone (moDT)",
    )
    network.add_argument(
        "--modem-use-aol",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="use AOL modem mode (moMF)",
    )
    network.add_argument(
        "--configure-ipv6",
        choices=sorted(IPV6_CONFIG_VALUES),
        help="set Configure IPv6: link-local, automatic, or manual",
    )
    network.add_argument(
        "--ipv6-mode",
        choices=sorted(IPV6_MODE_VALUES),
        help="set IPv6 Mode (6cfg)",
    )
    network.add_argument("--ipv6-default-route", help="set IPv6 Default Route (6Wgw)")
    network.add_argument(
        "--ipv6-firewall",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="enable or disable IPv6 firewall/shared firewall (6sfw)",
    )
    network.add_argument("--remote-ipv4-address", help="set Remote IPv4 Address (6Wte)")
    network.add_argument("--ipv6-lan-address", help="set IPv6 LAN Address (6Lad)")
    network.add_argument("--ipv6-lan-prefix-length", type=int, help="set IPv6 LAN Prefix Length (6Lfx)")
    network.add_argument("--ipv6-delegated-prefix", help="set IPv6 Prefix Delegate Address (6PDa)")
    network.add_argument(
        "--ipv6-delegated-prefix-length",
        type=int,
        help="set IPv6 Prefix Delegate Length (6PDl)",
    )
    network.add_argument("--ipv6-wan-prefix-length", type=int, help="set IPv6 WAN Prefix Length (6Wfx)")
    network.add_argument(
        "--ipv6-connection-sharing",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="enable or disable IPv6 connection sharing (6Lfw)",
    )
    network.add_argument(
        "--dynamic-global-hostname",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="enable or disable Dynamic Global Hostname (wbEn)",
    )
    network.add_argument("--global-hostname", help="set Dynamic Global Hostname host (wbHN)")
    network.add_argument("--global-hostname-user", help="set Dynamic Global Hostname user (wbHU)")
    network.add_argument("--global-hostname-password", help="set Dynamic Global Hostname password (wbHP)")
    network.add_argument(
        "--dynamic-global-hostname-auto-config",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="enable or disable Dynamic Global Hostname auto configuration (wbAC)",
    )

    add_advanced_arguments(parser)

    wireless = parser.add_argument_group("Wireless tab settings")
    wireless.add_argument(
        "--wireless-mode",
        choices=sorted(WIRELESS_MODE_VALUES),
        help="set Network Mode (raSt)",
    )
    wireless.add_argument("--wireless-name", help="set Wireless Network Name (raNm)")
    wireless.add_argument(
        "--wireless-security",
        choices=sorted(WIRELESS_SECURITY_VALUES),
        help="set Wireless Security (raWM)",
    )
    wireless.add_argument("--wireless-password", help="set Wireless Password (raCr/raWE)")
    wireless.add_argument(
        "--allow-network-extension",
        dest="allow_network_extension",
        action="store_true",
        default=None,
        help="allow this network to be extended (dWDS)",
    )
    wireless.add_argument(
        "--no-allow-network-extension",
        dest="allow_network_extension",
        action="store_false",
        help="do not allow this network to be extended (dWDS)",
    )
    wireless.add_argument(
        "--wds-peer-airport-id",
        action="append",
        help="set WDS peer AirPort ID list (wdLs); repeat or comma-separate",
    )
    wireless.add_argument(
        "--wds-mode",
        choices=sorted(WDS_MODE_VALUES),
        help="set WDS role (bsWM)",
    )
    wireless.add_argument("--region-code", type=int, help="set wireless Region code (syRe); 0 is United States")
    wireless.add_argument(
        "--hidden-network",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="enable or disable Create hidden network (raCl)",
    )
    wireless.add_argument(
        "--radio-mode",
        choices=sorted(RADIO_MODE_VALUES),
        help="set Radio Mode (raMd)",
    )
    wireless.add_argument("--radio-channel", help="set Radio Channel (raCh), e.g. automatic or 11")
    wireless.add_argument("--multicast-rate", type=int, help="set Multicast Rate (raMu)")
    wireless.add_argument("--transmit-power", type=int, help="set Transmit Power percent (raPo)")
    wireless.add_argument(
        "--group-key-timeout-seconds",
        type=int,
        help="set WPA Group Key Timeout in seconds (raKT)",
    )
    wireless.add_argument(
        "--interference-robustness",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="enable or disable interference robustness (raRo)",
    )

    airplay = parser.add_argument_group("AirPlay tab settings")
    airplay.add_argument(
        "--airplay-enabled",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="enable or disable AirPlay (auRR)",
    )
    airplay.add_argument("--airplay-speaker-name", help="set AirPlay Speaker Name (auNN)")
    airplay.add_argument("--airplay-speaker-password", help="set AirPlay Speaker Password (auNP)")
    airplay.add_argument(
        "--clear-airplay-speaker-password",
        action="store_true",
        help="clear AirPlay Speaker Password (auNP)",
    )
    airplay.add_argument(
        "--airplay-over-wan",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="enable or disable AirPlay over WAN (aWan)",
    )

    base_station = parser.add_argument_group("Base Station tab settings")
    base_station.add_argument(
        "--allow-setup-over-wan",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="enable or disable setup over the Ethernet WAN port (raWB)",
    )
    base_station.add_argument("--base-station-contact", help="set Contact (syCt)")
    base_station.add_argument("--base-station-location", help="set Location (syLo)")
    base_station.add_argument(
        "--time-server",
        help="set automatic Time Server (ntSV); use an empty value to disable",
    )

    router = parser.add_argument_group("Network tab settings")
    router.add_argument(
        "--router-mode",
        choices=sorted(ROUTER_MODE_VALUES),
        help="set Router Mode (bsRM)",
    )
    router.add_argument("--dhcp-range-start", help="set DHCP Range beginning (dhBg)")
    router.add_argument("--dhcp-range-end", help="set DHCP Range ending (dhEn)")
    router.add_argument("--dhcp-lease", type=int, help="set DHCP Lease duration number (dhLe)")
    router.add_argument(
        "--dhcp-lease-unit",
        choices=sorted(DHCP_LEASE_UNITS),
        default="seconds",
        help="unit for --dhcp-lease; default: seconds",
    )
    router.add_argument(
        "--nat-pmp",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="enable or disable NAT Port Mapping Protocol (naFl)",
    )
    router.add_argument("--default-host", help="set default host IP address (nDMZ)")
    router.add_argument("--clear-default-host", action="store_true", help="clear default host (nDMZ)")
    router.add_argument("--dhcp-message", help="set DHCP Message (dhMg)")
    router.add_argument("--ldap-server", help="set LDAP Server (dh95)")

    disks = parser.add_argument_group("Disks tab settings")
    disks.add_argument(
        "--file-sharing",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="enable or disable file sharing (bsFS)",
    )
    disks.add_argument(
        "--share-disks-over-wan",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="enable or disable Share disks over WAN (bsRF)",
    )
    disks.add_argument(
        "--disk-security",
        choices=sorted(DISK_SECURITY_VALUES),
        help="set Secure Shared Disks mode (bsFM)",
    )
    disks.add_argument("--disk-password", help="set Disk Password (fssp)")
    disks.add_argument(
        "--guest-disk-access",
        choices=sorted(GUEST_DISK_ACCESS_VALUES),
        help="set Guest Access for shared disks (bsGA)",
    )
    disks.add_argument(
        "--share-disks-global-hostname",
        action=argparse.BooleanOptionalAction,
        default=None,
        help="enable or disable Share Disks Using Global Hostname (bsWF)",
    )
    disks.add_argument("--wins-server", help="set Windows File Sharing WINS Server (SMBs)")
    disks.add_argument("--windows-workgroup", help="set Windows File Sharing Workgroup (SMBw)")
    disks.add_argument("--usb-file-sharing-flags", type=int, help="set USB file sharing flags (usbF)")
    disks.add_argument(
        "--disk-account-json",
        action="append",
        help="append one disk file-sharing account JSON object for usrd.users",
    )

    disk_actions = parser.add_argument_group("Disk management actions")
    disk_actions.add_argument(
        "--erase-disk",
        action="store_true",
        help="erase the selected Time Capsule disk partition with diskd.eraseDisk",
    )
    disk_actions.add_argument(
        "--erase-method",
        choices=sorted(ERASE_METHOD_VALUES),
        default="quick",
        help="security method for --erase-disk; default: quick",
    )
    disk_actions.add_argument(
        "--volume-name",
        help="volume name to pass to diskd.eraseDisk; defaults to the selected disk partition name",
    )
    disk_actions.add_argument(
        "--partition-uuid",
        help="partition UUID hex for --erase-disk; defaults to the selected disk partition uuid",
    )
    disk_actions.add_argument(
        "--erase-message",
        help="message string to pass to diskd.eraseDisk; defaults to AirPort Utility's erase warning",
    )
    disk_actions.add_argument(
        "--i-know-this-erases-the-disk",
        action="store_true",
        help="required to run --erase-disk without --dry-run",
    )
    disk_actions.add_argument(
        "--archive-disk",
        action="store_true",
        help="archive the built-in Time Capsule disk to an external AirPort disk",
    )
    disk_actions.add_argument(
        "--archive-name",
        help="archive folder/image name; defaults to '<source volume> Archive'",
    )
    disk_actions.add_argument(
        "--archive-source-uuid",
        help="source partition UUID hex; defaults to the single built-in disk partition",
    )
    disk_actions.add_argument(
        "--archive-destination-uuid",
        help="destination partition UUID hex; defaults to the single external disk partition",
    )
    disk_actions.add_argument(
        "--archive-source-name",
        help="source volume name; useful when multiple built-in partitions exist",
    )
    disk_actions.add_argument(
        "--archive-destination-name",
        help="destination volume name; useful when multiple external partitions exist",
    )
    disk_actions.add_argument(
        "--archive-message",
        help="message string to pass to diskd.archiveDisk; defaults to AirPort Utility's archive message",
    )
    disk_actions.add_argument(
        "--i-know-this-starts-the-archive",
        action="store_true",
        help="required to run --archive-disk without --dry-run",
    )

    firmware_actions = parser.add_argument_group("Firmware management actions")
    firmware_actions.add_argument(
        "--upload-firmware",
        help="firmware image file path or manifest URL to install",
    )
    firmware_actions.add_argument(
        "--i-know-this-updates-firmware",
        action="store_true",
        help="required to run --upload-firmware without --dry-run",
    )
