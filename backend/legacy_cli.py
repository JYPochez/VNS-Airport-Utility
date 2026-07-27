from __future__ import annotations

import argparse
import json
from typing import Any

from backend.intents import value_from_json_setting
from backend.settings import build_network_dirty_plist

LEGACY_WRITE_NETWORK_DEFAULTS: dict[str, Any] = {
    "router_mode": None,
    "dhcp_range_start": None,
    "dhcp_range_end": None,
    "dhcp_lease": None,
    "dhcp_lease_unit": None,
    "nat_pmp": None,
    "default_host": None,
    "enable_default_host": None,
    "disk_file_sharing": None,
    "disk_security": None,
    "guest_disk_access": None,
    "share_disks_wan": None,
    "share_disks_global_hostname": None,
    "wins_server": None,
    "windows_workgroup": None,
    "usb_file_sharing_flags": None,
    "disk_account_json": None,
}


def ensure_legacy_network_defaults(
    args: argparse.Namespace,
    defaults: dict[str, Any] = LEGACY_WRITE_NETWORK_DEFAULTS,
) -> None:
    for name, value in defaults.items():
        if not hasattr(args, name):
            setattr(args, name, value)


def build_dirty(
    args: argparse.Namespace,
    defaults: dict[str, Any] = LEGACY_WRITE_NETWORK_DEFAULTS,
) -> dict[str, Any]:
    dirty: dict[str, Any] = {}
    explicitly_set: set[str] = set()
    if getattr(args, "base_values_json", None) is not None:
        try:
            base_values = json.loads(args.base_values_json, object_pairs_hook=dict)
        except json.JSONDecodeError as exc:
            raise ValueError(f"--base-values-json is not valid JSON: {exc}") from None
        if not isinstance(base_values, dict) or not base_values:
            raise ValueError("--base-values-json must be a non-empty object")
        for setting, value in base_values.items():
            if len(setting) != 4 or len(setting.encode("ascii", errors="ignore")) != 4:
                raise ValueError(f"setting names must be exactly 4 ASCII characters: {setting!r}")
            dirty[setting] = value_from_json_setting(value)
    if getattr(args, "values_json", None) is not None:
        try:
            values = json.loads(args.values_json, object_pairs_hook=dict)
        except json.JSONDecodeError as exc:
            raise ValueError(f"--values-json is not valid JSON: {exc}") from None
        if not isinstance(values, dict) or not values:
            raise ValueError("--values-json must be a non-empty object")
        for setting, value in values.items():
            if len(setting) != 4 or len(setting.encode("ascii", errors="ignore")) != 4:
                raise ValueError(f"setting names must be exactly 4 ASCII characters: {setting!r}")
            dirty[setting] = value_from_json_setting(value)
            explicitly_set.add(setting)
    elif args.setting is not None:
        if args.value_json is not None:
            try:
                dirty[args.setting] = value_from_json_setting(json.loads(args.value_json))
            except json.JSONDecodeError as exc:
                raise ValueError(f"--value-json is not valid JSON: {exc}") from None
        else:
            dirty[args.setting] = args.value or ""
        explicitly_set.add(args.setting)
    ensure_legacy_network_defaults(args, defaults)
    network_dirty = build_network_dirty_plist(args)
    if getattr(args, "connect_using", None) == "dhcp":
        # Legacy 5.x devices omit the modern 0x8000 capability bit.
        network_dirty["waCV"] = 0x0300
    dirty.update(network_dirty)
    if "wdFl" in explicitly_set:
        wd_flags = dirty.get("wdFl")
        if isinstance(wd_flags, bytes):
            wd_flags = int.from_bytes(wd_flags, "big")
        if isinstance(wd_flags, int) and wd_flags != 0:
            dirty.pop("wdLs", None)
    return dirty
