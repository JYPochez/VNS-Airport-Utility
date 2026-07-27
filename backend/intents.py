from __future__ import annotations

import json
import struct
from typing import Any

from backend.cfb0 import CFB0_MAGIC
from backend.cfb0 import CFB0Integer
from backend.cfb0 import cfb0_dumps
from backend.cfb0 import cfb0_loads
from backend.firmware import FIRMWARE_MAX_STREAM_SIZE
from backend.firmware import FIRMWARE_REBOOT_PROPERTY
from backend.firmware import FIRMWARE_START_PROPERTY
from backend.firmware import FIRMWARE_UPLOAD_PROPERTY
from backend.firmware import firmware_source_bytes
from backend.legacy import bool_value
from backend.legacy import encode_setting_value
from backend.legacy import int32_value

PARSE_DIRTY_PLIST = "acpd.parseDirtyPlist"
SET_DIRTY_PLIST = "acpd.setDirtyPlist"

SENSITIVE_INTENT_SETTINGS = {
    "auNP",
    "bsBT",
    "bsDP",
    "bsGP",
    "fssp",
    "pePW",
    "raCr",
    "raWE",
    "raWP",
    "raW2",
    "raSe",
    "raS2",
    "syPW",
    "wbHP",
    "wbRP",
}
STRUCTURED_VALUE_ONLY_INTENT_SETTINGS = {"usrd"}

def json_safe_rpc_value(value: Any) -> Any:
    """Convert RPC values to printable JSON without losing byte identity."""

    if isinstance(value, bytes):
        return {
            "type": "bytes",
            "length": len(value),
            "hex": value.hex(),
        }
    if isinstance(value, dict):
        return {str(key): json_safe_rpc_value(item) for key, item in value.items()}
    if isinstance(value, list):
        return [json_safe_rpc_value(item) for item in value]
    return value

def value_from_json_setting(value: Any) -> Any:
    if (
        isinstance(value, dict)
        and value.get("type") == "wpa-psk"
        and isinstance(value.get("password"), str)
        and isinstance(value.get("ssid"), str)
    ):
        from backend.settings import wpa_preshared_key

        return wpa_preshared_key(value["password"], value["ssid"])
    if isinstance(value, dict) and value.get("type") == "bytes" and isinstance(value.get("hex"), str):
        return bytes.fromhex(value["hex"])
    if (
        isinstance(value, dict)
        and value.get("type") == "integer"
        and isinstance(value.get("decimal"), str)
    ):
        number = int(value["decimal"], 10)
        width = value.get("width")
        return CFB0Integer(number, width) if width in {1, 2, 4, 8} else number
    if isinstance(value, dict) and value.get("redacted") is True and isinstance(value.get("length"), int):
        return b"p" * max(0, value["length"])
    if isinstance(value, dict):
        return {str(key): value_from_json_setting(item) for key, item in value.items()}
    if isinstance(value, list):
        return [value_from_json_setting(item) for item in value]
    return value

def normalized_intent_value(setting: str, value: Any) -> Any:
    """Return a stable, secret-safe representation of an outgoing setting value."""

    if setting in SENSITIVE_INTENT_SETTINGS:
        length = len(value) if isinstance(value, (bytes, bytearray, str)) else None
        item: dict[str, Any] = {"redacted": True}
        if length is not None:
            item["length"] = length
        return item

    if isinstance(value, bytes):
        item: dict[str, Any] = {"type": "bytes", "length": len(value), "hex": value.hex()}
        stripped = value.rstrip(b"\x00")
        try:
            text = stripped.decode("utf-8")
        except UnicodeDecodeError:
            text = ""
        if text and all(ch.isprintable() for ch in text):
            item["text"] = text
        if len(value) == 4:
            item["u32"] = struct.unpack(">I", value)[0]
        return item
    if isinstance(value, dict):
        return {
            str(key): normalized_intent_value(str(key), item)
            for key, item in sorted(value.items(), key=lambda pair: str(pair[0]))
        }
    if isinstance(value, list):
        return [normalized_intent_value(setting, item) for item in value]
    return value

def modern_dirty_plist_value_bytes(value: Any) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bool):
        return bool_value(value)
    if isinstance(value, int):
        return int32_value(value)
    if isinstance(value, str):
        return value.encode("utf-8")
    if isinstance(value, (dict, list)):
        return cfb0_dumps(value)
    raise TypeError(f"unsupported modern dirty plist value: {type(value).__name__}")

def normalized_dirty_properties(dirty: dict[str, Any], *, legacy_property_write: bool = False) -> list[dict[str, Any]]:
    """Normalize a dirty settings dictionary for protocol-intent comparison."""

    properties: list[dict[str, Any]] = []
    for setting in sorted(dirty):
        value = dirty[setting]
        semantic_value = value
        if (
            setting in {"Prof", "WiFi", "timz"}
            and isinstance(value, bytes)
            and value.startswith(CFB0_MAGIC)
        ):
            try:
                semantic_value = cfb0_loads(value)
            except Exception:
                semantic_value = value
        encoded: bytes | None = None
        try:
            encoded = (
                encode_setting_value(setting, value)
                if legacy_property_write
                else modern_dirty_plist_value_bytes(value)
            )
        except Exception:
            encoded = None
        item: dict[str, Any] = {
            "name": setting,
            "value": normalized_intent_value(setting, semantic_value),
        }
        if encoded is not None and setting not in STRUCTURED_VALUE_ONLY_INTENT_SETTINGS:
            item["encodedLength"] = len(encoded)
            if setting in SENSITIVE_INTENT_SETTINGS:
                item["encoded"] = {"redacted": True, "length": len(encoded)}
            else:
                item["encoded"] = normalized_intent_value(setting, encoded)
        properties.append(item)
    return properties

def normalized_modern_write_intent(
    host: str,
    dirty: dict[str, Any],
    *,
    include_parse: bool = True,
    profile_mirroring: str = "not-evaluated-offline",
) -> dict[str, Any]:
    """Build an offline modern ACP RPC intent document for dirty settings."""

    operations: list[dict[str, Any]] = []
    if include_parse:
        operations.append(
            {
                "kind": "rpc",
                "command": "0x19",
                "function": PARSE_DIRTY_PLIST,
                "flags": 4,
                "writeAffecting": False,
                "properties": normalized_dirty_properties(dirty),
            }
        )
    operations.append(
        {
            "kind": "rpc",
            "command": "0x19",
            "function": SET_DIRTY_PLIST,
            "flags": 0,
            "writeAffecting": True,
            "properties": normalized_dirty_properties(dirty),
        }
    )
    return {
        "format": "airport-normalized-protocol-intent-v1",
        "backend": "modern",
        "host": host,
        "profileMirroring": profile_mirroring,
        "changedKeys": sorted(dirty),
        "operations": operations,
    }

def normalized_legacy_write_intent(
    host: str,
    dirty: dict[str, Any],
    *,
    streaming: bool,
    apply: bool,
    request_flags: int = 4,
) -> dict[str, Any]:
    """Build an offline legacy ACP property-write intent document."""

    return {
        "format": "airport-normalized-protocol-intent-v1",
        "backend": "legacy",
        "host": host,
        "changedKeys": sorted(dirty),
        "operations": [
            {
                "kind": "property-write",
                "command": "0x15",
                "flags": request_flags,
                "streaming": streaming,
                "writeAffecting": True,
                "apply": apply,
                "restart": apply,
                "properties": normalized_dirty_properties(dirty, legacy_property_write=True),
            }
        ],
    }

def normalized_action_intent(host: str, action: str, options: dict[str, Any]) -> dict[str, Any]:
    """Build an offline action intent for RPC actions that need live selection."""

    return {
        "format": "airport-normalized-protocol-intent-v1",
        "backend": "modern",
        "host": host,
        "changedKeys": [],
        "operations": [
            {
                "kind": "rpc",
                "command": "0x19",
                "function": action,
                "flags": 4,
                "writeAffecting": True,
                "requiresLiveSelection": True,
                "inputs": json_safe_rpc_value(options),
            }
        ],
    }

def normalized_firmware_upload_intent(host: str, source: str) -> dict[str, Any]:
    """Build the modern firmware property-write intent AirPort Utility emits."""

    firmware_data = firmware_source_bytes(source, max_size=FIRMWARE_MAX_STREAM_SIZE)
    return {
        "format": "airport-normalized-protocol-intent-v1",
        "backend": "modern",
        "host": host,
        "changedKeys": [
            FIRMWARE_UPLOAD_PROPERTY,
            FIRMWARE_START_PROPERTY,
            FIRMWARE_REBOOT_PROPERTY,
        ],
        "operations": [
            {
                "kind": "property-write",
                "command": "0x15",
                "flags": 4,
                "streaming": True,
                "writeAffecting": True,
                "properties": normalized_dirty_properties({FIRMWARE_UPLOAD_PROPERTY: firmware_data}),
            },
            {
                "kind": "property-write",
                "command": "0x15",
                "flags": 4,
                "streaming": True,
                "writeAffecting": True,
                "properties": normalized_dirty_properties({FIRMWARE_START_PROPERTY: b""}),
            },
            {
                "kind": "property-write",
                "command": "0x15",
                "flags": 0,
                "streaming": True,
                "writeAffecting": True,
                "properties": normalized_dirty_properties({FIRMWARE_REBOOT_PROPERTY: b""}),
            },
        ],
    }
