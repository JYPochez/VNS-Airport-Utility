from __future__ import annotations

import struct
from typing import Any, Callable

from backend.acp import ACPEncryptedTransport
from backend.firmware import FIRMWARE_UPLOAD_CAPABILITY
from backend.firmware import format_mac_address
from backend.modern import read_properties
from backend.modern import read_property


def read_u32_property(transport: ACPEncryptedTransport, setting: str) -> int:
    value = read_property(transport, setting)
    if len(value) == 4:
        return struct.unpack(">I", value)[0]
    text = value.rstrip(b"\x00").decode("ascii", errors="ignore").strip()
    if text.isdigit():
        return int(text)
    raise RuntimeError(f"property {setting} was not a 32-bit integer")


def supports_firmware_property_upload(transport: ACPEncryptedTransport) -> bool:
    try:
        features = read_property(transport, "feat").decode("ascii", errors="ignore")
        return FIRMWARE_UPLOAD_CAPABILITY in features
    except Exception:
        return False


def host_supports_firmware_property_upload(
    host: str,
    password: str,
    *,
    open_encrypted_transport: Callable[[str, str], tuple[Any, ACPEncryptedTransport]],
) -> bool:
    sock, transport = open_encrypted_transport(host, password)
    with sock:
        return supports_firmware_property_upload(transport)


def preflight_firmware_upload(
    host: str,
    password: str,
    firmware_info: dict[str, Any],
    *,
    open_encrypted_transport: Callable[[str, str], tuple[Any, ACPEncryptedTransport]],
) -> dict[str, Any]:
    sock, transport = open_encrypted_transport(host, password)
    with sock:
        values, errors = read_properties(transport, ["syAP", "feat", "srcv", "minS", "waMA"])
        if "syAP" not in values:
            raise RuntimeError(errors.get("syAP", "property syAP was not present"))

        product_value = values["syAP"]
        if len(product_value) == 4:
            device_product_id = struct.unpack(">I", product_value)[0]
        else:
            text = product_value.rstrip(b"\x00").decode("ascii", errors="ignore").strip()
            if not text.isdigit():
                raise RuntimeError("property syAP was not a 32-bit integer")
            device_product_id = int(text)

        image_product_id = int(firmware_info["productID"])
        if device_product_id != image_product_id:
            raise ValueError(
                "firmware product ID does not match base station: "
                f"image {image_product_id}, device {device_product_id}"
            )

        features = values.get("feat", b"").decode("ascii", errors="ignore")
        result: dict[str, Any] = {
            "deviceProductID": device_product_id,
            "supportsPropertyUpload": FIRMWARE_UPLOAD_CAPABILITY in features,
        }
        if len(values.get("waMA", b"")) == 6:
            result["wanMACAddress"] = format_mac_address(values["waMA"])
        elif "waMA" in errors:
            result["wanMACAddressError"] = errors["waMA"]
        for setting, label in (
            ("srcv", "deviceSourceVersion"),
            ("minS", "minimumSourceVersion"),
        ):
            if setting in values:
                result[label] = values[setting].rstrip(b"\x00").decode(
                    "ascii",
                    errors="replace",
                )
            elif setting in errors:
                result[f"{label}Error"] = errors[setting]
        return result
