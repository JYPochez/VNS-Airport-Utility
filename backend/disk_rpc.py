from __future__ import annotations

from typing import Any, Callable

from backend.acp import ACPEncryptedTransport
from backend.disk import build_archive_disk_options_from_mast
from backend.disk import build_erase_disk_options_from_mast

ERASE_DISK = "diskd.eraseDisk"
ARCHIVE_DISK = "diskd.archiveDisk"


def build_erase_disk_options(
    host: str,
    password: str,
    method_name: str,
    volume_name: str | None,
    uuid_text: str | None,
    message: str | None,
    *,
    read_cfb0_setting: Callable[[str, str, str], Any],
) -> tuple[dict[str, Any], str]:
    mast = read_cfb0_setting(host, password, "MaSt")
    return build_erase_disk_options_from_mast(mast, method_name, volume_name, uuid_text, message)


def build_archive_disk_options(
    host: str,
    password: str,
    source_uuid_text: str | None,
    destination_uuid_text: str | None,
    source_name: str | None,
    destination_name: str | None,
    archive_name: str | None,
    message: str | None,
    *,
    read_cfb0_setting: Callable[[str, str, str], Any],
) -> tuple[dict[str, Any], str, str]:
    mast = read_cfb0_setting(host, password, "MaSt")
    return build_archive_disk_options_from_mast(
        mast,
        source_uuid_text,
        destination_uuid_text,
        source_name,
        destination_name,
        archive_name,
        message,
    )


def erase_disk(
    host: str,
    password: str,
    options: dict[str, Any],
    *,
    open_encrypted_transport: Callable[[str, str], tuple[Any, ACPEncryptedTransport]],
    rpc_call: Callable[[ACPEncryptedTransport, str, dict[str, Any], int], dict[str, Any]],
) -> dict[str, Any]:
    sock, transport = open_encrypted_transport(host, password)
    with sock:
        return rpc_call(transport, ERASE_DISK, options, flags=4)


def archive_disk(
    host: str,
    password: str,
    options: dict[str, Any],
    *,
    open_encrypted_transport: Callable[[str, str], tuple[Any, ACPEncryptedTransport]],
    rpc_call: Callable[[ACPEncryptedTransport, str, dict[str, Any], int], dict[str, Any]],
) -> dict[str, Any]:
    sock, transport = open_encrypted_transport(host, password)
    with sock:
        return rpc_call(transport, ARCHIVE_DISK, options, flags=4)
