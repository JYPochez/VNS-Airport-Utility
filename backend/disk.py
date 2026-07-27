from __future__ import annotations

from typing import Any


DEFAULT_ERASE_MESSAGE = "Erasing the AirPort Time Capsule disk cannot be canceled."
DEFAULT_ERASE_VOLUME_NAME = "Data"
DEFAULT_ARCHIVE_NAME = "AirPort Time Capsule Archive"
DEFAULT_ARCHIVE_MESSAGE = (
    "The AirPort Time Capsule disk {source} is being archived to the AirPort disk "
    "{destination}. Cancel to stop archiving the disk."
)
ERASE_METHOD_VALUES = {
    "quick": 0,
    "zero": 1,
    "7-pass": 2,
    "35-pass": 3,
}


def parse_uuid_bytes(value: str) -> bytes:
    """Return 16 UUID bytes from hex with optional dashes."""

    clean = value.replace("-", "").lower()
    if len(clean) != 32:
        raise ValueError("partition UUID must be 16 bytes / 32 hex characters")
    try:
        raw = bytes.fromhex(clean)
    except ValueError:
        raise ValueError("partition UUID must be hexadecimal") from None
    return raw


def iter_mast_disks(mast: Any) -> list[dict[str, Any]]:
    """Return disk records from the MaSt inventory."""

    if not isinstance(mast, list):
        raise ValueError("disk inventory did not decode to a disk list")
    return [disk for disk in mast if isinstance(disk, dict)]


def iter_mast_partitions(mast: Any) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    """Return disk/partition records from the MaSt inventory."""

    partitions: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for disk in iter_mast_disks(mast):
        for partition in disk.get("partitions", []):
            if isinstance(partition, dict):
                partitions.append((disk, partition))
    return partitions


def partition_label(disk: dict[str, Any], partition: dict[str, Any]) -> str:
    """Return a compact disk/partition label for status output."""

    disk_name = disk.get("deviceName", "disk")
    partition_name = partition.get("deviceName", "partition")
    volume_name = partition.get("name", "")
    uuid = partition.get("uuid")
    uuid_text = uuid.hex() if isinstance(uuid, bytes) else "unknown-uuid"
    if volume_name:
        return f"{volume_name} ({disk_name}/{partition_name}, {uuid_text})"
    return f"{disk_name}/{partition_name} ({uuid_text})"


def select_mast_partition(
    mast: Any,
    uuid: bytes | None,
    volume_name: str | None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Select a MaSt partition by UUID, by name, or first available partition."""

    partitions = iter_mast_partitions(mast)
    if not partitions:
        return select_mast_disk_without_partitions(mast, uuid, volume_name)

    if uuid is not None:
        for disk, partition in partitions:
            if partition.get("uuid") == uuid:
                return disk, partition
        raise ValueError(f"partition UUID {uuid.hex()} was not found in disk inventory")

    if volume_name is not None:
        matches = [
            (disk, partition)
            for disk, partition in partitions
            if partition.get("name") == volume_name
        ]
        if len(matches) == 1:
            return matches[0]
        if not matches:
            raise ValueError(f"volume name {volume_name!r} was not found in disk inventory")
        raise ValueError(f"volume name {volume_name!r} matched more than one partition")

    return partitions[0]


def select_mast_disk_without_partitions(
    mast: Any,
    uuid: bytes | None,
    volume_name: str | None,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Select a disk-level erase target when MaSt has no partition records."""

    disks = iter_mast_disks(mast)
    if not disks:
        raise ValueError("disk inventory did not contain any disk partitions")

    if uuid is not None:
        matches = [disk for disk in disks if disk.get("uuid") == uuid]
        if len(matches) == 1:
            disk = matches[0]
        elif matches:
            raise ValueError(f"disk UUID {uuid.hex()} matched more than one disk")
        else:
            raise ValueError(f"partition or disk UUID {uuid.hex()} was not found in disk inventory")
    else:
        built_in_disks = [disk for disk in disks if disk_is_builtin(disk)]
        candidates = built_in_disks or disks
        if len(candidates) > 1:
            raise ValueError(
                "disk inventory did not contain partitions; pass --erase-partition-uuid to choose a disk"
            )
        disk = candidates[0]

    disk_uuid = disk.get("uuid")
    if not isinstance(disk_uuid, bytes) or len(disk_uuid) != 16:
        raise ValueError("selected disk inventory disk does not have a 16-byte uuid")

    target_name = volume_name or disk.get("name") or disk.get("IDNm") or DEFAULT_ERASE_VOLUME_NAME
    if not isinstance(target_name, str) or not target_name:
        target_name = DEFAULT_ERASE_VOLUME_NAME

    return disk, {
        "deviceName": disk.get("deviceName", "disk"),
        "name": target_name,
        "uuid": disk_uuid,
    }


def partition_uuid(partition: dict[str, Any]) -> bytes:
    """Return the 16-byte UUID from a MaSt partition."""

    uuid = partition.get("uuid")
    if not isinstance(uuid, bytes) or len(uuid) != 16:
        raise ValueError("selected disk inventory partition does not have a 16-byte uuid")
    return uuid


def partition_volume_name(partition: dict[str, Any]) -> str:
    """Return the volume name from a MaSt partition."""

    name = partition.get("name")
    if not isinstance(name, str) or not name:
        raise ValueError("selected disk inventory partition does not have a volume name")
    return name


def matching_partitions(
    mast: Any,
    uuid: bytes | None,
    volume_name: str | None,
    builtin: bool | None,
) -> list[tuple[dict[str, Any], dict[str, Any]]]:
    """Return MaSt partitions matching optional UUID, name, and disk kind."""

    matches: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for disk, partition in iter_mast_partitions(mast):
        if uuid is not None and partition.get("uuid") != uuid:
            continue
        if volume_name is not None and partition.get("name") != volume_name:
            continue
        if builtin is not None and disk_is_builtin(disk) is not builtin:
            continue
        matches.append((disk, partition))
    return matches


def disk_is_builtin(disk: dict[str, Any]) -> bool:
    """Return whether a MaSt disk is the built-in Time Capsule disk."""

    for key in ("builtIn", "builtin"):
        value = disk.get(key)
        if isinstance(value, bool):
            return value
    return str(disk.get("deviceName", "")).startswith("wd")


def select_archive_partition(
    mast: Any,
    role: str,
    uuid_text: str | None,
    volume_name: str | None,
    builtin: bool,
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Select one archive source or destination partition from MaSt."""

    uuid = parse_uuid_bytes(uuid_text) if uuid_text else None
    matches = matching_partitions(mast, uuid, volume_name, builtin)
    kind = "built-in" if builtin else "external"

    if len(matches) == 1:
        return matches[0]
    if matches:
        raise ValueError(
            f"{role} matched more than one {kind} partition; pass --archive-{role}-uuid"
        )

    filters = []
    if uuid is not None:
        filters.append(f"UUID {uuid.hex()}")
    if volume_name is not None:
        filters.append(f"name {volume_name!r}")
    suffix = f" matching {' and '.join(filters)}" if filters else ""
    raise ValueError(f"no {kind} archive {role} partition found in disk inventory{suffix}")


def build_erase_disk_options_from_mast(
    mast: Any,
    method_name: str,
    volume_name: str | None,
    uuid_text: str | None,
    message: str | None,
) -> tuple[dict[str, Any], str]:
    """Build AirPort Utility's disk erase option dictionary from MaSt."""

    uuid = parse_uuid_bytes(uuid_text) if uuid_text else None
    disk, partition = select_mast_partition(mast, uuid, None if uuid is not None else volume_name)
    selected_label = partition_label(disk, partition)

    found_uuid = partition.get("uuid")
    if not isinstance(found_uuid, bytes) or len(found_uuid) != 16:
        raise ValueError("selected disk inventory partition does not have a 16-byte uuid")
    if uuid is None:
        uuid = found_uuid

    found_name = partition.get("name")
    if not isinstance(found_name, str) or not found_name:
        raise ValueError("selected disk inventory partition does not have a volume name")
    if volume_name is None:
        volume_name = found_name
    elif volume_name != found_name:
        raise ValueError(
            f"partition UUID {uuid.hex()} is named {found_name!r}, not {volume_name!r}"
        )

    options = {
        "method": ERASE_METHOD_VALUES[method_name],
        "volumeName": volume_name,
        "message": message or DEFAULT_ERASE_MESSAGE,
        "uuid": uuid,
    }
    return options, selected_label


def default_archive_name(source_name: str) -> str:
    """Return AirPort Utility's simple default archive name."""

    if source_name:
        return f"{source_name} Archive"
    return DEFAULT_ARCHIVE_NAME


def build_archive_disk_options_from_mast(
    mast: Any,
    source_uuid_text: str | None,
    destination_uuid_text: str | None,
    source_name: str | None,
    destination_name: str | None,
    archive_name: str | None,
    message: str | None,
) -> tuple[dict[str, Any], str, str]:
    """Build AirPort Utility's disk archive option dictionary from MaSt."""

    source_disk, source_partition = select_archive_partition(
        mast,
        "source",
        source_uuid_text,
        source_name,
        builtin=True,
    )
    destination_disk, destination_partition = select_archive_partition(
        mast,
        "destination",
        destination_uuid_text,
        destination_name,
        builtin=False,
    )

    source_uuid = partition_uuid(source_partition)
    destination_uuid = partition_uuid(destination_partition)
    if source_uuid == destination_uuid:
        raise ValueError("archive source and destination must be different partitions")

    source_volume_name = partition_volume_name(source_partition)
    destination_volume_name = partition_volume_name(destination_partition)
    if source_name is not None and source_name != source_volume_name:
        raise ValueError(
            f"archive source UUID {source_uuid.hex()} is named {source_volume_name!r}, "
            f"not {source_name!r}"
        )
    if destination_name is not None and destination_name != destination_volume_name:
        raise ValueError(
            f"archive destination UUID {destination_uuid.hex()} is named "
            f"{destination_volume_name!r}, not {destination_name!r}"
        )

    source_used = partition_size_used(source_partition)
    destination_free = destination_partition.get("sizeFree")
    if isinstance(source_used, int) and isinstance(destination_free, int):
        if source_used > destination_free:
            raise ValueError(
                f"archive destination has insufficient free space: needs {source_used}, "
                f"has {destination_free}"
            )

    final_archive_name = archive_name or default_archive_name(source_volume_name)
    final_message = message or DEFAULT_ARCHIVE_MESSAGE.format(
        source=source_volume_name,
        destination=destination_volume_name,
    )
    options = {
        "archiveName": final_archive_name,
        "message": final_message,
        "srcUUID": source_uuid,
        "dstUUID": destination_uuid,
    }
    return options, partition_label(source_disk, source_partition), partition_label(
        destination_disk,
        destination_partition,
    )


def partition_size_used(partition: dict[str, Any]) -> int | None:
    """Return used bytes from MaSt partition fields when available."""

    size_used = partition.get("sizeUsed")
    if isinstance(size_used, int):
        return size_used
    size = partition.get("size")
    size_free = partition.get("sizeFree")
    if isinstance(size, int) and isinstance(size_free, int) and size >= size_free:
        return size - size_free
    return None
