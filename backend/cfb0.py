from __future__ import annotations

from typing import Any


CFB0_MAGIC = b"CFB0"


class CFB0CodecError(ValueError):
    """Raised when the CFB0 codec sees unsupported data."""

    pass


class CFB0Integer(int):
    """An integer retaining the byte width of its CFB0 number marker."""

    def __new__(cls, value: int, width: int):
        instance = int.__new__(cls, value)
        instance.width = width
        return instance


class CFB0Reader:
    """Small CFB0 reader for ACP request and response dictionaries."""

    def __init__(self, data: bytes):
        self.data = data
        self.pos = 0

    def read(self, count: int) -> bytes:
        if self.pos + count > len(self.data):
            raise CFB0CodecError("truncated CFB0 data")
        out = self.data[self.pos:self.pos + count]
        self.pos += count
        return out

    def read_c_string(self) -> str:
        end = self.data.find(b"\x00", self.pos)
        if end < 0:
            raise CFB0CodecError("unterminated CFB0 string")
        text = self.data[self.pos:end].decode("utf-8", "replace")
        self.pos = end + 1
        return text

    def read_string(self) -> str:
        if self.read(1) != b"p":
            raise CFB0CodecError("expected CFB0 string")
        return self.read_c_string()

    def read_int_payload(self, size: int) -> int:
        return CFB0Integer(int.from_bytes(self.read(size), "big", signed=False), size)

    def read_blob(self) -> bytes:
        marker = self.read(1)[0]
        if marker == 0x10:
            size = self.read_int_payload(1)
        elif marker == 0x11:
            size = self.read_int_payload(2)
        elif marker == 0x12:
            size = self.read_int_payload(4)
        elif marker == 0x13:
            size = self.read_int_payload(8)
        else:
            raise CFB0CodecError(f"unsupported CFB0 blob length marker 0x{marker:02x}")
        return self.read(size)

    def read_array(self) -> list[Any]:
        values: list[Any] = []
        while True:
            if self.pos >= len(self.data):
                raise CFB0CodecError("unterminated CFB0 array")
            if self.data[self.pos] == 0:
                self.pos += 1
                return values
            values.append(self.read_value())

    def read_dict_body(self) -> dict[str, Any]:
        values: dict[str, Any] = {}
        while True:
            if self.pos >= len(self.data):
                raise CFB0CodecError("unterminated CFB0 dictionary")
            if self.data[self.pos] == 0:
                self.pos += 1
                return values
            key = self.read_string()
            values[key] = self.read_value()

    def read_value(self) -> Any:
        marker = self.read(1)[0]
        if marker == 0x08:
            return False
        if marker == 0x09:
            return True
        if marker == 0x10:
            return self.read_int_payload(1)
        if marker == 0x11:
            return self.read_int_payload(2)
        if marker == 0x12:
            return self.read_int_payload(4)
        if marker == 0x13:
            return self.read_int_payload(8)
        if 0x40 <= marker <= 0x4E:
            return self.read(marker & 0x0F)
        if marker == 0x4F:
            return self.read_blob()
        if marker == 0x70:
            return self.read_c_string()
        if marker == 0xA0:
            return self.read_array()
        if marker == 0xD0:
            return self.read_dict_body()
        raise CFB0CodecError(f"unsupported CFB0 value marker 0x{marker:02x}")


def cfb0_loads(data: bytes) -> Any:
    """Decode one complete CFB0 object."""

    if not data.startswith(CFB0_MAGIC):
        raise CFB0CodecError("missing CFB0 magic")
    reader = CFB0Reader(data[4:])
    value = reader.read_value()
    if reader.read(4) != b"END!":
        raise CFB0CodecError("missing CFB0 END trailer")
    if reader.pos != len(reader.data):
        raise CFB0CodecError("trailing data after CFB0 object")
    return value


def cfb0_int(value: int) -> bytes:
    """Encode an unsigned integer using CFB0's compact integer markers."""

    if not 0 <= value <= 0xFFFFFFFFFFFFFFFF:
        raise CFB0CodecError("CFB0 integer is out of range")
    if value <= 0xFF:
        return b"\x10" + value.to_bytes(1, "big")
    if value <= 0xFFFF:
        return b"\x11" + value.to_bytes(2, "big")
    if value <= 0xFFFFFFFF:
        return b"\x12" + value.to_bytes(4, "big")
    return b"\x13" + value.to_bytes(8, "big")


def cfb0_value(value: Any) -> bytes:
    """Encode the CFB0 value types needed for ACP calls."""

    if isinstance(value, bool):
        return b"\x09" if value else b"\x08"
    if isinstance(value, CFB0Integer):
        if value.width not in {1, 2, 4, 8} or not 0 <= value < 1 << (value.width * 8):
            raise CFB0CodecError("CFB0 integer does not fit its retained width")
        marker = {1: 0x10, 2: 0x11, 4: 0x12, 8: 0x13}[value.width]
        return bytes([marker]) + int(value).to_bytes(value.width, "big")
    if isinstance(value, dict):
        out = bytearray(b"\xd0")
        for key, item in value.items():
            if not isinstance(key, str):
                raise CFB0CodecError("CFB0 dictionary keys must be strings")
            out += b"p" + key.encode("utf-8") + b"\x00"
            out += cfb0_value(item)
        out += b"\x00"
        return bytes(out)
    if isinstance(value, (list, tuple)):
        out = bytearray(b"\xa0")
        for item in value:
            out += cfb0_value(item)
        out += b"\x00"
        return bytes(out)
    if isinstance(value, str):
        return b"p" + value.encode("utf-8") + b"\x00"
    if isinstance(value, int):
        return cfb0_int(value)
    if isinstance(value, bytes):
        size = len(value)
        if size < 0x0F:
            return bytes([0x40 | size]) + value
        if size <= 0xFF:
            return b"O\x10" + size.to_bytes(1, "big") + value
        if size <= 0xFFFF:
            return b"O\x11" + size.to_bytes(2, "big") + value
        if size <= 0xFFFFFFFF:
            return b"O\x12" + size.to_bytes(4, "big") + value
        return b"O\x13" + size.to_bytes(8, "big") + value
    raise CFB0CodecError(f"unsupported CFB0 value type {type(value)!r}")


def cfb0_dumps(value: Any) -> bytes:
    """Encode one complete CFB0 object."""

    return CFB0_MAGIC + cfb0_value(value) + b"END!"
