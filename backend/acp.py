from __future__ import annotations

import ctypes
import ctypes.util
import socket
import struct
from dataclasses import dataclass
from typing import Callable


# AirPort Configuration Protocol listens on TCP/5009.
ACP_PORT = 5009

# Every ACP message begins with a fixed 128-byte header. The message body,
# if present, follows immediately after the header.
ACP_HEADER_LEN = 128
ACP_MAGIC = b"acpp"

# A body size of 0xffffffff means "streaming" response. For property reads,
# the base station then sends one encrypted 12-byte property record followed
# by that record's encrypted value bytes.
ACP_STREAM_SIZE = 0xFFFFFFFF

# This is the largest body size the AirPort Utility code accepts in related
# paths. Keeping the guard makes accidental bad decrypts fail quickly.
ACP_MAX_BODY_SIZE = 0x180000

# ACP property records are:
#   4 bytes: property name, for example b"sySN"
#   4 bytes: flags
#   4 bytes: value size in bytes
ACP_PROPERTY_HEADER = struct.Struct("!4s2I")

# This is the 32-byte client token observed in AirPort Utility's ACP headers.
# The base station accepts it for the authentication and property read flow.
DEFAULT_CLIENT_TOKEN = bytes.fromhex(
    "0e39f805c401554f0cac857d868ab5173e09c835f431657f3c9cb56d969aa507"
)

# After SRP succeeds, AirPort Utility derives two independent AES keys from
# the raw 40-byte SRP session key with PBKDF2-HMAC-SHA1:
#   request key:  salt below, 5 rounds
#   response key: salt below, 7 rounds
ACP_REQUEST_SALT = bytes.fromhex("f072fa3f66b410a135fae8e6d1d43d5f")
ACP_RESPONSE_SALT = bytes.fromhex("bd0682c9fe79325bc73655f4174b996c")


@dataclass
class ACPHeader:
    """Decoded fields from the 128-byte ACP header."""

    body_size: int
    flags: int
    command: int
    status: int


def acp_adler32(data: bytes, initial: int = 1) -> int:
    """Compute ACP's Adler-style checksum."""

    s1 = initial & 0xFFFF
    s2 = (initial >> 16) & 0xFFFF
    for offset in range(0, len(data), 0x1388):
        # 0x1388 is the chunk size used by AirPort Utility's implementation.
        # Reducing modulo after each chunk keeps sums bounded while matching
        # the observed checksum values.
        for byte in data[offset:offset + 0x1388]:
            s1 += byte
            s2 += s1
        s1 %= 0xFFF1
        s2 %= 0xFFF1
    return (s2 << 16) | s1


def make_header(
    body: bytes,
    flags: int,
    command: int,
    client_token: bytes = DEFAULT_CLIENT_TOKEN,
    body_size: int | None = None,
) -> bytes:
    """Build an ACP header for ``body``."""

    header = bytearray(ACP_HEADER_LEN)
    header[0:4] = ACP_MAGIC
    header[4:8] = b"\x00\x03\x00\x01"
    # Offsets below come from AirPort Utility behavior:
    #   16: body size
    #   20: flags (4/5 during auth, usually 0 for property reads)
    #   28: command selector (0x1a auth, 0x14 property request)
    #   48: client token
    header[16:20] = struct.pack(">I", len(body) if body_size is None else body_size)
    header[20:24] = struct.pack(">I", flags)
    header[28:32] = struct.pack(">I", command)
    if len(client_token) != 32:
        raise ValueError("ACP client token must be exactly 32 bytes")
    header[48:80] = client_token
    # The body checksum is part of the header checksum, so write it first.
    header[12:16] = struct.pack(">I", acp_adler32(body))
    header[8:12] = struct.pack(">I", acp_adler32(header))
    return bytes(header)


def parse_header(data: bytes) -> ACPHeader:
    """Validate and decode one 128-byte ACP header."""

    if len(data) != ACP_HEADER_LEN:
        raise ValueError("ACP header must be 128 bytes")
    if data[:4] != ACP_MAGIC:
        raise ValueError(f"bad ACP magic: {data[:4]!r}")
    return ACPHeader(
        body_size=struct.unpack(">I", data[16:20])[0],
        flags=struct.unpack(">I", data[20:24])[0],
        command=struct.unpack(">I", data[28:32])[0],
        status=struct.unpack(">i", data[32:36])[0],
    )


class CommonCryptoAES:
    """Small wrapper around CommonCrypto AES-ECB block encryption."""

    def __init__(self):
        lib_path = ctypes.util.find_library("System") or "/usr/lib/libSystem.B.dylib"
        self.lib = ctypes.CDLL(lib_path)
        self.lib.CCCrypt.argtypes = [
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_uint32,
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_void_p,
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.c_void_p,
            ctypes.c_size_t,
            ctypes.POINTER(ctypes.c_size_t),
        ]
        self.lib.CCCrypt.restype = ctypes.c_int

    def encrypt_block(self, key: bytes, block: bytes) -> bytes:
        """Encrypt exactly one 16-byte block with a 16-byte AES key."""

        if len(key) != 16 or len(block) != 16:
            raise ValueError("AES key and block must both be 16 bytes")
        inbuf = ctypes.create_string_buffer(block)
        outbuf = ctypes.create_string_buffer(16)
        moved = ctypes.c_size_t()
        status = self.lib.CCCrypt(
            0,  # kCCEncrypt
            0,  # kCCAlgorithmAES
            2,  # kCCOptionECBMode, deliberately no padding option.
            key,
            len(key),
            None,  # IV is ignored for ECB mode.
            inbuf,
            len(block),
            outbuf,
            len(outbuf),
            ctypes.byref(moved),
        )
        if status != 0 or moved.value != 16:
            raise RuntimeError(f"CCCrypt failed: status={status} moved={moved.value}")
        return outbuf.raw


class ACPStreamCipher:
    """Stateful AES-counter stream used for encrypted ACP."""

    def __init__(self, key: bytes, iv: bytes):
        if len(key) != 16:
            raise ValueError("ACP AES keys must be 16 bytes")
        if len(iv) != 16:
            raise ValueError("ACP AES IVs must be 16 bytes")
        self.aes = CommonCryptoAES()
        self.key = key
        self.counter = bytearray(iv)
        self.stream = b""
        self.stream_offset = 0

    def crypt(self, data: bytes) -> bytes:
        """Encrypt or decrypt ``data``."""

        out = bytearray()
        offset = 0
        while offset < len(data):
            if self.stream_offset == 0:
                self.stream = self.aes.encrypt_block(self.key, bytes(self.counter))
                self.increment_counter()
            count = min(len(data) - offset, 16 - self.stream_offset)
            for index in range(count):
                out.append(data[offset + index] ^ self.stream[self.stream_offset + index])
            offset += count
            self.stream_offset = (self.stream_offset + count) & 0xF
        return bytes(out)

    def increment_counter(self) -> None:
        """Increment the 16-byte counter as a big-endian integer."""

        for index in range(15, -1, -1):
            self.counter[index] = (self.counter[index] + 1) & 0xFF
            if self.counter[index] != 0:
                break


def recvn(sock: socket.socket, count: int) -> bytes:
    """Receive exactly ``count`` bytes or raise if the socket closes."""

    chunks = []
    remaining = count
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise EOFError("connection closed")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


class ACPPlainTransport:
    """Cleartext ACP transport used only during SRP authentication."""

    def __init__(self, sock: socket.socket):
        self.sock = sock

    def send(self, body: bytes, flags: int = 4, command: int = 0x1A) -> None:
        """Send one cleartext ACP message."""

        self.sock.sendall(make_header(body, flags, command) + body)

    def recv(self) -> tuple[ACPHeader, bytes]:
        """Receive one cleartext ACP message."""

        header = parse_header(recvn(self.sock, ACP_HEADER_LEN))
        if header.body_size == ACP_STREAM_SIZE:
            return header, b""
        if header.body_size > ACP_MAX_BODY_SIZE:
            raise RuntimeError(f"implausible ACP body size {header.body_size}")
        return header, recvn(self.sock, header.body_size)


class ACPEncryptedTransport:
    """Encrypted ACP transport used after SRP authentication succeeds."""

    def __init__(
        self,
        sock: socket.socket,
        request_key: bytes,
        response_key: bytes,
        request_iv: bytes,
        response_iv: bytes,
        client_token: bytes = DEFAULT_CLIENT_TOKEN,
        align_calls: bool = False,
    ):
        self.sock = sock
        self.request_cipher = ACPStreamCipher(request_key, request_iv)
        self.response_cipher = ACPStreamCipher(response_key, response_iv)
        self.client_token = client_token
        self.align_calls = align_calls

    def _crypt(self, cipher: ACPStreamCipher, data: bytes) -> bytes:
        encrypted = cipher.crypt(data)
        if self.align_calls:
            # Legacy ACP17 advances to the next counter block at each protocol
            # call, even when the current block was only partially consumed.
            cipher.stream_offset = 0
        return encrypted

    def send(self, body: bytes, flags: int, command: int) -> None:
        """Send one encrypted ACP message."""

        header = make_header(body, flags, command, self.client_token)
        self.sock.sendall(
            self._crypt(self.request_cipher, header)
            + self._crypt(self.request_cipher, body)
        )

    def send_stream_header(self, flags: int, command: int) -> None:
        """Start an encrypted ACP streaming request with no immediate body."""

        header = make_header(
            b"",
            flags,
            command,
            self.client_token,
            body_size=ACP_STREAM_SIZE,
        )
        self.sock.sendall(self._crypt(self.request_cipher, header))

    def send_encrypted_stream(
        self,
        data: bytes,
        progress_callback: Callable[[int, int], None] | None = None,
        progress_chunk_size: int = 64 * 1024,
    ) -> None:
        """Send bytes that belong to an already-open encrypted stream."""

        if progress_callback is None or len(data) <= progress_chunk_size:
            self.sock.sendall(self._crypt(self.request_cipher, data))
            if progress_callback is not None:
                progress_callback(len(data), len(data))
            return

        sent = 0
        while sent < len(data):
            chunk = data[sent:sent + progress_chunk_size]
            self.sock.sendall(self._crypt(self.request_cipher, chunk))
            sent += len(chunk)
            progress_callback(sent, len(data))

    def recv(self) -> tuple[ACPHeader, bytes]:
        """Receive one encrypted ACP message."""

        header = parse_header(self._crypt(self.response_cipher, recvn(self.sock, ACP_HEADER_LEN)))
        if header.body_size == ACP_STREAM_SIZE:
            return header, b""
        if header.body_size > ACP_MAX_BODY_SIZE:
            raise RuntimeError(f"implausible ACP body size {header.body_size}")
        return header, self._crypt(self.response_cipher, recvn(self.sock, header.body_size))

    def recv_decrypted(self, count: int) -> bytes:
        """Read and decrypt ``count`` bytes from a streaming response."""

        return self._crypt(self.response_cipher, recvn(self.sock, count))


def connect_acp(host: str, timeout: float = 8.0) -> socket.socket:
    """Connect to ACP on ``host``."""

    scope_id = 0
    lookup_host = host
    if ":" in host and "%" in host:
        lookup_host, scope_name = host.rsplit("%", 1)
        scope_id = socket.if_nametoindex(scope_name)

    last_error: OSError | None = None
    for family, socktype, proto, _canon, sockaddr in socket.getaddrinfo(
        lookup_host, ACP_PORT, socket.AF_UNSPEC, socket.SOCK_STREAM
    ):
        sock = socket.socket(family, socktype, proto)
        try:
            sock.settimeout(timeout)
            if family == socket.AF_INET:
                sock.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, 255)
            elif family == socket.AF_INET6:
                sock.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_UNICAST_HOPS, 255)
                if scope_id:
                    addr, port, flowinfo, _old_scope = sockaddr
                    sockaddr = (addr, port, flowinfo, scope_id)
            sock.connect(sockaddr)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            return sock
        except OSError as exc:
            last_error = exc
            sock.close()
    raise OSError(f"could not connect to {host}:{ACP_PORT}: {last_error}")
