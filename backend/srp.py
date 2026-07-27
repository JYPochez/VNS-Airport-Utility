from __future__ import annotations

import hashlib
import os
import struct
from dataclasses import dataclass
from typing import Any

from backend.acp import ACPPlainTransport
from backend.acp import ACP_REQUEST_SALT
from backend.acp import ACP_RESPONSE_SALT
from backend.cfb0 import cfb0_dumps
from backend.cfb0 import cfb0_loads


@dataclass
class SRPValues:
    """Values computed from the live AppleSRP-compatible challenge."""

    public_key: bytes
    client_proof: bytes
    session_key: bytes


@dataclass
class AuthResult:
    """Material needed to switch from cleartext SRP to encrypted ACP."""

    session_key: bytes
    request_iv: bytes
    response_iv: bytes


def sha1(data: bytes) -> bytes:
    """Return SHA-1 digest bytes."""

    return hashlib.sha1(data).digest()


def xor_bytes(left: bytes, right: bytes) -> bytes:
    """XOR equal-length byte strings."""

    if len(left) != len(right):
        raise ValueError("cannot XOR byte strings with different lengths")
    return bytes(a ^ b for a, b in zip(left, right))


def int_from_bytes(data: bytes) -> int:
    """Decode a big-endian integer."""

    return int.from_bytes(data, "big")


def int_to_bytes(value: int) -> bytes:
    """Encode a non-negative integer like AppleSRP's BigIntegerToCstr."""

    if value < 0:
        raise ValueError("negative SRP integer")
    if value == 0:
        return b"\x00"
    return value.to_bytes((value.bit_length() + 7) // 8, "big")


def int_to_padded_bytes(value: int, length: int) -> bytes:
    """Encode a big-endian integer padded to ``length`` bytes."""

    data = int_to_bytes(value)
    if len(data) > length:
        raise ValueError("SRP integer is longer than the modulus")
    return data.rjust(length, b"\x00")


def mgf1_sha1(seed: bytes, length: int) -> bytes:
    """AppleSRP SRP-6a session-key expansion: MGF1-SHA1(seed, length)."""

    out = bytearray()
    counter = 0
    while len(out) < length:
        out += sha1(seed + struct.pack(">I", counter))
        counter += 1
    return bytes(out[:length])


def applesrp_client_proof(username: str, password: str, challenge: dict[str, Any]) -> SRPValues:
    """Compute the AppleSRP-compatible SRP-6a response for a challenge."""

    generator = challenge["generator"]
    if isinstance(generator, int):
        generator_bytes = bytes([generator])
    elif isinstance(generator, bytes):
        generator_bytes = generator
    else:
        raise RuntimeError("SRP generator has an unexpected type")

    modulus = challenge["modulus"]
    salt = challenge["salt"]
    server_public = challenge["publicKey"]
    if (
        not isinstance(modulus, bytes)
        or not isinstance(salt, bytes)
        or not isinstance(server_public, bytes)
    ):
        raise RuntimeError("SRP challenge fields have unexpected types")

    n = int_from_bytes(modulus)
    g = int_from_bytes(generator_bytes)
    b_pub = int_from_bytes(server_public)
    if n <= 0 or g <= 0:
        raise RuntimeError("SRP challenge contains invalid modulus or generator")
    if b_pub <= 0 or b_pub >= n:
        raise RuntimeError("SRP server public key is out of range")

    n_len = (n.bit_length() + 7) // 8
    n_bytes = int_to_bytes(n)
    g_bytes = int_to_bytes(g)
    b_bytes = int_to_padded_bytes(b_pub, n_len)

    username_bytes = username.encode("utf-8")
    password_bytes = password.encode("utf-8")
    identity_hash = sha1(username_bytes + b":" + password_bytes)
    x = int_from_bytes(sha1(salt + identity_hash))
    verifier = pow(g, x, n)

    a = int_from_bytes(os.urandom(n_len)) + n.bit_length()
    a_pub = pow(g, a, n)
    if a_pub <= 0:
        raise RuntimeError("SRP client public key is invalid")
    a_bytes = int_to_bytes(a_pub)
    a_padded = int_to_padded_bytes(a_pub, n_len)

    multiplier = int_from_bytes(sha1(n_bytes + g_bytes.rjust(n_len, b"\x00")))
    if multiplier == 0:
        raise RuntimeError("SRP multiplier is zero")
    scrambling = int_from_bytes(sha1(a_padded + b_bytes))
    if scrambling == 0:
        raise RuntimeError("SRP scrambling parameter is zero")

    base = (b_pub - multiplier * verifier) % n
    exponent = a + scrambling * x
    shared_secret = pow(base, exponent, n)
    session_key = mgf1_sha1(int_to_bytes(shared_secret), 40)

    client_proof = sha1(
        xor_bytes(sha1(modulus), sha1(generator_bytes))
        + sha1(username_bytes)
        + salt
        + a_bytes
        + b_bytes
        + session_key
    )
    return SRPValues(
        public_key=a_bytes.rjust(len(modulus), b"\x00"),
        client_proof=client_proof,
        session_key=session_key,
    )


def authenticate(transport: ACPPlainTransport, password: str) -> AuthResult:
    """Perform the two-message SRP authentication exchange."""

    username = "admin"
    transport.send(cfb0_dumps({"state": 1, "username": username}))
    header, body = transport.recv()
    if header.status or not body:
        raise RuntimeError(f"SRP challenge failed with ACP status {header.status}")
    challenge = cfb0_loads(body)
    for key in ("salt", "generator", "publicKey", "modulus"):
        if key not in challenge:
            raise RuntimeError(f"SRP challenge missing {key}")

    srp = applesrp_client_proof(username, password, challenge)
    request_iv = os.urandom(16)
    transport.send(
        cfb0_dumps(
            {
                "iv": request_iv,
                "publicKey": srp.public_key,
                "state": 3,
                "response": srp.client_proof,
            }
        )
    )

    header, body = transport.recv()
    if header.status or not body:
        raise RuntimeError(f"SRP proof failed with ACP status {header.status}")
    final = cfb0_loads(body)
    response_iv = final.get("iv")
    if not isinstance(response_iv, bytes) or len(response_iv) != 16:
        raise RuntimeError("SRP final response did not include a 16-byte IV")
    return AuthResult(srp.session_key, request_iv, response_iv)


def derive_keys(session_key: bytes) -> tuple[bytes, bytes]:
    """Derive the post-auth request and response AES keys."""

    request_key = hashlib.pbkdf2_hmac("sha1", session_key, ACP_REQUEST_SALT, 5, 16)
    response_key = hashlib.pbkdf2_hmac("sha1", session_key, ACP_RESPONSE_SALT, 7, 16)
    return request_key, response_key
