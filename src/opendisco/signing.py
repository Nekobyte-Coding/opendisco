"""Checking the Ed25519 signature on a release's SHA256SUMS against OpenDisco's release key.

verify() uses the cryptography package where the app has it (Android, iOS, the AppImage) and
otherwise this module's own check, which follows RFC 8032 section 5.1.7 with the standard library
only (the macOS, Windows, .deb and .rpm apps carry no cryptography). It only verifies: OpenDisco
never signs anything, so no secret goes through this code, and plain Python's speed (a fraction
of a second per signature) is fine.

The public key is resources/release-signing.pub: the raw 32-byte key, base64, on one line.
"""
from __future__ import annotations

import base64
import hashlib
from pathlib import Path

PUBLIC_KEY_FILE = Path(__file__).resolve().parent / "resources" / "release-signing.pub"

_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_SQRT_M1 = pow(2, (_P - 1) // 4, _P)


def public_key(path: Path = PUBLIC_KEY_FILE) -> bytes:
    """OpenDisco's release public key, 32 bytes."""
    raw = base64.b64decode(Path(path).read_text(encoding="ascii").strip(), validate=True)
    if len(raw) != 32:
        raise ValueError("the release public key isn't 32 bytes")
    return raw


def fingerprint(key: bytes) -> str:
    """The key's short name: the first 16 hex digits of its SHA-256."""
    return hashlib.sha256(key).hexdigest()[:16]


def verify(public: bytes, message: bytes, signature: bytes) -> bool:
    """True when signature (64 bytes) is public's Ed25519 signature of message."""
    if len(public) != 32 or len(signature) != 64:
        return False
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    except ImportError:
        return verify_pure(public, message, signature)
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(signature, message)
        return True
    except (InvalidSignature, ValueError):
        return False


# -- RFC 8032, standard library only --------------------------------------------------------
# Points in extended coordinates (X, Y, Z, T), x = X/Z, y = Y/Z, x*y = T/Z.
def _add(p, q):
    a = (p[1] - p[0]) * (q[1] - q[0]) % _P
    b = (p[1] + p[0]) * (q[1] + q[0]) % _P
    c = 2 * p[3] * q[3] * _D % _P
    d = 2 * p[2] * q[2] % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return e * f % _P, g * h % _P, f * g % _P, e * h % _P


def _mul(s: int, p):
    q = (0, 1, 1, 0)  # the neutral point
    while s:
        if s & 1:
            q = _add(q, p)
        p = _add(p, p)
        s >>= 1
    return q


def _equal(p, q) -> bool:
    return (p[0] * q[2] - q[0] * p[2]) % _P == 0 and (p[1] * q[2] - q[1] * p[2]) % _P == 0


def _recover_x(y: int, sign: int):
    if y >= _P:
        return None
    x2 = (y * y - 1) * pow(_D * y * y + 1, _P - 2, _P)
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (_P + 3) // 8, _P)
    if (x * x - x2) % _P:
        x = x * _SQRT_M1 % _P
    if (x * x - x2) % _P:
        return None
    if (x & 1) != sign:
        x = _P - x
    return x


def _decompress(s: bytes):
    y = int.from_bytes(s, "little")
    sign, y = y >> 255, y & ((1 << 255) - 1)
    x = _recover_x(y, sign)
    return None if x is None else (x, y, 1, x * y % _P)


_G = _decompress(bytes.fromhex("5866666666666666666666666666666666666666666666666666666666666666"))


def verify_pure(public: bytes, message: bytes, signature: bytes) -> bool:
    if len(public) != 32 or len(signature) != 64:
        return False
    a = _decompress(public)
    r = _decompress(signature[:32])
    if a is None or r is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= _L:
        return False
    h = int.from_bytes(hashlib.sha512(signature[:32] + public + message).digest(), "little") % _L
    return _equal(_mul(s, _G), _add(r, _mul(h, a)))
