"""Pure-Python Ed25519 (RFC 8032), vendored — no runtime dependencies.

Used to sign audit-log chain tips. Straightforward port of the
reference algorithm; correctness is pinned by fixed cross-check
vectors generated with libsodium (an independent implementation)
in tests/test_ed25519.py — key derivation, deterministic
signatures, and verification all match byte-for-byte.

Not constant-time: signatures are made over public audit data on
the host, and the threat model here is tamper-evidence (detecting
modification), not side-channel resistance of the signing key.
The signing key file itself is protected by 0600 permissions and
a fail-closed permission check at load time.
"""

from __future__ import annotations

import hashlib

# ---------------------------------------------------------------------------
# Field arithmetic over GF(2**255 - 19)
# ---------------------------------------------------------------------------

Q = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
# d = -121665 * inv(121666) mod Q
D = (-121665 * pow(121666, Q - 2, Q)) % Q
# sqrt(-1) mod Q, used to recover x from y
SQRT_M1 = pow(2, (Q - 1) // 4, Q)


def _inv(x: int) -> int:
    return pow(x, Q - 2, Q)


def _x_from_y(y: int) -> int | None:
    """Recover x from y on the curve; None if y is not on the curve."""
    y2 = (y * y) % Q
    num = (y2 - 1) % Q
    den = (D * y2 + 1) % Q
    x2 = (num * _inv(den)) % Q
    x = pow(x2, (Q + 3) // 8, Q)
    if (x * x - x2) % Q != 0:
        x = (x * SQRT_M1) % Q
    if (x * x - x2) % Q != 0:
        return None
    # RFC 8032: take the even x (negative of the odd one)
    if x & 1:
        x = Q - x
    return x


def _encode_point(x: int, y: int) -> bytes:
    bits = y & (2**255 - 1)
    if x & 1:
        bits |= 1 << 255
    return bits.to_bytes(32, "little")


def _decode_point(data: bytes) -> tuple[int, int] | None:
    """Decode a 32-byte encoded point; None when invalid."""
    if len(data) != 32:
        return None
    bits = int.from_bytes(data, "little")
    y = bits & (2**255 - 1)
    x_odd = (bits >> 255) & 1
    x = _x_from_y(y)
    if x is None:
        return None
    if (x & 1) != x_odd:
        x = Q - x
    return x, y


def _point_add(
    p: tuple[int, int] | None, q: tuple[int, int] | None
) -> tuple[int, int] | None:
    """Twisted-Edwards addition; None is the identity element."""
    if p is None:
        return q
    if q is None:
        return p
    x1, y1 = p
    x2, y2 = q
    # Twisted Edwards with a = -1: y3 = (y1*y2 + x1*x2) / (1 - d*x1*x2*y1*y2).
    x = (x1 * y2 + x2 * y1) % Q
    y = (y1 * y2 + x1 * x2) % Q
    den_x = (1 + D * x1 * x2 * y1 * y2) % Q
    den_y = (1 - D * x1 * x2 * y1 * y2) % Q
    return (x * _inv(den_x)) % Q, (y * _inv(den_y)) % Q


def _point_mul(scalar: int, point: tuple[int, int] | None) -> (
    tuple[int, int] | None
):
    result: tuple[int, int] | None = None
    addend = point
    n = scalar % L
    while n:
        if n & 1:
            result = _point_add(result, addend)
        addend = _point_add(addend, addend)
        n >>= 1
    return result


# Base point: y = 4/5, x even per RFC 8032.
_BASE_Y = (4 * _inv(5)) % Q
_BASE_X = _x_from_y(_BASE_Y)
assert _BASE_X is not None
BASE: tuple[int, int] = (_BASE_X, _BASE_Y)


def _clamp(scalar: bytes) -> int:
    """Clamp the lower half of SHA-512(seed) per RFC 8032."""
    assert len(scalar) == 32
    a = bytearray(scalar)
    a[0] &= 248
    a[31] &= 63
    a[31] |= 64
    return int.from_bytes(bytes(a), "little")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def public_key_from_seed(seed: bytes) -> bytes:
    """Derive the 32-byte Ed25519 public key from a 32-byte seed."""
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be 32 bytes")
    digest = hashlib.sha512(seed).digest()
    a = _clamp(digest[:32])
    point = _point_mul(a, BASE)
    assert point is not None
    return _encode_point(*point)


def sign(seed: bytes, message: bytes) -> bytes:
    """Sign a message; returns the 64-byte signature."""
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be 32 bytes")
    digest = hashlib.sha512(seed).digest()
    a = _clamp(digest[:32])
    prefix = digest[32:]
    r = int.from_bytes(
        hashlib.sha512(prefix + message).digest(), "little"
    ) % L
    r_point = _point_mul(r, BASE)
    assert r_point is not None
    r_enc = _encode_point(*r_point)
    pub = public_key_from_seed(seed)
    h = int.from_bytes(
        hashlib.sha512(r_enc + pub + message).digest(), "little"
    ) % L
    s = (r + h * a) % L
    return r_enc + s.to_bytes(32, "little")


def verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    """Verify a signature; False on any malformed input or mismatch."""
    if len(public_key) != 32 or len(signature) != 64:
        return False
    a_point = _decode_point(public_key)
    if a_point is None:
        return False
    r_enc, s_enc = signature[:32], signature[32:]
    # RFC 8032: reject non-canonical S (>= L) and low-order R.
    if int.from_bytes(s_enc, "little") >= L:
        return False
    r_point = _decode_point(r_enc)
    if r_point is None:
        return False
    # Reject small-order R (prevents signature malleability tricks).
    if _point_mul(L, r_point) is not None:
        return False
    h = int.from_bytes(
        hashlib.sha512(r_enc + public_key + message).digest(), "little"
    ) % L
    s = int.from_bytes(s_enc, "little")
    left = _point_mul(s, BASE)
    ha = _point_mul(h, a_point)
    right = _point_add(r_point, ha)
    if left is None or right is None:
        return False
    return _encode_point(*left) == _encode_point(*right)
