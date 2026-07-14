"""Small deterministic fallback for Garaga's two fastecdsa calls.

The pinned Garaga release only uses ``curvemath.add`` and ``curvemath.mul``
while constructing off-chain MSM hints. Windows has no matching fastecdsa wheel
for this historical release, so this module supplies the same affine group
operations without introducing an unpinned native library. Cairo verifies every
resulting hint; this code is not part of the trust boundary.
"""


def _add_points(p1, p2, modulus, a):
    if p1 == (0, 0):
        return p2
    if p2 == (0, 0):
        return p1
    x1, y1 = p1
    x2, y2 = p2
    if x1 == x2 and (y1 + y2) % modulus == 0:
        return (0, 0)
    if p1 == p2:
        slope = (3 * x1 * x1 + a) * pow(2 * y1, -1, modulus) % modulus
    else:
        slope = (y2 - y1) * pow((x2 - x1) % modulus, -1, modulus) % modulus
    x3 = (slope * slope - x1 - x2) % modulus
    y3 = (slope * (x1 - x3) - y1) % modulus
    return (x3, y3)


def add(x1, y1, x2, y2, modulus, a, _b, _order, _gx, _gy):
    return _add_points(
        (int(x1), int(y1)), (int(x2), int(y2)), int(modulus), int(a)
    )


def mul(x, y, scalar, modulus, a, _b, _order, _gx, _gy):
    modulus = int(modulus)
    a = int(a)
    scalar = int(scalar)
    addend = (int(x), int(y))
    result = (0, 0)
    while scalar:
        if scalar & 1:
            result = _add_points(result, addend, modulus, a)
        addend = _add_points(addend, addend, modulus, a)
        scalar >>= 1
    return result
