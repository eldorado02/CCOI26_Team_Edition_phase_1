"""
Solver — Midnight Registry
Flag: CCOI26{m1dn1ght_r3g1stry_k33p3r}

Algorithm recovered from disassembly:
  1. Input must be exactly 32 printable characters.
  2. Input is reversed in memory.
  3. Per-byte transform (SIMD/SSE, decoded):
       x in a-z  →  ((x + 0xe0) % 256) ^ 0x5a
       x in A-Z  →  ((x + 0x20) % 256) ^ 0x5a
       otherwise →  x ^ 0x5a
  4. Result compared with two 16-byte targets from .rodata.
"""

TARGET = bytes([
    0x27, 0x08, 0x69, 0x0a, 0x69, 0x69, 0x11, 0x05,
    0x03, 0x08, 0x0e, 0x09, 0x6b, 0x1d, 0x69, 0x08,
    0x05, 0x0e, 0x12, 0x1d, 0x6b, 0x14, 0x1e, 0x6b,
    0x17, 0x21, 0x6c, 0x68, 0x33, 0x35, 0x39, 0x39,
])


def f_inv(t: int) -> int:
    """Invert the per-byte transform for target byte t."""
    x = t ^ 0x5a
    if not (0x41 <= x <= 0x5a) and not (0x61 <= x <= 0x7a):
        return x

    x = ((t ^ 0x5a) + 0xe0) % 256
    if 0x41 <= x <= 0x5a:
        return x

    x = ((t ^ 0x5a) + 0x20) % 256
    if 0x61 <= x <= 0x7a:
        return x

    raise ValueError(f"No inverse found for target byte 0x{t:02x}")


def solve() -> str:
    reversed_input = bytes(f_inv(t) for t in TARGET)

    token = reversed_input[::-1]

    return token.decode()


if __name__ == "__main__":
    flag = solve()
    print(flag)
