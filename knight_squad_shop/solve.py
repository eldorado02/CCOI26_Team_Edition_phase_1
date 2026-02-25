#!/usr/bin/env python3
"""
Solver — Knight Squad Shop
Flag: CCOI26{kn1ght_squ4d_0rd3r_l0ck}

The binary checks a 31-character order string split into two parts:

  Part 1 — bytes 0..15 — Atbash (SIMD)
    Compared to target1 = b'XXLR26{pm1tsg_hj'
    Checksum constraint: sum of transformed bytes == 0x5be (1470)

  Part 2 — bytes 16..30 — XOR with incrementing key
    output[i] = input[16+i] ^ (0x37 + 5*i)
    Compared to target2 = bytes([0x42,0x08,0x25,0x19,0x7b,
                                  0x22,0x31,0x69,0x2d,0x3b,
                                  0x05,0x5e,0x10,0x13,0x00])
"""

TARGET1 = b'XXLR26{pm1tsg_hj'
TARGET2 = bytes([0x42, 0x08, 0x25, 0x19, 0x7b,
                 0x22, 0x31, 0x69, 0x2d, 0x3b,
                 0x05, 0x5e, 0x10, 0x13, 0x00])


def atbash(b: int) -> int:
    if 65  <= b <= 90:  return 155 - b   # 90-(b-65) = 155-b
    if 97  <= b <= 122: return 219 - b   # 122-(b-97) = 219-b
    return b


def solve() -> str:
    # Part 1: Atbash is its own inverse
    part1 = bytes(atbash(b) for b in TARGET1)

    # Part 2: XOR with key (0x37, 0x3c, 0x41, …) — one-time-pad, just XOR again
    part2 = bytes(TARGET2[i] ^ (0x37 + 5 * i) for i in range(15))

    return (part1 + part2).decode()


if __name__ == "__main__":
    print(solve())
    # Expected: CCOI26{kn1ght_squ4d_0rd3r_l0ck}
