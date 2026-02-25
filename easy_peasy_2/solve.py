#!/usr/bin/env python3
"""
Solver — Easy Peasy 2
Flag: CCOI26{_3asy_p3asy_2_4ll_3asy_p3asy_}

Encryption (enc_original.py) applies two operations in order:
  1. Atbash substitution  (A↔Z, a↔z — involution)
  2. Block-reversal of 4-byte blocks  (also an involution)

Since both operations are involutions, decryption = applying them in reverse order:
  1. Undo block-reversal  → reverse each 4-byte block
  2. Undo Atbash          → apply Atbash again
"""

from pathlib import Path


BLOCK = 4


def atbash(b: int) -> int:
    if 65 <= b <= 90:   return 90  - (b - 65)   # A-Z ↔ Z-A
    if 97 <= b <= 122:  return 122 - (b - 97)    # a-z ↔ z-a
    return b


def solve(path: str = "challenge_ep2.bin") -> str:
    enc = bytearray(Path(path).read_bytes())

    # Step 1: undo block-reversal
    tmp = bytearray()
    for i in range(0, len(enc), BLOCK):
        tmp.extend(enc[i:i + BLOCK][::-1])

    # Step 2: undo Atbash
    flag = bytearray(atbash(b) for b in tmp)

    return flag.decode()


if __name__ == "__main__":
    print(solve())
    # Expected: CCOI26{_3asy_p3asy_2_4ll_3asy_p3asy_}
