#!/usr/bin/env python3

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
