# Writeup — Midnight Registry

**Challenge:** Midnight Registry  
**Category:** Reverse Engineering  
**Binary:** `midnight_registry` (ELF 64-bit, stripped)  
**Flag:** `CCOI26{m1dn1ght_r3g1stry_k33p3r}`

---

## Description

> Reverse it to get your flag.

A stripped 64-bit ELF binary that asks for an "access token". The goal is to recover the valid token.

---

## Reconnaissance

```bash
$ file midnight_registry
midnight_registry: ELF 64-bit LSB pie executable, x86-64, dynamically linked, stripped

$ strings midnight_registry
Validate your access token.
Input:
Access denied.
Access granted.
!lh3599
ZZZZZZZZZZZZZZZZ
```

The string `!lh3599` and `ZZZZZZ...` hint at constants used in the transformation.

---

## Static Analysis — Disassembly

### 1. Input length check

```asm
call   strlen
cmp    $0x20,%rax    ; must be exactly 32 characters
```

### 2. String reversal

The input is copied byte-by-byte in reverse order into `rsp+0x120`.

### 3. Per-byte SIMD transform (SSE)

Constants loaded from `.rodata`:

| Register | Value × 16 | Role               |
|----------|------------|--------------------|
| `xmm8`   | `0x9f`     | lowercase detection |
| `xmm6`   | `0xbf`     | uppercase detection |
| `xmm7`   | `0xe0`     | lowercase add       |
| `xmm5`   | `0x20`     | uppercase add       |
| `xmm4`   | `0x5a`     | final XOR mask      |

Decoded transform per byte `x`:

```
x in a-z  →  ((x + 0xe0) % 256) ^ 0x5a
x in A-Z  →  ((x + 0x20) % 256) ^ 0x5a
otherwise →  x ^ 0x5a
```

### 4. Comparison with target

Result compared byte-by-byte with targets from `.rodata`:

```
0x2090: 27 08 69 0a 69 69 11 05 03 08 0e 09 6b 1d 69 08
0x20a0: 05 0e 12 1d 6b 14 1e 6b 17 21 6c 68 33 35 39 39
```

---

## Solution

Both steps (reversal + transform) are easily inverted:

### Invert the per-byte transform

```python
def f_inv(t):
    x = t ^ 0x5a
    if not (0x41 <= x <= 0x5a) and not (0x61 <= x <= 0x7a):
        return x                              # not a letter
    x = ((t ^ 0x5a) + 0xe0) % 256
    if 0x41 <= x <= 0x5a: return x           # was uppercase
    x = ((t ^ 0x5a) + 0x20) % 256
    if 0x61 <= x <= 0x7a: return x           # was lowercase
```

### Invert the reversal

```python
reversed_input = bytes(f_inv(t) for t in TARGET)
token = reversed_input[::-1]
# → b'CCOI26{m1dn1ght_r3g1stry_k33p3r}'
```

---

## Verification

```bash
$ echo -n "CCOI26{m1dn1ght_r3g1stry_k33p3r}" | ./midnight_registry
Access granted.
```

---

## Flag

```
CCOI26{m1dn1ght_r3g1stry_k33p3r}
```
