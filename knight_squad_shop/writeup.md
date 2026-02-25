# Writeup — Knight Squad Shop

**Challenge:** Knight Squad Shop  
**Category:** Reverse Engineering  
**Binary:** `knight_squad_shop` (ELF 64-bit, stripped)  
**Flag:** `CCOI26{kn1ght_squ4d_0rd3r_l0ck}`

---

## Description

> Get a valid order.

A stripped 64-bit ELF binary that asks for a 31-character "order" string.

---

## Reconnaissance

```bash
$ file knight_squad_shop
knight_squad_shop: ELF 64-bit LSB pie executable, x86-64, stripped

$ strings knight_squad_shop
Submit your orders.
Orders:
Orders denied.
Orders accepted.
XXLR26{pm1tsg_hj        ← looks like a partial flag, Atbash'd
{"1i-;                  ← XOR'd target bytes for part 2
```

---

## Static Analysis — Disassembly

### Input length check

```asm
call   strlen
cmp    $0x1f,%rax     ; must be exactly 31 characters
```

The input is split in two:
- **Part 1**: `input[0..15]` — 16 bytes
- **Part 2**: `input[16..30]` — 15 bytes

---

### Part 1 — Atbash (SIMD/SSE)

Constants loaded from `.rodata`:

| Register | Value | Role                  |
|----------|-------|-----------------------|
| `xmm1`   | `0x1a`| alphabet span (26)    |
| `xmm2`   | `0xbf`| uppercase threshold   |
| `xmm5`   | `0x9f`| lowercase threshold   |

Transform per byte:
```
x in A-Z  →  (0x9b - x) % 256
x in a-z  →  (0xdb - x) % 256
otherwise →  x
```
This is standard Atbash. Result compared to:
```
target1 = b'XXLR26{pm1tsg_hj'
```
Checksum: sum of transformed bytes must equal `0x5be = 1470`.

---

### Part 2 — XOR with incrementing key

```asm
; initial counter: edx = 0x37
xor    %edx,%esi         ; byte = input[i] ^ counter
add    $0x5,%edx         ; counter += 5
```

Formula: `output[i] = input[16+i] ^ (0x37 + 5*i)` for `i = 0..14`

Result compared to:
```
target2 = [0x42,0x08,0x25,0x19,0x7b,0x22,0x31,0x69,
           0x2d,0x3b,0x05,0x5e,0x10,0x13,0x00]
```

---

## Solution

### Part 1

Atbash is its own inverse — apply it directly to `target1`:

```python
def atbash(b):
    if 65 <= b <= 90:  return 155 - b
    if 97 <= b <= 122: return 219 - b
    return b

part1 = bytes(atbash(b) for b in b'XXLR26{pm1tsg_hj')
# → b'CCOI26{kn1ght_sq'
```

Checksum: `sum(atbash(b) for b in part1) == 1470` ✓

### Part 2

The XOR key is deterministic — XOR target2 with the same key:

```python
part2 = bytes(target2[i] ^ (0x37 + 5*i) for i in range(15))
# → b'u4d_0rd3r_l0ck}'
```

### Combined

```
CCOI26{kn1ght_sq  +  u4d_0rd3r_l0ck}
= CCOI26{kn1ght_squ4d_0rd3r_l0ck}
```

---

## Verification

```bash
$ echo -n "CCOI26{kn1ght_squ4d_0rd3r_l0ck}" | ./knight_squad_shop
Orders accepted.
```

---

## Flag

```
CCOI26{kn1ght_squ4d_0rd3r_l0ck}
```
