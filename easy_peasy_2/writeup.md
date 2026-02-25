# Writeup — Easy Peasy 2

**Challenge:** Easy Peasy 2  
**Category:** Cryptography  
**Files:** `challenge_ep2.bin`, `enc_original.py`  
**Flag:** `CCOI26{_3asy_p3asy_2_4ll_3asy_p3asy_}`

---

## Description

> Decrypt the file and find the flag.

We are given an encrypted binary file and the Python script that produced it.

---

## Encryption Script Analysis

```python
FLAG = b"REDACTED"
BLOCK = 4

# Step 1: Atbash substitution
tmp = bytearray()
for b in FLAG:
    if 65 <= b <= 90:          # A-Z → Z-A
        tmp.append(90 - (b - 65))
    elif 97 <= b <= 122:       # a-z → z-a
        tmp.append(122 - (b - 97))
    else:
        tmp.append(b)

# Step 2: reverse each 4-byte block
enc = bytearray()
for i in range(0, len(tmp), BLOCK):
    enc.extend(tmp[i:i + BLOCK][::-1])
```

Two successive operations:

1. **Atbash** — substitution cipher inverting the alphabet (`A↔Z`, `a↔z`, …).  
   This is an **involution**: applying it twice returns the original.

2. **Block-reversal** — each 4-byte block is reversed.  
   Also an **involution**.

---

## Ciphertext

```
$ xxd challenge_ep2.bin
00000000: 524c 5858 5f7b 3632 6268 7a33 7a33 6b5f  RLXX_{62bhz3z3k_
00000010: 325f 6268 6f6f 345f 687a 335f 336b 5f62  2_bhoo4_hz3_3k_b
00000020: 5f62 687a 7d                             _bhz}
```

45 bytes total.

---

## Decryption

Since both operations are involutions, decryption simply applies them **in reverse order**:

1. Undo block-reversal → reverse each 4-byte block
2. Undo Atbash → apply Atbash again

```python
enc = bytearray(Path('challenge_ep2.bin').read_bytes())

# Step 1: undo block-reversal
tmp = bytearray()
for i in range(0, len(enc), 4):
    tmp.extend(enc[i:i+4][::-1])

# Step 2: undo Atbash
flag = bytearray()
for b in tmp:
    if 65 <= b <= 90:   flag.append(90  - (b - 65))
    elif 97 <= b <= 122: flag.append(122 - (b - 97))
    else:                flag.append(b)
```

### Manual trace (first two 4-byte blocks)

| Ciphertext  | After block-reversal | After Atbash |
|-------------|----------------------|--------------|
| `R L X X`   | `X X L R`            | `C C O I`    |
| `_ { 6 2`   | `2 6 { _`            | `2 6 { _`    |
| `b h z 3`   | `3 z h b`            | `3 a s y`    |

---

## Result

```bash
$ python3 solve.py
CCOI26{_3asy_p3asy_2_4ll_3asy_p3asy_}
```

---

## Flag

```
CCOI26{_3asy_p3asy_2_4ll_3asy_p3asy_}
```
