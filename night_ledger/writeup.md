# Writeup — Night Ledger

**Category:** Reverse Engineering  
**File:** `night_ledger` (ELF 64-bit, stripped, PIE)  
**Flag:** `CCOI26{n1ght_l3dg3r_k33p3r_logs}`

---

## Description

> Get your access token.

Un seul binaire. Je le lance :

```
====================================
            Night Ledger
====================================
Authenticate token.

Token: _
```

Mauvais token → `Rejected.`, bon token → `Accepted.`.

---

## Analyse statique

```
$ file night_ledger
night_ledger: ELF 64-bit LSB pie executable, x86-64, stripped
```

Pas de symboles. Dans `.rodata` je vois des blocs de bytes structurés et les strings `"Token: "`, `"Rejected."`, `"Accepted."`.

---

## Reverser la validation

### Contrainte de taille

Premier check dans le binaire :

```asm
cmp rax, 0x20    ; strlen doit être 32
```

Le token fait exactement **32 bytes**.

---

### Block 1 — bytes 0–15 : swap-case + XOR

Les 16 premiers bytes passent dans une séquence SSE (`paddb`, `psubusb`, `pcmpeqb`, `pand`, `por`) qui fait un **swap-case byte à byte** :

- `a–z` → majuscule (−0x20)
- `A–Z` → minuscule (+0x20)
- autre → inchangé

Ensuite XOR avec la constante à `0x20a0` :

```
xor1 = 23 28 2d 32 37 3c 41 46 4b 50 55 5a 5f 64 69 6e
```

Résultat attendu (`0x2090`) :

```
target1 = 40 4b 42 5b 05 0a 3a 08 7a 17 1d 0e 00 28 5a 2a
```

---

### Block 2 — bytes 16–31 : reverse + XOR

Les bytes 16–31 sont **inversés dans l'ordre**, puis XOR avec (`0x20b0`) :

```
xor2 = 61 5e 5b 58 55 52 4f 4c 49 46 43 40 3d 3a 37 34
```

Résultat attendu (`0x2080`) :

```
target2 = 1c 2d 3c 37 39 0d 3d 7f 39 75 70 2b 62 48 04 53
```

---

## Inversion

### Block 1

```
swap_case(input[0:16]) ^ xor1 = target1
=> input[i] = swap_case(target1[i] ^ xor1[i])
```

En calculant `target1 XOR xor1` :

```
63 63 6f 69 32 36 7b 4e 31 47 48 54 5f 4c 33 44
= c  c  o  i  2  6  {  N  1  G  H  T  _  L  3  D
```

Après swap_case → `CCOI26{n1ght_l3d`

### Block 2

```
reversed(input[16:32]) ^ xor2 = target2
=> input[16:32] = reverse(xor2 ^ target2)
```

`xor2 XOR target2` donne :

```
7d 73 67 6f 6c 5f 72 33 70 33 33 6b 5f 72 33 67
= "}sgol_r3p33k_r3g"
```

Reversed → `g3r_k33p3r_logs}`

---

## Script

```python
target1 = bytes([0x40,0x4b,0x42,0x5b,0x05,0x0a,0x3a,0x08,
                 0x7a,0x17,0x1d,0x0e,0x00,0x28,0x5a,0x2a])
xor1    = bytes([0x23,0x28,0x2d,0x32,0x37,0x3c,0x41,0x46,
                 0x4b,0x50,0x55,0x5a,0x5f,0x64,0x69,0x6e])
target2 = bytes([0x1c,0x2d,0x3c,0x37,0x39,0x0d,0x3d,0x7f,
                 0x39,0x75,0x70,0x2b,0x62,0x48,0x04,0x53])
xor2    = bytes([0x61,0x5e,0x5b,0x58,0x55,0x52,0x4f,0x4c,
                 0x49,0x46,0x43,0x40,0x3d,0x3a,0x37,0x34])

def swap_case(b):
    if 0x61 <= b <= 0x7a: return b - 0x20
    if 0x41 <= b <= 0x5a: return b + 0x20
    return b

part1 = bytes(swap_case(t ^ x) for t, x in zip(target1, xor1))
part2 = bytes(x ^ t for x, t in zip(xor2, target2))[::-1]
print((part1 + part2).decode())
```

Vérification :

```
$ echo -n "CCOI26{n1ght_l3dg3r_k33p3r_logs}" | ./night_ledger
...
Token: Accepted.
```

---

## Flag

```
CCOI26{n1ght_l3dg3r_k33p3r_logs}
```
