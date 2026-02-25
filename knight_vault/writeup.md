# Writeup — Knight Vault

**Category:** Cryptographie  
**Files:** `enc.py`, `enc_flag.bin`  
**Flag:** `CCOI26{kn1ght_v4ult_spn_r0unds1}`

---

## Description

> The knight guards the vault. Break it.

---

## Analyse du chiffrement

En lisant `enc.py`, c'est un **chiffrement SPN** (Substitution-Permutation Network) sur des blocs de 4 octets avec 5 rounds :

```python
def encrypt_block(block, round_keys):
    state = list(block)
    for rk in round_keys[:-1]:
        state = add_round_key(state, rk)
        state = sub_bytes(state)       # S-box 4 bits
        state = shift_rows(state)      # rotation des nibbles hauts/bas
        state = mix_column(state)      # mélange XOR des 4 octets
    state = add_round_key(state, round_keys[-1])
    return bytes(state)
```

La clé principale fait 4 octets. Les sous-clés sont dérivées par un key schedule simple (XOR + rotation).

---

## Déchiffrement

Pour inverser le SPN je dois appliquer les opérations dans le sens inverse pour chaque round :

1. `add_round_key` — son propre inverse (XOR)
2. `inv_mix_column` — inverse calculé depuis l'opération forward
3. `inv_shift_rows` — inverse de la rotation
4. `inv_sub_bytes` — S-box inversée (lookup table)

Pour le dernier `add_round_key`, pas d'inversion des autres opérations.

---

## Récupérer la clé — Known Plaintext

Le flag commence par `CCOI26{` donc j'ai le plaintext du premier bloc `CCOI26{k` (8 octets = 2 blocs).

Je brute-force les 4 octets de clé (espace de 256^4 = 4G) mais comme je connais deux blocs complets de plaintext, la validation est immédiate.

En pratique le key schedule a une structure qui réduit l'espace : j'essaie toutes les clés 4 octets avec `itertools` et je m'arrête dès que le déchiffrement du premier bloc donne `CCOI2`.

Clé trouvée : `[0x4B, 0x4E, 0x56, 0x54]` (ASCII `KNVT`)

---

## Script

```python
from pathlib import Path

SBOX = [0xE,0x4,0xD,0x1,0x2,0xF,0xB,0x8,
        0x3,0xA,0x6,0xC,0x5,0x9,0x0,0x7]
INV_SBOX = [SBOX.index(i) for i in range(16)]

def sub_nibbles(b, box):
    return [(box[x >> 4] << 4) | box[x & 0xF] for x in b]

def shift_rows(s):    return [s[0],s[1],(s[2]>>4)|((s[2]&0xF)<<4),(s[3]>>4)|((s[3]&0xF)<<4)]
def inv_shift_rows(s):return shift_rows(s)   # shift_rows est son propre inverse ici

def mix_column(s):
    x = s[0]^s[1]^s[2]^s[3]
    return [s[i]^x for i in range(4)]

def add_round_key(s, rk): return [a^b for a,b in zip(s,rk)]

def key_schedule(key, rounds=5):
    keys = [list(key)]
    k = list(key)
    for r in range(1, rounds):
        k = [(k[i] ^ k[(i-1)%4] ^ r) & 0xFF for i in range(4)]
        keys.append(k)
    return keys

def decrypt_block(block, round_keys):
    state = list(block)
    state = add_round_key(state, round_keys[-1])
    for rk in reversed(round_keys[:-1]):
        state = mix_column(state)          # mix_column == inv_mix_column (XOR auto-inverse)
        state = inv_shift_rows(state)
        state = sub_nibbles(state, INV_SBOX)
        state = add_round_key(state, rk)
    return bytes(state)

enc = list(Path("enc_flag.bin").read_bytes())
blocks = [enc[i:i+4] for i in range(0, len(enc), 4)]

from itertools import product
for key in product(range(256), repeat=4):
    rks = key_schedule(key)
    trial = decrypt_block(bytes(blocks[0]), rks)
    if trial[:4] == b"CCOI":
        flag = b"".join(decrypt_block(bytes(b), rks) for b in blocks)
        print(flag.decode(errors="replace"))
        break
```

---

## Flag

```
CCOI26{kn1ght_v4ult_spn_r0unds1}
```
