# Writeup — Chunks 2

**Category:** Cryptographie (Hard)  
**Files:** `enc.py`, `challenge.bin`  
**Flag:** `CCOI26{ChUnK5_2_Sh4d0w_K3y5_4nd_Ch41n5}`

---

## Description

> Find the flag.

Même principe que Chunks mais avec beaucoup plus de couches.

---

## Analyse du format binaire

Le ciphertext commence par un header structuré :

```
Offset  Taille  Champ
------  ------  -----
0       4       Magic: "CHK2"
4       1       PARTS = 4
5       4       sizes[4]   — taille de chaque chunk plaintext
9       4       perm[4]    — ordre de sortie mélangé
13      4       salts[4]   — sel aléatoire par chunk (0–255)
17      4       ivs[4]     — IV aléatoire par chunk (0–255)
21      …       chunks chiffrés (dans l'ordre de perm)
```

En parsant `challenge.bin` :

| Champ  | Valeurs                              |
|--------|--------------------------------------|
| sizes  | [10, 10, 10, 9]  (total 39 octets)   |
| perm   | [1, 2, 3, 0]                         |
| salts  | [239, 129, 209, 76]                  |
| ivs    | [134, 45, 105, 121]                  |

Les chunks sont stockés dans l'ordre `[1, 2, 3, 0]` plutôt que `[0, 1, 2, 3]`.

---

## Schéma de chiffrement

Pour chaque chunk avec sa clé `k ∈ [1, 80]`, son `salt` et son `iv` :

```python
prev = iv
for i, v in enumerate(chunk):
    x = (v + i) & 0xFF               # décalage positionnel
    x = rotl3(x)                     # rotation gauche 3 bits
    ks = sha256([k, salt, part_idx, i])[0]  # keystream SHA-256
    x ^= ks                          # XOR keystream
    x ^= prev                        # CBC-like chaining
    x = (x + (part_idx + 1) * 7) & 0xFF    # biais additif
    out.append(x)
    prev = x
```

Par rapport à Chunks 1, il y a trois nouveautés : un **keystream SHA-256** par byte, un **chaînage CBC**, et une **permutation de l'ordre des chunks**.

---

## Déchiffrement

L'inverse par byte (en sachant que `prev` est le byte **ciphertext**, pas plaintext) :

```python
prev = iv
for i, c in enumerate(enc_chunk):
    x = (c - (part_idx + 1) * 7) & 0xFF
    x ^= prev
    ks = sha256([k, salt, part_idx, i])[0]
    x ^= ks
    x = rotr3(x)
    v = (x - i) & 0xFF
    prev = c
```

Les salts et ivs sont dans le header en clair, donc la seule inconnue par chunk est `k ∈ [1, 80]`.

---

## Résolution

### Chunk 0 — Texte clair connu

Le flag commence par `CCOI26{`. Le chunk 0 est en dernière position dans le fichier (à cause de la permutation) mais ça ne change rien au déchiffrement :

```
k0 = 74  →  "CCOI26{ChU"  ✓
```

### Chunk 3 — Contrainte de fermeture

```
k3 = 7  →  "d_Ch41n5}"  ✓
```

### Chunks 1 & 2 — Score alphanumérique

| Chunk | k  | Plaintext      |
|-------|----|----------------|
| 1     | 18 | `nK5_2_Sh4d`   |
| 2     | 48 | `0w_K3y5_4n`   |

---

## Clés récupérées

| Chunk | Taille | Salt | IV  | Clé |
|-------|--------|------|-----|-----|
| 0     | 10     | 239  | 134 | 74  |
| 1     | 10     | 129  | 45  | 18  |
| 2     | 10     | 209  | 105 | 48  |
| 3     | 9      | 76   | 121 | 7   |

---

## Script

```python
from pathlib import Path
import hashlib, string

data = Path("challenge.bin").read_bytes()

assert data[:4] == b"CHK2"
PARTS = data[4]
sizes = list(data[5:5+PARTS])
perm  = list(data[5+PARTS:5+2*PARTS])
salts = list(data[5+2*PARTS:5+3*PARTS])
ivs   = list(data[5+3*PARTS:5+4*PARTS])

HEADER = 5 + 4*PARTS
enc_by_part = {}
offset = HEADER
for perm_idx, part_idx in enumerate(perm):
    sz = sizes[part_idx]
    enc_by_part[part_idx] = data[offset:offset+sz]
    offset += sz

def rotl3(x): return ((x << 3) | (x >> 5)) & 255
def rotr3(x): return ((x >> 3) | (x << 5)) & 255

def decrypt_chunk(enc_chunk, key, salt, part_idx, iv):
    prev, out = iv, []
    for i, c in enumerate(enc_chunk):
        x = (c - (part_idx + 1) * 7) & 255
        x ^= prev
        ks = hashlib.sha256(bytes([key, salt, part_idx, i])).digest()[0]
        x ^= ks
        x = rotr3(x)
        out.append((x - i) & 255)
        prev = c
    return bytes(out)

def score(b):
    return sum(1 for c in b.decode(errors='replace')
               if c in string.ascii_letters + string.digits + '_{}')

results = {}

for k in range(1, 81):
    dec = decrypt_chunk(enc_by_part[0], k, salts[0], 0, ivs[0])
    if dec[:7] == b"CCOI26{":
        results[0] = dec; break

for k in range(1, 81):
    dec = decrypt_chunk(enc_by_part[3], k, salts[3], 3, ivs[3])
    if dec[-1] == ord('}'):
        results[3] = dec; break

for part_idx in [1, 2]:
    best_k, best_dec, best_score = None, None, -1
    for k in range(1, 81):
        dec = decrypt_chunk(enc_by_part[part_idx], k, salts[part_idx], part_idx, ivs[part_idx])
        s = score(dec)
        if s > best_score:
            best_score, best_k, best_dec = s, k, dec
    results[part_idx] = best_dec

flag = b"".join(results[i] for i in range(PARTS))
print(flag.decode())
```

---

## Flag

```
CCOI26{ChUnK5_2_Sh4d0w_K3y5_4nd_Ch41n5}
```
