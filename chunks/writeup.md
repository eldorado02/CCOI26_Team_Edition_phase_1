# Writeup — Chunks

**Category:** Cryptographie  
**Files:** `enc_chunks.py`, `challenge.bin`  
**Flag:** `CCOI26{ChUnK5_0f_K3y5_4nd_0ff53t5}`

---

## Description

> Find the flag.

Deux fichiers fournis : `enc_chunks.py` (le script de chiffrement) et `challenge.bin` (34 octets de ciphertext).

---

## Le problème

Le flag est chiffré de la façon suivante dans `enc_chunks.py` :

1. Le flag (34 caractères) est découpé en **4 chunks** de tailles quasi-égales (`[8, 8, 9, 9]`).
2. Chaque chunk reçoit une **clé aléatoire** `k ∈ [1, 80]` (tirée avec `random.randint`).
3. Chaque octet `v` à la position locale `i` dans son chunk est transformé ainsi :
   ```
   ciphertext[byte] = ((v + i) & 0xFF) ^ k
   ```
   → on décale d'abord par la position (`+ i`), puis XOR avec la clé du chunk.

Le résultat est écrit dans `challenge.bin`. Les clés **ne sont pas fournies** : il faut les retrouver.

**Pourquoi c'est cassable ?** L'espace des clés est minuscule : seulement **80 valeurs possibles** par chunk, soit au maximum 80⁴ = 40 960 000 combinaisons — et en pratique beaucoup moins grâce aux contraintes connues sur le flag.

---

## Déchiffrement

L'opération inverse de `((v + i) & 0xFF) ^ k` est :

```
v = ((ciphertext[byte] ^ k) - i) & 0xFF
```

Pour chaque chunk, on XOR le ciphertext avec la clé `k`, puis on soustrait l'offset local `i`. Il suffit donc de trouver la bonne valeur de `k` pour chaque chunk.

---

## Résolution

### Chunk 0 — Attaque à texte clair connu

Le flag commence par `CCOI26{`. À la position `i=0` il n'y a pas de décalage, donc `k0` se calcule directement :

```
k0 = enc[0] ^ ord('C') = 67
```

Déchiffrement avec `k0=67` → `"CCOI26{Ch"` ✓

### Chunk 3 — Contrainte de fermeture

Le flag se termine par `}`. Je brute-force les 80 clés du dernier chunk et je garde la seule dont le dernier caractère est `}` :

```
k3 = 34  →  "0ff53t5}"  ✓
```

### Chunks 1 & 2 — Score alphanumérique

Pour les deux chunks du milieu, je teste toutes les 80 × 80 combinaisons et je score chaque reconstruction complète en comptant les caractères valides (`[a-zA-Z0-9_{}]`). Une seule paire atteint le score parfait 34/34 :

| k1 | k2 | Chunk 1     | Chunk 2     |
|----|----|-------------|-------------|
| 18 | 77 | `UnK5_0f_`  | `K3y5_4nd_` |

---

## Clés récupérées

| Chunk | Octets | Clé |
|-------|--------|-----|
| 0     | 0–8    | 67  |
| 1     | 9–17   | 18  |
| 2     | 18–25  | 77  |
| 3     | 26–33  | 34  |

---

## Script

Le script complet est dans `solve_chunks_v2.py`. Voici le cœur de la logique :

```python
from pathlib import Path
import string

enc = list(Path("challenge.bin").read_bytes())
n = len(enc)

sizes = [n // 4] * 4
for i in range(n % 4):
    sizes[i] += 1

offsets, p = [], 0
for s in sizes:
    offsets.append((p, p + s))
    p += s

def decrypt_chunk(enc_chunk, key):
    return ''.join(chr(((x ^ key) - i) & 255) for i, x in enumerate(enc_chunk))

CTF_CHARS = set(string.ascii_letters + string.digits + '_{}')

# Chunk 0 : préfixe connu → clé directe
k0 = enc[0] ^ ord('C')
part0 = decrypt_chunk(enc[offsets[0][0]:offsets[0][1]], k0)

# Chunk 3 : seul k donnant un '}' final
k3 = next(k for k in range(1, 81)
          if decrypt_chunk(enc[offsets[3][0]:offsets[3][1]], k).endswith('}'))
part3 = decrypt_chunk(enc[offsets[3][0]:offsets[3][1]], k3)

# Chunks 1 & 2 : brute-force avec filtre alphanumérique
best = (0, None, None)
for k1 in range(1, 81):
    p1 = decrypt_chunk(enc[offsets[1][0]:offsets[1][1]], k1)
    if not all(c in CTF_CHARS for c in p1): continue
    for k2 in range(1, 81):
        p2 = decrypt_chunk(enc[offsets[2][0]:offsets[2][1]], k2)
        if not all(c in CTF_CHARS for c in p2): continue
        score = sum(1 for c in (part0+p1+p2+part3) if c in CTF_CHARS)
        if score > best[0]:
            best = (score, k1, k2)

_, k1, k2 = best
flag = (part0
        + decrypt_chunk(enc[offsets[1][0]:offsets[1][1]], k1)
        + decrypt_chunk(enc[offsets[2][0]:offsets[2][1]], k2)
        + part3)
print(flag)
```

---

## Flag

```
CCOI26{ChUnK5_0f_K3y5_4nd_0ff53t5}
```
