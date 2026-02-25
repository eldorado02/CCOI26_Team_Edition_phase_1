# Writeup — Easy Peasy

**Category:** Cryptographie  
**Files:** `enc_easy.py`, `challenge_easy.bin`  
**Flag:** `CCOI26{_eAsY_PeAsY_1s_3v3n_b3tt3r_w1th_4_k3y}`

---

## Description

> Find the flag.

Deux fichiers : `enc_easy.py` et `challenge_easy.bin` (45 octets chiffrés).

---

## Comprendre le chiffrement

Dans `enc_easy.py` :

```python
data = bytes((((b + 2) & 255) ^ KEY) for b in FLAG)
```

Chaque byte du flag est d'abord décalé de +2, puis XOR avec une clé globale `KEY ∈ [1, 80]`. C'est un XOR mono-octet avec un tout petit espace de clés.

---

## Résolution

### Méthode 1 — Texte clair connu (1 opération)

Le flag commence par `CCOI26{`, donc je connais le premier octet du plaintext. En position 0 :

```
c[0] = (ord('C') + 2) ^ KEY
     = 69 ^ KEY
=> KEY = c[0] ^ 69 = 0x6F ^ 69 = 42
```

Une seule XOR et j'ai la clé.

**Déchiffrement :**

```
v = ((c ^ KEY) - 2) & 0xFF
```

Avec `KEY = 42` appliqué aux 45 octets, le flag sort directement.

### Méthode 2 — Brute force (vérification)

80 clés possibles au total. En testant toutes, seule `key=42` donne un texte qui commence par `CCOI26{` et se termine par `}`. ✓

---

## Script

```python
from pathlib import Path

enc = list(Path("challenge_easy.bin").read_bytes())

# KEY depuis le premier octet connu 'C' (ASCII 67)
# c[0] = (67 + 2) ^ KEY  =>  KEY = c[0] ^ 69
key = enc[0] ^ 69

flag = bytes(((c ^ key) - 2) & 255 for c in enc).decode()
print(flag)
```

---

## Flag

```
CCOI26{_eAsY_PeAsY_1s_3v3n_b3tt3r_w1th_4_k3y}
```
