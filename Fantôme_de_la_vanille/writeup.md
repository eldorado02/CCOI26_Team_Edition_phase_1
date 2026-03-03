# Writeup — Infiltré (Fantôme de la Vanille)

**Category:** Forensics  
**File:** `image.png` (512×512 PNG)  
**Flag:** `CCOI26{v4n1ll4_15l4nd_s3cr3t_1n_pl41n_s1ght}`

---

## Description

> Un agent infiltré dans le réseau de la Réunion a transmis cette image avant de disparaître.  
> Les analystes ont trouvé quelque chose... mais ce n'était pas le bon message.  
> **Cherchez plus profondément.**

---

## Recon

```
$ file image.png
image.png: PNG image data, 512 x 512, 8-bit/color RGB, non-interlaced

$ exiftool image.png
Author  : OCOI2026
```

Je note `OCOI2026` dans les métadonnées — j'y reviendrai.

---

## Couche 1 — Le faux flag (LSB)

```
$ zsteg image.png
b1,r,lsb,xy  .. text: "CCOI26{n0t_th3_r34l_fl4g_k33p_d1gg1ng}"
chunk:1:ocOI .. text: "author=OCOI2026"
```

Le texte du flag lui-même dit *"not the real flag, keep digging"*. C'est un leurre planté dans les LSB du canal rouge. Je creuse.

---

## Couche 2 — Chunk PNG privé `ocOI`

`zsteg` révèle aussi un chunk non-standard `ocOI`. Les chunks PNG ont le format `[length][type][data][CRC]` — aucun outil classique ne l'affiche. Je parse manuellement :

```python
import struct, base64, hashlib
data = open('image.png','rb').read()
i = 8
while i < len(data):
    length = struct.unpack('>I', data[i:i+4])[0]
    ctype  = data[i+4:i+8]
    chunk_data = data[i+8:i+8+length]
    if ctype == b'ocOI':
        for field in chunk_data.split(b'\x00'):
            print(field.decode(errors='replace'))
    i += 12 + length
```

Sortie :

```
author=OCOI2026
hint=WE9SKGZsYWcsIE1ENShBdXRob3JfbWV0YWRhdGEpKQ==
payload=ymHNxXIjUXxF0TlCNoBCsLxOtuIkSlk5Es07WgWFc975Tra9LkpZOxbXfFM=
```

Je décode le hint :

```python
base64.b64decode("WE9SKGZsYWcsIE1ENShBdXRob3JfbWV0YWRhdGEpKQ==")
# → b"XOR(flag, MD5(Author_metadata))"
```

L'algorithme est clair : `flag = payload XOR MD5("OCOI2026")`

---

## Déchiffrement

```python
key = hashlib.md5(b"OCOI2026").digest()
# 8922828c40152a0a71bf082e5ab41d81

payload = base64.b64decode(
    "ymHNxXIjUXxF0TlCNoBCsLxOtuIkSlk5Es07WgWFc975Tra9LkpZOxbXfFM="
)
flag = bytes(payload[i] ^ key[i % 16] for i in range(len(payload)))
print(flag.decode())
# CCOI26{v4n1ll4_15l4nd_s3cr3t_1n_pl41n_s1ght}
```

---

## Flag

```
CCOI26{v4n1ll4_15l4nd_s3cr3t_1n_pl41n_s1ght}
```
