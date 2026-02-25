# Writeup — Lagon Noir

**Category:** Forensics  
**File:** `final.jpg` (JPEG 640×480)  
**Flag:** `CCOI26{l4g0n_n01r_0p3r4t10n_c0mpl3t3_4g3nt_c0mpr0m1s}`  
**Prérequis :** clés des deux challenges précédents (Infiltré + Signal Fantôme)

---

## Description

> Transmission finale de l'agent avant sa compromission.  
> *Pour décoder ce message, vous aurez besoin de ce que vous avez appris lors des deux transmissions précédentes.*

---

## Recon

```
$ file final.jpg
JPEG image data, 640x480, comment: "CCOI26{n0t_th3_f1n4l_fl4g_th1s_1s_4_tr4p}"

$ exiftool final.jpg
Comment  : CCOI26{n0t_th3_f1n4l_fl4g_th1s_1s_4_tr4p}
GPS Position : 20 deg 9' 39.24" S, 57 deg 29' 56.40" E
```

Deux leurres immédiats : un faux flag dans le COM segment, et des coordonnées GPS bidon (Port-Louis, Maurice). Je les ignore et je parse les segments JPEG.

---

## Analyse des segments JPEG

Les JPEG sont composés de marqueurs `0xFF 0xXX` chacun avec un payload préfixé par sa longueur. Je liste tout :

```python
import struct
data = open('final.jpg','rb').read()
i = 2
while i < len(data) - 4:
    marker = f"0xFF{data[i+1]:02X}"
    seg_len = struct.unpack('>H', data[i+2:i+4])[0]
    print(f"{marker} len={seg_len}")
    if data[i+1] in (0xD9, 0xDA): break
    i += 2 + seg_len
```

Segments trouvés :

| Marqueur | Type | Contenu |
|----------|------|---------|
| `0xFFE0` | APP0 (JFIF) | Header standard |
| `0xFFFE` | COM | Faux flag ← leurre |
| `0xFFE1` | APP1 (EXIF) | Faux GPS ← leurre |
| **`0xFFEE`** | **APP14** | **`OCOI_LAGON` — payload réel install pwntools* |

APP14 est normalement utilisé par Adobe pour les infos couleur. Ici il est détourné, comme `ocOI` dans le PNG et `OCOI` dans le WAV.

---

## Segment APP14 — Décodage

Trois champs séparés par `\x00` :

```
OCOI_LAGON
key=XOR(MD5(challenge2_codename),MD5(challenge1_author))
payload=x9Gmy8/cQ7kmcfp3GV67+PbN2fLOmAyhIyakRiUA5rnooZ2xot5f5nxilXp2Xfu7tP/Y8YA=
```

Le hint est explicite : la clé combine les deux challenges précédents.

- `challenge2_codename` = `SPECTRE_NODE` (Signal Fantôme, champ ROT13)
- `challenge1_author`   = `OCOI2026` (Infiltré, métadonnées `Author`)

---

## Construction de la clé combinée

```python
import hashlib
md5_ch2 = hashlib.md5(b"SPECTRE_NODE").digest()  # 0db06b0ebdff12df63a9c2371c849648
md5_ch1 = hashlib.md5(b"OCOI2026").digest()       # 8922828c40152a0a71bf082e5ab41d81
key = bytes(a ^ b for a, b in zip(md5_ch2, md5_ch1))
# 8492e982fdea38d51216ca1946308bc9
```

---

## Déchiffrement

```python
import base64
payload = base64.b64decode(
    "x9Gmy8/cQ7kmcfp3GV67+PbN2fLOmAyhIyakRiUA5rnooZ2xot5f5nxilXp2Xfu7tP/Y8YA="
)
flag = bytes(payload[i] ^ key[i % 16] for i in range(len(payload)))
print(flag.decode())
# CCOI26{l4g0n_n01r_0p3r4t10n_c0mpl3t3_4g3nt_c0mpr0m1s}
```

---

## Structure générale des 3 challenges forensics

| Challenge | Format | Container | Clé |
|-----------|--------|-----------|-----|
| Infiltré (Fantôme de la Vanille) | PNG | Chunk `ocOI` | `MD5("OCOI2026")` |
| Signal Fantôme | WAV | RIFF chunk `OCOI` | `MD5("SPECTRE_NODE")` |
| **Lagon Noir** | **JPEG** | **APP14 `OCOI_LAGON`** | `MD5("SPECTRE_NODE") XOR MD5("OCOI2026")` |

---

## Script complet

```python
import struct, base64, hashlib

data = open('final.jpg', 'rb').read()

i = 2
while i < len(data) - 4:
    if data[i] == 0xFF and data[i+1] == 0xEE:
        seg_len  = struct.unpack('>H', data[i+2:i+4])[0]
        seg_data = data[i+4:i+2+seg_len]
        fields   = [f for f in seg_data.split(b'\x00') if f]
        payload_b64 = fields[2].split(b'=', 1)[1]
        break
    seg_len = struct.unpack('>H', data[i+2:i+4])[0]
    i += 2 + seg_len

key = bytes(a ^ b for a, b in zip(
    hashlib.md5(b"SPECTRE_NODE").digest(),
    hashlib.md5(b"OCOI2026").digest()
))
payload = base64.b64decode(payload_b64)
flag = bytes(payload[i] ^ key[i % 16] for i in range(len(payload)))
print(flag.decode())
```

---

## Flag

```
CCOI26{l4g0n_n01r_0p3r4t10n_c0mpl3t3_4g3nt_c0mpr0m1s}
```
