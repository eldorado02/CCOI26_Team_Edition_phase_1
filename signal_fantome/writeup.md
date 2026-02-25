# Writeup — Signal Fantôme

**Category:** Forensics  
**File:** `audio.wav` (WAV 44100 Hz mono 16-bit, ~706 kB, 8 s)  
**Flag:** `CCOI26{sp3ctr3_n0d3_c00rd5_-20.8789_55.4481}`

---

## Description

> L'agent a transmis un second fichier : un enregistrement audio capté sur une fréquence radio illicite dans la région malgache.  
> Les analystes ont passé des heures sur le spectrogramme. Rien.  
> Pourtant, le fichier contient quelque chose. Regardez là où les outils ne regardent pas.

---

## Recon

```
$ file audio.wav
RIFF (little-endian) data, WAVE audio, Microsoft PCM, 16 bit, mono 44100 Hz

$ exiftool audio.wav
Duration: 8.00 s
```

Rien d'intéressant en surface, et la description dit que le spectrogramme ne montre rien. Donc je ne perds pas de temps avec Audacity ou SSTV — le format RIFF est un conteneur qui supporte des chunks privés, exactement comme PNG avec `ocOI` dans le challenge précédent.

---

## Structure RIFF

Je parse tous les chunks du fichier :

```python
import struct
data = open('audio.wav','rb').read()
i = 12
while i < len(data):
    chunk_id   = data[i:i+4].decode(errors='replace')
    chunk_size = struct.unpack('<I', data[i+4:i+8])[0]
    print(f"chunk='{chunk_id}' size={chunk_size}")
    i += 8 + chunk_size
    if chunk_size % 2 == 1: i += 1
```

Sortie :

```
chunk='fmt ' size=16
chunk='data' size=705600
chunk='OCOI' size=155   ← chunk privé !
```

Même technique qu'Infiltré — les données sont dans un chunk `OCOI` après l'audio.

---

## Décodage du chunk OCOI

Le chunk contient 4 champs séparés par `\x00` :

| Index | Contenu brut | Décodé |
|-------|-------------|--------|
| 0 | `FCRPGER_ABQR` | ROT13 → `SPECTRE_NODE` |
| 1 | base64 → 16 bytes | coordonnées GPS chiffrées |
| 2 | base64 → 44 bytes | flag chiffré |
| 3 | base64 → texte | hint de déchiffrement |

Je décode le hint (champ 3) :

```python
import base64
base64.b64decode("Uk9UMTMoY29kZW5hbWUpIC0+IFhPUiBrZXkgPSBNRDUoY29kZW5hbWUp")
# → b"ROT13(codename) -> XOR key = MD5(codename)"
```

Le codename est dans le champ 0, encodé ROT13 → `SPECTRE_NODE`.

---

## Récupérer le flag

```python
import hashlib, codecs

codename = codecs.encode("FCRPGER_ABQR", "rot_13")  # → "SPECTRE_NODE"
key = hashlib.md5(codename.encode()).digest()
# 0db06b0ebdff12df63a9c2371c849648

payload = base64.b64decode(
    "TvMkR4/JaawTmqFDbrfJJj3UWFHezyKtB5ydGi60uHA6iFJRiMo861eR80o="
)
flag = bytes(payload[i] ^ key[i % 16] for i in range(len(payload)))
print(flag.decode())
# CCOI26{sp3ctr3_n0d3_c00rd5_-20.8789_55.4481}
```

Bonus — le champ 1 contient des coordonnées GPS :

```python
coords_enc = base64.b64decode("IIJbIIXIKuZPnPcZKLCueQ==")
coords = bytes(coords_enc[i] ^ key[i % 16] for i in range(len(coords_enc)))
# → "-20.8789,55.4481"  (La Réunion)
```

---

## Script complet

```python
import struct, base64, hashlib, codecs

data = open('audio.wav', 'rb').read()

i = 12
while i < len(data):
    chunk_id   = data[i:i+4]
    chunk_size = struct.unpack('<I', data[i+4:i+8])[0]
    if chunk_id == b'OCOI':
        fields   = [f for f in data[i+8:i+8+chunk_size].split(b'\x00') if f]
        codename = codecs.encode(fields[0].decode(), 'rot_13')
        payload  = base64.b64decode(fields[2])
        key      = hashlib.md5(codename.encode()).digest()
        flag     = bytes(payload[j] ^ key[j % 16] for j in range(len(payload)))
        print(flag.decode())
    i += 8 + chunk_size
    if chunk_size % 2 == 1: i += 1
```

---

## Flag

```
CCOI26{sp3ctr3_n0d3_c00rd5_-20.8789_55.4481}
```
