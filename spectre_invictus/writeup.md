# Writeup — Spectre Invictus

**Category:** Reverse Engineering  
**Binary:** `rev2` (ELF 64-bit, not stripped, debug info, No PIE)  
**Flag:** `CCOI26{elf_s3ct10n_h4ck_inv1ctus_5p3ctr3_0c34n}`

---

## Description

> The specter is invincible... or is it?

---

## Premier tour du binaire

```
$ file rev2
ELF 64-bit LSB executable, x86-64, not stripped, with debug_info

$ checksec rev2
NX: enabled, No PIE, No canary
```

Je le lance — il demande un token, retourne `Rejected` si faux.

```
$ strings rev2 | grep CCOI
CCOI26{f4k3_fl4g_y0u_f00l_r3v3rs3_h4rd3r}
```

Un faux flag bien visible dans `.rodata`. Je creuse plus loin.

---

## Anti-debug via ptrace

Le binaire appelle `ptrace(PTRACE_TRACEME)` au démarrage. Si un debugger est déjà attaché, `ptrace` retourne `-1` et le programme branche sur une autre logique (le faux flag). Pour reverser sous GDB j'ai deux options :

- Patcher l'instruction `jne` après le check
- Ou analyser statiquement (plus simple)

---

## Chercher les sections cachées

```
$ readelf -S rev2
```

Sections visibles : `.text`, `.rodata`, `.data`, comme d'habitude. Rien d'inhabituel.

Mais je regarde les **program headers** (segments) :

```
$ readelf -l rev2
```

Un segment `PT_NOTE` sort du lot : il mappe une plage mémoire qui **n'appartient à aucune section ELF**. File offset `0x4f13`, taille 76 octets.

---

## Parser le segment PT_NOTE

```python
from elftools.elf.elffile import ELFFile

with open("rev2", "rb") as f:
    elf = ELFFile(f)
    for seg in elf.iter_segments():
        if seg.header.p_type == "PT_NOTE":
            offset = seg.header.p_offset
            size   = seg.header.p_filesz
            print(f"PT_NOTE @ 0x{offset:x}, size={size}")
```

Output : `PT_NOTE @ 0x4f13, size=76`

Format du payload :

```
Offset  Taille  Champ
------  ------  -----
0       4       Magic "OCOI" (même convention que les forensics)
4       4       longueur = 64
8       64      ciphertext base64
72      4       checksum
```

Je décode le base64 → **47 bytes de ciphertext XOR**.

---

## Retrouver la clé XOR — known plaintext

Le flag commence par `CCOI26{`. Grâce à ce texte clair connu je peux XOR directement les 7 premiers bytes :

```python
ciphertext = bytes.fromhex("...")   # 47 bytes extrait du PT_NOTE
known = b"CCOI26{"
key_partial = bytes(c ^ k for c, k in zip(ciphertext, known))
```

Ça me donne les 7 premiers bytes de la clé. La clé est une chaîne hex de 32 bytes — je teste si elle est périodique ou répétée. En essayant longueur 32 (MD5-like) et en cross-validant avec `_` et `}` à des positions connues, je trouve :

```
key = fa77e56098aa45108e4bc86ad4dedcd1
```

---

## Déchiffrement

```python
import base64

data = open("rev2", "rb").read()
note_offset = 0x4f13

magic   = data[note_offset:note_offset+4]
length  = int.from_bytes(data[note_offset+4:note_offset+8], 'little')
ct_b64  = data[note_offset+8:note_offset+8+length]
ct      = base64.b64decode(ct_b64)

key = bytes.fromhex("fa77e56098aa45108e4bc86ad4dedcd1")
flag = bytes(c ^ key[i % len(key)] for i, c in enumerate(ct))
print(flag.decode())
# CCOI26{elf_s3ct10n_h4ck_inv1ctus_5p3ctr3_0c34n}
```

---

## Details techniques résumés

| Élément | Valeur |
|---------|--------|
| PT_NOTE file offset | `0x4f13` |
| Magic | `OCOI` |
| Ciphertext (base64 len) | 64 bytes → 47 bytes décodés |
| Clé XOR | `fa77e56098aa45108e4bc86ad4dedcd1` |
| Méthode de découverte clé | Known-plaintext `CCOI26{` + validation `_` / `}` |

---

## Script complet

```python
import base64

data = open("rev2", "rb").read()

# PT_NOTE segment hors sections → offset trouvé via readelf
NOTE_OFFSET = 0x4f13
magic  = data[NOTE_OFFSET:NOTE_OFFSET+4]
assert magic == b"OCOI"
length = int.from_bytes(data[NOTE_OFFSET+4:NOTE_OFFSET+8], 'little')
ct     = base64.b64decode(data[NOTE_OFFSET+8:NOTE_OFFSET+8+length])

key    = bytes.fromhex("fa77e56098aa45108e4bc86ad4dedcd1")
flag   = bytes(c ^ key[i % len(key)] for i, c in enumerate(ct))
print(flag.decode())
```

---

## Flag

```
CCOI26{elf_s3ct10n_h4ck_inv1ctus_5p3ctr3_0c34n}
```
