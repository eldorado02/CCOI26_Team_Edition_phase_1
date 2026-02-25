#!/usr/bin/env python3
# ─── Lagon Noir ─────────────────────────────────────────────────────────────
# Category: Forensics
# Flag: CCOI26{l4g0n_n01r_0p3r4t10n_c0mpl3t3_4g3nt_c0mpr0m1s}
# Requires keys from both previous forensics challenges:
#   challenge1_author   = "OCOI2026"         (Infiltré / Fantôme de la Vanille)
#   challenge2_codename = "SPECTRE_NODE"     (Signal Fantôme)
# ---------------------------------------------------------------------------
import struct, base64, hashlib

data = open('final.jpg', 'rb').read()

# Parse JPEG segments looking for APP14 (0xFFEE) carrying OCOI_LAGON data
i = 2
payload_b64 = None
while i < len(data) - 4:
    if data[i] != 0xFF:
        break
    marker  = data[i+1]
    seg_len = struct.unpack('>H', data[i+2:i+4])[0]

    if marker == 0xEE:  # APP14
        seg_data = data[i+4:i+2+seg_len]
        fields   = [f for f in seg_data.split(b'\x00') if f]
        # Field 2: "payload=<base64>"
        for field in fields:
            if field.startswith(b'payload='):
                payload_b64 = field[8:]
        break

    if marker in (0xD9, 0xDA):  # EOI or SOS
        break
    i += 2 + seg_len

if payload_b64 is None:
    raise RuntimeError("APP14 OCOI_LAGON segment not found")

# Build combined key: MD5("SPECTRE_NODE") XOR MD5("OCOI2026")
key = bytes(a ^ b for a, b in zip(
    hashlib.md5(b"SPECTRE_NODE").digest(),   # Signal Fantôme codename
    hashlib.md5(b"OCOI2026").digest()        # Infiltré author metadata
))

payload = base64.b64decode(payload_b64)
flag    = bytes(payload[j] ^ key[j % 16] for j in range(len(payload)))
print(flag.decode())
