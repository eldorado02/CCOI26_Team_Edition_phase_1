#!/usr/bin/env python3
# ─── Signal Fantôme ─────────────────────────────────────────────────────────
# Category: Forensics
# Flag: CCOI26{sp3ctr3_n0d3_c00rd5_-20.8789_55.4481}
# ---------------------------------------------------------------------------
import struct, base64, hashlib, codecs

data = open('audio.wav', 'rb').read()

# Parse RIFF chunks looking for private 'OCOI' chunk
i = 12  # skip RIFF header (4 magic + 4 size + 4 "WAVE")
while i < len(data):
    chunk_id   = data[i:i+4]
    chunk_size = struct.unpack('<I', data[i+4:i+8])[0]

    if chunk_id == b'OCOI':
        raw    = data[i+8:i+8+chunk_size]
        fields = [f for f in raw.split(b'\x00') if f]

        # Field 0: codename encoded with ROT13
        codename = codecs.encode(fields[0].decode(), 'rot_13')   # → SPECTRE_NODE

        # Field 2: XOR-encrypted flag (base64)
        payload = base64.b64decode(fields[2])

        # Key = MD5(codename)
        key  = hashlib.md5(codename.encode()).digest()
        flag = bytes(payload[j] ^ key[j % 16] for j in range(len(payload)))
        print(flag.decode())

        # Bonus: field 1 contains GPS coordinates
        coords_enc = base64.b64decode(fields[1])
        coords     = bytes(coords_enc[j] ^ key[j % 16] for j in range(len(coords_enc)))
        print(f"[*] GPS coords: {coords.decode()}")
        break

    i += 8 + chunk_size
    if chunk_size % 2 == 1:
        i += 1  # RIFF padding byte
