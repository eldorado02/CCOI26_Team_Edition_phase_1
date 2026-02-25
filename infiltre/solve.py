#!/usr/bin/env python3
import struct, base64, hashlib

data = open('image.png', 'rb').read()

# Parse PNG chunks looking for private 'ocOI' chunk
i = 8
payload_b64 = None
while i < len(data):
    length     = struct.unpack('>I', data[i:i+4])[0]
    chunk_type = data[i+4:i+8]
    chunk_data = data[i+8:i+8+length]

    if chunk_type == b'ocOI':
        for field in chunk_data.split(b'\x00'):
            if field.startswith(b'payload='):
                payload_b64 = field[8:]

    i += 12 + length  # 4 len + 4 type + length data + 4 CRC

if payload_b64 is None:
    raise RuntimeError("ocOI chunk not found")

# Decrypt: XOR(payload, MD5("OCOI2026"))
key     = hashlib.md5(b"OCOI2026").digest()
payload = base64.b64decode(payload_b64)
flag    = bytes(payload[j] ^ key[j % 16] for j in range(len(payload)))
print(flag.decode())
