import struct, base64, hashlib

data = open('final.jpg', 'rb').read()

i = 2
payload_b64 = None
while i < len(data) - 4:
    if data[i] != 0xFF:
        break
    marker  = data[i+1]
    seg_len = struct.unpack('>H', data[i+2:i+4])[0]

    if marker == 0xEE:
        seg_data = data[i+4:i+2+seg_len]
        fields   = [f for f in seg_data.split(b'\x00') if f]
        for field in fields:
            if field.startswith(b'payload='):
                payload_b64 = field[8:]
        break

    if marker in (0xD9, 0xDA):
        break
    i += 2 + seg_len

if payload_b64 is None:
    raise RuntimeError("APP14 OCOI_LAGON segment not found")

key = bytes(a ^ b for a, b in zip(
    hashlib.md5(b"SPECTRE_NODE").digest(),
    hashlib.md5(b"OCOI2026").digest()
))

payload = base64.b64decode(payload_b64)
flag    = bytes(payload[j] ^ key[j % 16] for j in range(len(payload)))
print(flag.decode())
