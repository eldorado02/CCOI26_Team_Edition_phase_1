import struct, base64, hashlib, codecs

data = open('audio.wav', 'rb').read()

i = 12
while i < len(data):
    chunk_id   = data[i:i+4]
    chunk_size = struct.unpack('<I', data[i+4:i+8])[0]

    if chunk_id == b'OCOI':
        raw    = data[i+8:i+8+chunk_size]
        fields = [f for f in raw.split(b'\x00') if f]

        codename = codecs.encode(fields[0].decode(), 'rot_13')

        payload = base64.b64decode(fields[2])

        key  = hashlib.md5(codename.encode()).digest()
        flag = bytes(payload[j] ^ key[j % 16] for j in range(len(payload)))
        print(flag.decode())

        coords_enc = base64.b64decode(fields[1])
        coords     = bytes(coords_enc[j] ^ key[j % 16] for j in range(len(coords_enc)))
        print(f"[*] GPS coords: {coords.decode()}")
        break

    i += 8 + chunk_size
    if chunk_size % 2 == 1:
        i += 1
