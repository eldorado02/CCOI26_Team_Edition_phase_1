from pathlib import Path
import string

enc = list(Path("challenge.bin").read_bytes())
n = len(enc)

PARTS = 4
KEY_MIN = 1
KEY_MAX = 80

sizes = [n // PARTS] * PARTS
for i in range(n % PARTS):
    sizes[i] += 1

offsets = []
p = 0
for s in sizes:
    offsets.append((p, p + s))
    p += s

def decrypt_chunk(enc_chunk, key):
    result = []
    for i, x in enumerate(enc_chunk):
        v = ((x ^ key) - i) & 255
        result.append(v)
    return ''.join(chr(v) for v in result)

k0 = enc[0] ^ ord('C')
part0 = decrypt_chunk(enc[offsets[0][0]:offsets[0][1]], k0)

k3 = None
for k in range(KEY_MIN, KEY_MAX + 1):
    d = decrypt_chunk(enc[offsets[3][0]:offsets[3][1]], k)
    if d.endswith('}'):
        if k3 is None:
            k3 = k

CTF_CHARS = set(string.ascii_letters + string.digits + '_{}')

candidates1 = {}
candidates2 = {}

for k in range(KEY_MIN, KEY_MAX + 1):
    d1 = decrypt_chunk(enc[offsets[1][0]:offsets[1][1]], k)
    d2 = decrypt_chunk(enc[offsets[2][0]:offsets[2][1]], k)
    if all(c in CTF_CHARS for c in d1):
        candidates1[k] = d1
    if all(c in CTF_CHARS for c in d2):
        candidates2[k] = d2

results = []
for k1, p1 in candidates1.items():
    for k2, p2 in candidates2.items():
        full_flag = part0 + p1 + p2 + decrypt_chunk(enc[offsets[3][0]:offsets[3][1]], k3)
        score = sum(1 for c in full_flag if c in string.ascii_letters + string.digits + '_{}')
        results.append((score, k1, k2, full_flag))

results.sort(reverse=True)

if results:
    _, k1, k2, best = results[0]
    print(best)
