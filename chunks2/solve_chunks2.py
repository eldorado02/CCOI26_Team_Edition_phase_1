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

starts = [0]
for s in sizes[:-1]:
    starts.append(starts[-1] + s)

def decrypt_chunk(enc_chunk, key):
    plaintext = []
    for i, byte in enumerate(enc_chunk):
        plaintext.append(((byte ^ key) - i) & 255)
    return bytes(plaintext)

def find_candidates_for_chunk(chunk):
    candidates = []
    for k in range(KEY_MIN, KEY_MAX + 1):
        dec = decrypt_chunk(chunk, k)
        try:
            s = dec.decode()
            if all(c in string.printable for c in s):
                candidates.append((k, dec))
        except:
            pass
    return candidates

CTF_CHARS = set(string.ascii_letters + string.digits + '_{}')

def score(b):
    s = bytes(b).decode(errors='replace')
    return sum(1 for c in s if c in string.ascii_letters + string.digits + '_{}')

known_prefix = b'CCOI26{'
k0 = enc[0] ^ known_prefix[0]
chunk0 = enc[starts[0]:starts[0]+sizes[0]]
part0 = decrypt_chunk(chunk0, k0)

chunk3 = enc[starts[3]:starts[3]+sizes[3]]
cand3 = find_candidates_for_chunk(chunk3)
k3_candidates = [(k, p) for k, p in cand3 if p.endswith(b'}')]
if k3_candidates:
    k3, part3 = k3_candidates[0]
else:
    k3, part3 = None, None

chunk1 = enc[starts[1]:starts[1]+sizes[1]]
chunk2 = enc[starts[2]:starts[2]+sizes[2]]

cand1 = find_candidates_for_chunk(chunk1)
cand2 = find_candidates_for_chunk(chunk2)

best_score = 0
best_combo = None

for k1, p1 in cand1:
    for k2, p2 in cand2:
        full = part0 + p1 + p2 + part3
        s = score(full)
        if s > best_score:
            best_score = s
            best_combo = full

if best_combo:
    print(best_combo.decode(errors='replace'))
