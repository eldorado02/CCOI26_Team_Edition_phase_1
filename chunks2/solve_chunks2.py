from pathlib import Path
import hashlib
import string

data = Path("challenge.bin").read_bytes()

# Parse header
assert data[:4] == b"CHK2"
PARTS = data[4]
sizes = list(data[5:5+PARTS])
perm  = list(data[5+PARTS:5+2*PARTS])
salts = list(data[5+2*PARTS:5+3*PARTS])
ivs   = list(data[5+3*PARTS:5+4*PARTS])

print(f"PARTS={PARTS}, sizes={sizes}, perm={perm}")
print(f"salts={salts}, ivs={ivs}")

HEADER = 5 + 4*PARTS  # 21 bytes

# Extract enc_chunks in perm order, put back into original part indices
enc_by_part = {}
offset = HEADER
for perm_idx, part_idx in enumerate(perm):
    sz = sizes[part_idx]
    enc_by_part[part_idx] = data[offset:offset+sz]
    offset += sz

# Rotation helpers
def rotl3(x): return ((x << 3) | (x >> 5)) & 255
def rotr3(x): return ((x >> 3) | (x << 5)) & 255

def decrypt_chunk(enc_chunk, key, salt, part_idx, iv):
    prev = iv
    out = []
    for i, c in enumerate(enc_chunk):
        x = (c - (part_idx + 1) * 7) & 255
        x ^= prev
        ks = hashlib.sha256(bytes([key, salt, part_idx, i])).digest()[0]
        x ^= ks
        x = rotr3(x)
        v = (x - i) & 255
        out.append(v)
        prev = c
    return bytes(out)

# Known plaintext: FLAG starts with "CCOI26{"
KNOWN = b"CCOI26{"

def find_key_kpa(part_idx):
    enc = enc_by_part[part_idx]
    salt = salts[part_idx]
    iv = ivs[part_idx]
    for k in range(1, 81):
        dec = decrypt_chunk(enc, k, salt, part_idx, iv)
        if dec[:len(KNOWN)] == KNOWN:
            return k
    return None

def find_key_closing_brace(part_idx):
    enc = enc_by_part[part_idx]
    salt = salts[part_idx]
    iv = ivs[part_idx]
    candidates = []
    for k in range(1, 81):
        dec = decrypt_chunk(enc, k, salt, part_idx, iv)
        if dec[-1] == ord('}'):
            candidates.append((k, dec))
    return candidates

CTF_CHARS = set(string.ascii_letters + string.digits + '_{}!@#$%^&*()-+=[]|;:,.<>?/ ')

def score(b):
    s = bytes(b).decode(errors='replace')
    return sum(1 for c in s if c in string.ascii_letters + string.digits + '_{}')

# --- Part 0: KPA ---
k0 = find_key_kpa(0)
if k0:
    print(f"k0 (KPA) = {k0}")
    p0 = decrypt_chunk(enc_by_part[0], k0, salts[0], 0, ivs[0]).decode(errors='replace')
    print(f"  chunk0 = {repr(p0)}")
else:
    print("KPA failed for part 0 — trying all")
    k0 = None

# --- Part 3: closing brace ---
cands3 = find_key_closing_brace(3)
print(f"Part 3 candidates (ends with '}}'):")
for k, dec in cands3:
    print(f"  k={k} → {repr(dec.decode(errors='replace'))}")

# --- Parts 1 & 2: score ---
results = {}
for part_idx in range(PARTS):
    enc = enc_by_part[part_idx]
    salt = salts[part_idx]
    iv = ivs[part_idx]
    best_k, best_dec, best_score = None, None, -1
    for k in range(1, 81):
        dec = decrypt_chunk(enc, k, salt, part_idx, iv)
        s = score(dec)
        if s > best_score:
            best_score, best_k, best_dec = s, k, dec
    results[part_idx] = (best_k, best_dec)
    print(f"Part {part_idx}: k={best_k}, score={best_score}/{sizes[part_idx]}, → {repr(best_dec.decode(errors='replace'))}")

flag = b"".join(results[i][1] for i in range(PARTS))
print(f"\nFLAG: {flag.decode(errors='replace')}")
