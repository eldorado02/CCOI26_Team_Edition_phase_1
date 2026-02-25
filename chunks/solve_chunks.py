from pathlib import Path
import string

# === Load ciphertext ===
enc = list(Path("challenge.bin").read_bytes())
n = len(enc)  # 34

PARTS = 4
KEY_MIN = 1
KEY_MAX = 80

# === Reconstruct chunk sizes ===
sizes = [n // PARTS] * PARTS
for i in range(n % PARTS):
    sizes[i] += 1
# sizes = [9, 9, 8, 8] for n=34

print(f"[*] Ciphertext length : {n}")
print(f"[*] Chunk sizes       : {sizes}")
print(f"[*] Hex               : {bytes(enc).hex()}")
print()

# Build chunk offsets
offsets = []
p = 0
for s in sizes:
    offsets.append((p, p + s))
    p += s

# === Decrypt function ===
def decrypt_chunk(enc_chunk, key):
    result = []
    for i, x in enumerate(enc_chunk):
        v = ((x ^ key) - i) & 255
        result.append(v)
    return result

def is_printable(vals):
    return all(chr(v) in string.printable for v in vals)

# === Part 0: known plaintext attack ===
# Flag starts with CCOI26{
known_prefix = "CCOI26{"
chunk0 = enc[offsets[0][0]:offsets[0][1]]
# Derive key from first byte: x = (v + 0) ^ k => k = x ^ v
k0 = chunk0[0] ^ ord(known_prefix[0])
print(f"[*] Key part 0 (derived from known prefix 'CCOI26{{'): {k0}")

# Verify against full known prefix
dec0 = decrypt_chunk(chunk0, k0)
dec0_str = ''.join(chr(v) for v in dec0)
print(f"[*] Part 0 decrypted: {dec0_str}")
print()

# === Parts 1, 2, 3: brute-force ===
found_keys = [k0, None, None, None]
found_parts = [dec0_str, None, None, None]

for part_idx in range(1, PARTS):
    start, end = offsets[part_idx]
    chunk = enc[start:end]
    print(f"[*] Brute-forcing part {part_idx} (bytes {start}-{end-1})...")
    candidates = []
    for k in range(KEY_MIN, KEY_MAX + 1):
        dec = decrypt_chunk(chunk, k)
        if is_printable(dec):
            s = ''.join(chr(v) for v in dec)
            candidates.append((k, s))
    for k, s in candidates:
        print(f"    key={k:2d} -> {s}")
    if candidates:
        # Pick best: prefer key that gives valid flag chars
        printable_ascii = [(k, s) for k, s in candidates if all(32 <= ord(c) <= 126 for c in s)]
        if printable_ascii:
            found_keys[part_idx] = printable_ascii[0][0]
            found_parts[part_idx] = printable_ascii[0][1]
    print()

# === Reconstruct flag ===
print("=" * 50)
print("[*] All candidates assembled:")
flag = ''.join(p for p in found_parts if p is not None)
print(f"    FLAG = {flag}")
print(f"    Keys = {found_keys}")
