from pathlib import Path
import string

enc = list(Path("challenge_easy.bin").read_bytes())
print(f"[*] Ciphertext ({len(enc)} bytes): {bytes(enc).hex()}")
print()

def decrypt(data, key):
    return bytes(((c ^ key) - 2) & 255 for c in data)

k = enc[0] ^ 69
print(f"[*] KEY derived from known plaintext 'C': {k}")
print()

flag = decrypt(enc, k)
flag_str = flag.decode('latin-1')
print(f"[+] FLAG: {flag_str}")

print("\n[*] Brute-force verification (all 80 keys):")
for key in range(1, 81):
    d = decrypt(enc, key)
    s = d.decode('latin-1')
    if s.startswith('CCOI26{') and s.endswith('}'):
        print(f"    key={key:2d} -> {s}  *** MATCH ***")
        break
    elif all(chr(b) in string.printable for b in d):
        print(f"    key={key:2d} -> {s}")
