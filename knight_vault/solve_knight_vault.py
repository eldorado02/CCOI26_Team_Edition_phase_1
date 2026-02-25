import struct

# ════════════════════════════════════════
#  Constants extracted from knight_vault
# ════════════════════════════════════════

TARGET = bytes.fromhex(
    "802d77ca6dfd3e05fb15cfd44b75c4b9"   # chunk 0 (esi=0)
    "dfea37290ad57a5aaeb0ed6165b3aa2e"   # chunk 1 (esi=1)
)

ROUND_KEYS_RAW = bytes.fromhex(
    "0206061a127e6e1a222626eaf2cedeca"
    "1616726a1e2e222ad6f6f2dace3e425a"
    "761a223e2edaf2f6d6cac24e5e4a7256"
    "222adeeef2cac6c6425a4e7e525aa6a6"
    "d2fecedac246464a726e5eaaa2a6e6fa"
    "dece424a5676725aaebea29af6f6928a"
)
ROUND_KEYS = [list(ROUND_KEYS_RAW[i*16:(i+1)*16]) for i in range(6)]

SBOX = list(bytes.fromhex(
    "637c777bf26b6fc53001672bfed7ab76ca82c97dfa5947f0add4a2af9ca472c0"
    "b7fd9326363ff7cc34a5e5f171d8311504c723c31896059a071280e2eb27b275"
    "09832c1a1b6e5aa0523bd6b329e32f8453d100ed20fcb15b6acbbe394a4c58cf"
    "d0efaafb434d338545f9027f503c9fa851a3408f929d38f5bcb6da2110fff3d2"
    "cd0c13ec5f974417c4a77e3d645d197360814fdc222a908846eeb814de5e0bdb"
    "e0323a0a4906245cc2d3ac629195e479e7c8376d8dd54ea96c56f4ea657aae08"
    "ba78252e1ca6b4c6e8dd741f4bbd8b8a703eb5664803f60e613557b986c11d9e"
    "e1f8981169d98e949b1e87e9ce5528df8ca1890dbfe6426841992d0fb054bb16"
))

PERM   = [0x00,0x05,0x0a,0x0f,0x04,0x09,0x0e,0x03,
          0x08,0x0d,0x02,0x07,0x0c,0x01,0x06,0x0b]

OFFSET = [0x00,0x07,0x0e,0x15,0x1c,0x23,0x2a,0x31,
          0x38,0x3f,0x46,0x4d,0x54,0x5b,0x62,0x69]

EXTRA1 = list(bytes.fromhex("85bbbda7ad4b455f656b0d077d7b656f"))
EXTRA2 = list(bytes.fromhex("000306090c0f1215181b1e2124272a2d"))


# ════════════════════════════════════════
#  Precompute inverse tables
# ════════════════════════════════════════

# Inverse S-box
INV_SBOX = [0] * 256
for i, v in enumerate(SBOX):
    INV_SBOX[v] = i

# Inverse permutation: inv_perm[perm[i]] = i
INV_PERM = [0] * 16
for i, p in enumerate(PERM):
    INV_PERM[p] = i

def rol8(b, n):
    n &= 7
    return ((b << n) | (b >> (8 - n))) & 0xFF

def ror8(b, n):
    return rol8(b, 8 - (n & 7))


# ════════════════════════════════════════
#  Forward cipher (for verification)
# ════════════════════════════════════════

def encrypt_block(block, esi):
    data = list(block)
    ebp = 0 if esi == 0 else 61
    r12 = 0 if esi == 0 else 41

    for r in range(6):
        rk = ROUND_KEYS[r]
        # Step a: XOR with (ebp + offset) ^ round_key
        for i in range(16):
            data[i] = ((ebp + OFFSET[i]) & 0xFF) ^ rk[i] ^ data[i]
        # Step b: S-box
        data = [SBOX[b] for b in data]
        # Step c: Permutation  output[i] = input[perm[i]]
        data = [data[PERM[i]] for i in range(16)]
        # Step d: Cumulative XOR (data[0] unchanged, data[i] = XOR(data[0..i]))
        dl = data[0]
        for i in range(1, 16):
            dl = dl ^ data[i]
            data[i] = dl
        # Step e: Rotation
        for i in range(16):
            data[i] = rol8(data[i], (i % 7) + 1)
        ebp = (ebp + 11) & 0xFF

    # Final XOR
    for i in range(16):
        data[i] = ((r12 + EXTRA2[i]) & 0xFF) ^ EXTRA1[i] ^ data[i]

    return bytes(data)


# ════════════════════════════════════════
#  Inverse cipher
# ════════════════════════════════════════

def decrypt_block(block, esi):
    data = list(block)
    r12  = 0 if esi == 0 else 41
    ebp_start = 0 if esi == 0 else 61

    # Undo final XOR (self-inverse)
    for i in range(16):
        data[i] = ((r12 + EXTRA2[i]) & 0xFF) ^ EXTRA1[i] ^ data[i]

    # Compute ebp values for all rounds
    ebp_vals = [(ebp_start + 11 * r) & 0xFF for r in range(6)]

    # Undo rounds in REVERSE order
    for r in range(5, -1, -1):
        rk  = ROUND_KEYS[r]
        ebp = ebp_vals[r]

        # Undo step e: rotation  →  ror
        for i in range(16):
            data[i] = ror8(data[i], (i % 7) + 1)

        # Undo step d: cumulative XOR
        # Forward: data[i] = XOR(orig[0..i])  orig[0] unchanged
        # Inverse: orig[0] = data[0]; orig[i] = data[i] ^ data[i-1]
        for i in range(15, 0, -1):
            data[i] = data[i] ^ data[i - 1]

        # Undo step c: inverse permutation  data[perm[i]] = old[i]
        tmp = data[:]
        for i in range(16):
            data[PERM[i]] = tmp[i]

        # Undo step b: inverse S-box
        data = [INV_SBOX[b] for b in data]

        # Undo step a: same XOR (self-inverse)
        for i in range(16):
            data[i] = ((ebp + OFFSET[i]) & 0xFF) ^ rk[i] ^ data[i]

    return bytes(data)


# ════════════════════════════════════════
#  Main
# ════════════════════════════════════════

chunk0 = TARGET[:16]
chunk1 = TARGET[16:]

plain0 = decrypt_block(chunk0, 0)
plain1 = decrypt_block(chunk1, 1)
flag = plain0 + plain1

print(f"[*] Chunk 0 decrypted : {plain0.hex()} | {plain0}")
print(f"[*] Chunk 1 decrypted : {plain1.hex()} | {plain1}")
print(f"\n[+] FLAG: {flag.decode('latin-1')}")

# Self-test: re-encrypt and compare to target
enc0 = encrypt_block(plain0, 0)
enc1 = encrypt_block(plain1, 1)
ok = (enc0 == chunk0 and enc1 == chunk1)
print(f"\n[*] Self-test (re-encrypt == target): {'PASS ✓' if ok else 'FAIL ✗'}")
if not ok:
    print(f"    enc0: {enc0.hex()}  expected: {chunk0.hex()}")
    print(f"    enc1: {enc1.hex()}  expected: {chunk1.hex()}")
