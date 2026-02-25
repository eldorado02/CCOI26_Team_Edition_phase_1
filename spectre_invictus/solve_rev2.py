#!/usr/bin/env python3
"""
CyberCup 2026 - Reverse Engineering 2: Spectre Invictus
Solver script

Binary: rev2/chall (ELF 64-bit, not stripped, debug info, No PIE)
Flag:   CCOI26{elf_s3ct10n_h4ck_inv1ctus_5p3ctr3_0c34n}

Solution overview:
  1. Binary has ptrace anti-debug, a decoy flag in .rodata, and ghost functions
  2. Symbol names encode a key: sym_4b33595f_ → K3Y_, etc. → K3Y_0C34N_1ND1NE
  3. Real payload hidden in a PT_NOTE segment (offset 0x4f13) not mapped to any section
     → "The truth lies between the sections."
  4. PT_NOTE contents: magic "OCOI" + 64-byte length + 64-char base64 string + 4-byte checksum
  5. Base64 decodes to 47-byte XOR ciphertext
  6. Decryption key derived via known-plaintext attack (flag prefix CCOI26{ and suffix })
     confirmed by cross-validating multiple positions against "elf_s3cti0n_h4ck_inv1ctus_..."
"""

import base64
import struct

BINARY_PATH = "chall"

with open(BINARY_PATH, "rb") as f:
    data = f.read()

print("[*] Locating hidden PT_NOTE segment...")

# Parse ELF program headers to find PT_NOTE not mapped to any section
# Program header table offset is at ELF header offset 0x20 (8 bytes), n headers at 0x38
e_phoff  = int.from_bytes(data[0x20:0x28], 'little')
e_phentsize = int.from_bytes(data[0x36:0x38], 'little')
e_phnum  = int.from_bytes(data[0x38:0x3a], 'little')

PT_NOTE = 4
hidden_offset = None

for i in range(e_phnum):
    ph = data[e_phoff + i * e_phentsize : e_phoff + (i + 1) * e_phentsize]
    p_type    = int.from_bytes(ph[0:4],  'little')
    p_flags   = int.from_bytes(ph[4:8],  'little')
    p_offset  = int.from_bytes(ph[8:16], 'little')
    p_vaddr   = int.from_bytes(ph[16:24],'little')
    p_filesz  = int.from_bytes(ph[32:40],'little')

    if p_type == PT_NOTE:
        # The suspicious PT_NOTE has p_vaddr == p_offset (not a normal loaded address)
        if p_vaddr == p_offset and p_offset > 0x4000:
            print(f"    Found suspicious PT_NOTE at file offset 0x{p_offset:x}, size 0x{p_filesz:x}")
            hidden_offset = p_offset
            hidden_size   = p_filesz
            break

if hidden_offset is None:
    # Fallback: hardcoded offset from analysis
    hidden_offset = 0x4f13
    hidden_size   = 0x4c

raw = data[hidden_offset : hidden_offset + hidden_size]

# Parse custom format: magic(4) + length(4 LE) + base64(length bytes) + checksum(4)
magic  = raw[:4]
length = int.from_bytes(raw[4:8], 'little')
b64_payload = raw[8 : 8 + length]
checksum    = raw[8 + length : 8 + length + 4]

print(f"    Magic:    {magic.decode()!r}")
print(f"    Length:   {length}")
print(f"    Checksum: {checksum.hex()}")

ciphertext = base64.b64decode(b64_payload)
print(f"\n[*] Ciphertext ({len(ciphertext)} bytes): {ciphertext.hex()}")

# ------------------------------------------------------------------
# Key derivation via known-plaintext attack:
#   flag starts with CCOI26{ → key[0..6] = ct[0..6] XOR "CCOI26{"
#   flag ends   with }       → key[14]   = ct[46]   XOR '}'
#   "s3cti0n" at positions 11-17 → key[11..13,15]
#   "_inv1ctus" at positions 23-31 → key[7..10,15]
# ------------------------------------------------------------------
key = bytes([
    0xfa,  # key[0]  = ct[0]  XOR 'C'
    0x77,  # key[1]  = ct[1]  XOR 'C'
    0xe5,  # key[2]  = ct[2]  XOR 'O'
    0x60,  # key[3]  = ct[3]  XOR 'I'
    0x98,  # key[4]  = ct[4]  XOR '2'
    0xaa,  # key[5]  = ct[5]  XOR '6'   ← = sym_4b33595f_ value
    0x45,  # key[6]  = ct[6]  XOR '{'   ← = 'E' (last char of K3Y_0C34N_1ND1NE)
    0x10,  # key[7]  = ct[23] XOR '_'    (from _inv1ctus at pos 23)
    0x8e,  # key[8]  = ct[24] XOR 'i'    (from inv1ctus at pos 24)
    0x4b,  # key[9]  = ct[25] XOR 'n'    (cross-validated at pos 9 and 25)
    0xc8,  # key[10] = ct[26] XOR 'v'
    0x6a,  # key[11] = ct[11] XOR 's'  = ct[27] XOR '1'  (double-confirmed)
    0xd4,  # key[12] = ct[12] XOR '3'  = ct[28] XOR 'c'  (double-confirmed)
    0xde,  # key[13] = ct[13] XOR 'c'  = ct[29] XOR 't'  (double-confirmed)
    0xdc,  # key[14] = ct[46] XOR '}'
    0xd1,  # key[15] = ct[31] XOR 's'
])
print(f"\n[*] Derived XOR key (16 bytes): {key.hex()}")

# Decrypt
flag_bytes = bytes(ciphertext[i] ^ key[i % 16] for i in range(len(ciphertext)))
flag = flag_bytes.decode()

print(f"\n[+] FLAG: {flag}")

# Sanity checks
assert flag.startswith("CCOI26{"), "Flag doesn't start with CCOI26{"
assert flag.endswith("}"),         "Flag doesn't end with }"
assert all(32 <= b < 127 for b in flag_bytes), "Flag has non-printable bytes"
print("[+] All checks passed!")
