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
        if p_vaddr == p_offset and p_offset > 0x4000:
            print(f"    Found suspicious PT_NOTE at file offset 0x{p_offset:x}, size 0x{p_filesz:x}")
            hidden_offset = p_offset
            hidden_size   = p_filesz
            break

if hidden_offset is None:
    hidden_offset = 0x4f13
    hidden_size   = 0x4c

raw = data[hidden_offset : hidden_offset + hidden_size]

magic  = raw[:4]
length = int.from_bytes(raw[4:8], 'little')
b64_payload = raw[8 : 8 + length]
checksum    = raw[8 + length : 8 + length + 4]

print(f"    Magic:    {magic.decode()!r}")
print(f"    Length:   {length}")
print(f"    Checksum: {checksum.hex()}")

ciphertext = base64.b64decode(b64_payload)
print(f"\n[*] Ciphertext ({len(ciphertext)} bytes): {ciphertext.hex()}")

key = bytes([
    0xfa,
    0x77,
    0xe5,
    0x60,
    0x98,
    0xaa,
    0x45,
    0x10,
    0x8e,
    0x4b,
    0xc8,
    0x6a,
    0xd4,
    0xde,
    0xdc,
    0xd1,
])
print(f"\n[*] Derived XOR key (16 bytes): {key.hex()}")

flag_bytes = bytes(ciphertext[i] ^ key[i % 16] for i in range(len(ciphertext)))
flag = flag_bytes.decode()

print(f"\n[+] FLAG: {flag}")

assert flag.startswith("CCOI26{"), "Flag doesn't start with CCOI26{"
assert flag.endswith("}"),         "Flag doesn't end with }"
assert all(32 <= b < 127 for b in flag_bytes), "Flag has non-printable bytes"
print("[+] All checks passed!")
