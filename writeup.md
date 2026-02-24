# Breaking Cisco Packet Tracer's .pka Password Protection - A Full Reverse Engineering Walkthrough

Cisco Packet Tracer's Activity Wizard lets instructors lock `.pka` lab files behind a password. Students can't view the answer network or grading rubric without it. I decided to take that apart - completely.

What started as "can I bypass this password prompt?" turned into a 5-hour deep dive through Twofish encryption, custom obfuscation layers, IPC bridges, embedded JavaScript engines, and a salted MD5 scheme with a hardcoded key buried in the binary.

Here's everything I found.

> **Disclaimer:** This research is intended for educational purposes only. The Activity Wizard password is designed to prevent students from casually viewing lab answers - not to protect sensitive or personal data. The techniques described here are shared to advance understanding of reverse engineering and cryptographic analysis. Use responsibly and only on files you have legitimate access to.

---

## The Target

**Binary:** Cisco Packet Tracer 9.0 (Windows x64)  
**File format:** `.pka` (Activity Wizard labs)  
**Tools:** Ghidra, x64dbg, Python 3  
**Goal:** Bypass or remove the Activity Wizard password on any `.pka` file

---

## Part 1 - Understanding the .pka File Format

A `.pka` file is not a ZIP. It's not plain XML. Opening it in a hex editor reveals nothing recognizable - the entire file is encrypted.

Thanks to prior work by the [Unpacket](https://github.com/Punkcake21/Unpacket) project, the encryption pipeline was already documented. The file goes through four layers:

### Layer 1 - Stage 1 Obfuscation (Reverse + XOR)

The raw bytes are reversed and XORed with a position-dependent mask:

```python
result[i] = data[L-1-i] ^ ((L - i*L) & 0xFF)
```

The mask depends only on the file length `L` and the index - no secret key. This is obfuscation, not encryption.

### Layer 2 - Twofish-EAX Authenticated Encryption

The real crypto layer. Twofish in EAX mode (an AEAD scheme combining CMAC and CTR mode). The key and IV are **hardcoded** in the binary:

```
Key: 0x89 repeated 16 times
IV:  0x10 repeated 16 times
```

The 16-byte authentication tag is appended to the ciphertext.

### Layer 3 - Stage 2 Obfuscation (Positional XOR)

Another XOR pass after decryption:

```python
result[i] = data[i] ^ ((L - i) & 0xFF)
```

This one is self-inverse - the same formula encrypts and decrypts.

### Layer 4 - Qt Compression

The innermost layer is Qt's `qCompress` format: a 4-byte big-endian uncompressed size prefix followed by a standard zlib stream.

After peeling all four layers, you get clean XML - the full Packet Tracer topology with every device, cable, configuration, and activity setting.

---

## Part 2 - Finding the Password

Inside the decrypted XML, near the very end of the file, sits the `ACTIVITY` tag:

```xml
<ACTIVITY PASS="FE0B83A6803E208182FCBA1F03183DA3"
          VALUE="efbfbdefbfbd01efbfbd79392311efbfbdefbfbdefbfbd02"
          ENABLED="no" ...>
```

The `PASS` attribute holds a 32-character hex string - clearly a 128-bit hash. My first assumption: standard MD5.

**Wrong.**

I tested `MD5("cisco")`, `MD5("password")`, every common encoding variant. None matched. Online rainbow tables (CrackStation, hashes.com) returned nothing either.

---

## Part 3 - The Known-Plaintext Attack

Since cracking the hash blind wasn't working, I created `.pka` files in Packet Tracer with known passwords and extracted the hashes:

| Password   | PASS Hash                          |
|------------|-------------------------------------|
| `a`        | `4EE1BDC79FE5B241B2C5680E0032E3DF` |
| `cisco`    | `4447C410290BC95F98FF11CDC4C59B59` |
| `test`     | `AB85C14EED49DDE1C6644823F5D45A13` |
| `password` | `83F7F5CC57C777ED925B27B4420D1674` |

Standard `MD5("cisco")` didn't match. This told me something extra was involved in the hashing - but I didn't yet know what.

I tested dozens of alternatives: MD4, SHA-family truncations, BLAKE2, HMAC-MD5, various salts and encodings. Nothing matched. It turned out to be standard MD5 all along - just with a hardcoded salt prepended to the password before hashing. But I wouldn't discover that until tracing the actual code.

---

## Part 4 - Reversing the Hash Function in Ghidra

Time to go to the source. I loaded the Packet Tracer binary in Ghidra (base `0x140000000`) and traced the password verification path.

### The Comparison Point

The password check lives in `FUN_142e15010`, a massive function (~155K chars of disassembly). At address `0x142e16782`, there's a critical `CALL` to a case-insensitive string comparison. Two values are compared: the stored `PASS` hash from the file, and a freshly computed hash from the entered password.

### Tracing Backward

Just before the comparison, the code calls `FUN_142b4eef0` - a function that takes three parameters:

```
RCX = output buffer
RDX = pointer to salt (std::string at object + 0x1E0)
R8  = pointer to password (std::string)
```

### Inside the Hash Function

Decompiling `FUN_142b4eef0` revealed the algorithm:

```c
MD5_Init(ctx);
MD5_Update(ctx, salt->data(), salt->size());     // salt first
MD5_Update(ctx, password->data(), password->size()); // then password
MD5_Final(result, ctx);
// convert 16 bytes to uppercase hex string
```

I confirmed it was MD5 by checking the initialization function (`FUN_14096f9e0`), which sets the classic MD5 constants:

```
0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476
```

The algorithm is **MD5(salt + password)**, output as uppercase hex.

---

## Part 5 - Extracting the Salt

The salt comes from offset `0x1E0` in the activity object. But what bytes does it actually contain?

### Dynamic Analysis with x64dbg

I set a breakpoint on the MD5 update function (`FUN_14096faa0`, offset `0x96FAA0` from module base). On the first hit:

- **RDX** pointed to the salt data
- **R8** held the salt length

The memory dump revealed 12 bytes:

```
C0 A8 01 BE 79 39 23 11 A0 9B C6 02
```

### Verification

```python
import hashlib
salt = bytes.fromhex('C0A801BE79392311A09BC602')
hashlib.md5(salt + b'cisco').hexdigest().upper()
# '4447C410290BC95F98FF11CDC4C59B59' ✓
```

All four known password/hash pairs matched perfectly.

### Is the Salt Per-File?

I searched the Packet Tracer binary for these exact bytes and found them at **5 locations**, including one preceded by the ASCII string `"VALUE"`:

```
Offset 0x4DC2B70: "VALUE" 00000000 C0A801BE79392311A09BC602 00000000 "TIME"
```

The salt is a **hardcoded default** in the binary. It's the same for every `.pka` file (at least within a given PT version).

> **Note on the VALUE attribute:** The `VALUE` XML attribute is a mangled UTF-8 copy of this salt - bytes above `0x7F` get replaced with `U+FFFD` during XML serialization, making it lossy and unrecoverable from the file alone. It doesn't matter though, since the binary always uses the same hardcoded value regardless.

---

## Part 6 - The Complete Bypass

With the algorithm fully understood, the bypass is straightforward:

1. Decrypt the `.pka` file (Twofish-EAX pipeline)
2. Find the `PASS` attribute in the XML
3. Compute `MD5(salt + new_password)` for any password you choose
4. Replace the hash
5. Re-encrypt

I built a **standalone Python script** (~270 lines, zero dependencies) that does this automatically:

```bash
# Replace password with 'cisco'
python pka_bypass.py locked_lab.pka -p cisco

# Just inspect the current hash without modifying
python pka_bypass.py locked_lab.pka --info
```

The script includes full Twofish, CMAC, CTR, and EAX implementations inline - no pip installs needed. It also includes proper error handling for corrupt files, unsupported versions, and invalid inputs.

### For Hash Cracking

If you want to recover the original password instead of replacing it, use hashcat with salted MD5:

```bash
hashcat -m 20 --hex-salt HASH:c0a801be79392311a09bc602 wordlist.txt
```

---

## Summary of Findings

| Component | Detail |
|-----------|--------|
| File encryption | Twofish-128 in EAX mode |
| Encryption key | `0x89` repeated 16 bytes (hardcoded) |
| Encryption IV | `0x10` repeated 16 bytes (hardcoded) |
| Obfuscation | Two XOR layers (reverse+positional, positional) |
| Compression | Qt `qCompress` (zlib + 4-byte BE header) |
| Password hash | `MD5(salt + password)`, uppercase hex |
| Salt | `C0A801BE79392311A09BC602` (12 bytes, hardcoded) |
| Hash storage | `PASS` attribute in `<ACTIVITY>` XML tag |

---

## Takeaways

The entire `.pka` protection model relies on **security through obscurity**. The encryption key, IV, and hash salt are all hardcoded in the binary. The dual XOR obfuscation layers add complexity for casual analysis but provide zero cryptographic strength.

For Cisco, this is likely an acceptable trade-off - the Activity Wizard password is meant to prevent students from casually peeking at answers, not to withstand a determined reverse engineering effort. But it's a good reminder: hardcoded keys are not security.

---

## Credits

- **Unpacket** ([Punkcake21](https://github.com/Punkcake21/Unpacket)) - reversed the file encryption pipeline (Twofish-EAX + obfuscation + compression)
- **Claude AI**

*Tools used: Ghidra, x64dbg, Python 3, and a lot of coffee.*
