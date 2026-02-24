#!/usr/bin/env python3

import argparse, hashlib, os, re, struct, sys, zlib

# ─── Twofish block cipher (pure Python, based on Bjorn Edstrom's implementation) ─────────────────

def _rotr32(x, n): return (x >> n) | ((x << (32 - n)) & 0xFFFFFFFF)
def _rotl32(x, n): return ((x << n) & 0xFFFFFFFF) | (x >> (32 - n))
def _byte(x, n):   return (x >> (8 * n)) & 0xFF

_tab_5b = [0, 90, 180, 238]
_tab_ef  = [0, 238, 180, 90]
_ror4    = [0, 8, 1, 9, 2, 10, 3, 11, 4, 12, 5, 13, 6, 14, 7, 15]
_ashx    = [0, 9, 2, 11, 4, 13, 6, 15, 8, 1, 10, 3, 12, 5, 14, 7]

_qt0 = [[8,1,7,13,6,15,3,2,0,11,5,9,14,12,10,4],  [2,8,11,13,15,7,6,14,3,1,9,4,0,10,12,5]]
_qt1 = [[14,12,11,8,1,2,3,5,15,4,10,6,7,0,9,13],  [1,14,2,11,4,12,3,7,6,13,10,5,15,9,0,8]]
_qt2 = [[11,10,5,14,6,13,9,0,12,8,15,3,2,4,7,1],  [4,12,7,5,1,6,9,10,0,14,13,8,2,11,3,15]]
_qt3 = [[13,7,15,4,1,2,6,14,9,11,3,0,8,5,12,10],  [11,9,5,1,12,3,13,14,6,4,7,15,2,0,8,10]]

def _qp(n, x):
    a0 = x >> 4;  b0 = x & 15
    a1 = a0 ^ b0; b1 = _ror4[b0] ^ _ashx[a0]
    a2 = _qt0[n][a1]; b2 = _qt1[n][b1]
    a3 = a2 ^ b2;     b3 = _ror4[b2] ^ _ashx[a2]
    return (_qt3[n][b3] << 4) | _qt2[n][a3]

class _TWI:
    def __init__(self):
        self.k_len  = 0
        self.l_key  = [0] * 40
        self.s_key  = [0] * 4
        self.q_tab  = [[0]*256, [0]*256]
        self.m_tab  = [[0]*256, [0]*256, [0]*256, [0]*256]
        self.mk_tab = [[0]*256, [0]*256, [0]*256, [0]*256]

def _gen_qtab(p):
    for i in range(256):
        p.q_tab[0][i] = _qp(0, i)
        p.q_tab[1][i] = _qp(1, i)

def _gen_mtab(p):
    for i in range(256):
        f01 = p.q_tab[1][i]
        f5b = f01 ^ (f01 >> 2) ^ _tab_5b[f01 & 3]
        fef = f01 ^ (f01 >> 1) ^ (f01 >> 2) ^ _tab_ef[f01 & 3]
        p.m_tab[0][i] = f01 + (f5b << 8) + (fef << 16) + (fef << 24)
        p.m_tab[2][i] = f5b + (fef << 8) + (f01 << 16) + (fef << 24)
        f01 = p.q_tab[0][i]
        f5b = f01 ^ (f01 >> 2) ^ _tab_5b[f01 & 3]
        fef = f01 ^ (f01 >> 1) ^ (f01 >> 2) ^ _tab_ef[f01 & 3]
        p.m_tab[1][i] = fef + (fef << 8) + (f5b << 16) + (f01 << 24)
        p.m_tab[3][i] = f5b + (f01 << 8) + (fef << 16) + (f5b << 24)

def _gen_mk_tab(p, key):
    if p.k_len != 2:
        raise ValueError(f"Unsupported key length: k_len={p.k_len} (only 128-bit keys supported)")
    for i in range(256):
        b = i
        p.mk_tab[0][i] = p.m_tab[0][p.q_tab[0][p.q_tab[0][b] ^ _byte(key[1],0)] ^ _byte(key[0],0)]
        p.mk_tab[1][i] = p.m_tab[1][p.q_tab[0][p.q_tab[1][b] ^ _byte(key[1],1)] ^ _byte(key[0],1)]
        p.mk_tab[2][i] = p.m_tab[2][p.q_tab[1][p.q_tab[0][b] ^ _byte(key[1],2)] ^ _byte(key[0],2)]
        p.mk_tab[3][i] = p.m_tab[3][p.q_tab[1][p.q_tab[1][b] ^ _byte(key[1],3)] ^ _byte(key[0],3)]

def _h_fun(p, x, key):
    b0, b1, b2, b3 = _byte(x,0), _byte(x,1), _byte(x,2), _byte(x,3)
    if p.k_len >= 2:
        b0 = p.q_tab[0][p.q_tab[0][b0] ^ _byte(key[1],0)] ^ _byte(key[0],0)
        b1 = p.q_tab[0][p.q_tab[1][b1] ^ _byte(key[1],1)] ^ _byte(key[0],1)
        b2 = p.q_tab[1][p.q_tab[0][b2] ^ _byte(key[1],2)] ^ _byte(key[0],2)
        b3 = p.q_tab[1][p.q_tab[1][b3] ^ _byte(key[1],3)] ^ _byte(key[0],3)
    return p.m_tab[0][b0] ^ p.m_tab[1][b1] ^ p.m_tab[2][b2] ^ p.m_tab[3][b3]

def _mds_rem(p0, p1):
    for _ in range(8):
        t  = p1 >> 24
        p1 = ((p1 << 8) & 0xFFFFFFFF) | (p0 >> 24)
        p0 = (p0 << 8) & 0xFFFFFFFF
        u  = (t << 1) & 0xFFFFFFFF
        if t & 0x80: u ^= 0x14D
        p1 ^= t ^ ((u << 16) & 0xFFFFFFFF)
        u  ^= (t >> 1)
        if t & 1: u ^= 0x14D >> 1
        p1 ^= ((u << 24) & 0xFFFFFFFF) | ((u << 8) & 0xFFFFFFFF)
    return p1

def _tf_set_key(p, in_key, key_len):
    _gen_qtab(p); _gen_mtab(p)
    p.k_len = (key_len * 8) // 64
    me_key = [0]*4; mo_key = [0]*4
    for i in range(p.k_len):
        me_key[i] = in_key[i*2];    mo_key[i] = in_key[i*2+1]
        p.s_key[p.k_len - i - 1] = _mds_rem(in_key[i*2], in_key[i*2+1])
    for i in range(0, 40, 2):
        a = (0x01010101 * i) % 0x100000000
        b = (a + 0x01010101)  % 0x100000000
        a = _h_fun(p, a, me_key)
        b = _rotl32(_h_fun(p, b, mo_key), 8)
        p.l_key[i]   = (a + b) % 0x100000000
        p.l_key[i+1] = _rotl32((a + 2*b) % 0x100000000, 9)
    _gen_mk_tab(p, p.s_key)

def _tf_encrypt(p, blk):
    b = [blk[0]^p.l_key[0], blk[1]^p.l_key[1], blk[2]^p.l_key[2], blk[3]^p.l_key[3]]
    for i in range(8):
        t0 = (p.mk_tab[0][_byte(b[0],0)] ^ p.mk_tab[1][_byte(b[0],1)] ^
              p.mk_tab[2][_byte(b[0],2)] ^ p.mk_tab[3][_byte(b[0],3)])
        t1 = (p.mk_tab[0][_byte(b[1],3)] ^ p.mk_tab[1][_byte(b[1],0)] ^
              p.mk_tab[2][_byte(b[1],1)] ^ p.mk_tab[3][_byte(b[1],2)])
        b[2] = _rotr32(b[2] ^ ((t0+t1+p.l_key[4*i+8])  % 0x100000000), 1)
        b[3] = _rotl32(b[3], 1) ^ ((t0+2*t1+p.l_key[4*i+9]) % 0x100000000)
        t0 = (p.mk_tab[0][_byte(b[2],0)] ^ p.mk_tab[1][_byte(b[2],1)] ^
              p.mk_tab[2][_byte(b[2],2)] ^ p.mk_tab[3][_byte(b[2],3)])
        t1 = (p.mk_tab[0][_byte(b[3],3)] ^ p.mk_tab[1][_byte(b[3],0)] ^
              p.mk_tab[2][_byte(b[3],1)] ^ p.mk_tab[3][_byte(b[3],2)])
        b[0] = _rotr32(b[0] ^ ((t0+t1+p.l_key[4*i+10]) % 0x100000000), 1)
        b[1] = _rotl32(b[1], 1) ^ ((t0+2*t1+p.l_key[4*i+11]) % 0x100000000)
    blk[0]=b[2]^p.l_key[4]; blk[1]=b[3]^p.l_key[5]
    blk[2]=b[0]^p.l_key[6]; blk[3]=b[1]^p.l_key[7]

class _Twofish:
    def __init__(self, key):
        if len(key) not in (16, 24, 32):
            raise ValueError(f"Twofish key must be 16, 24, or 32 bytes (got {len(key)})")
        self._ctx = _TWI()
        kw = [0]*32
        for i, chunk in enumerate(key[j:j+4] for j in range(0, len(key), 4)):
            kw[i] = struct.unpack("<L", chunk)[0]
        _tf_set_key(self._ctx, kw, len(key))

    def encrypt(self, block):
        if len(block) != 16:
            raise ValueError(f"Twofish block must be 16 bytes (got {len(block)})")
        t = list(struct.unpack("<4L", block))
        _tf_encrypt(self._ctx, t)
        return struct.pack("<4L", *t)


# ─── CMAC ─────────────────────────────────────────────────────────────────────

_BS = 16

def _xor16(a, b):
    """XOR two equal-length byte strings."""
    return bytes(x ^ y for x, y in zip(a, b))

def _lshift1(s):
    """Left-shift a byte string by 1 bit (big-endian)."""
    out = bytearray(len(s)); carry = 0
    for i in range(len(s)-1, -1, -1):
        out[i] = ((s[i] << 1) & 0xFF) | carry
        carry   = (s[i] & 0x80) >> 7
    return bytes(out)

class _CMAC:
    def __init__(self, enc):
        self._enc = enc
        L = enc(bytes(_BS))
        self._K1 = _lshift1(L)
        if L[0] & 0x80:
            self._K1 = _xor16(self._K1, b'\x00'*15 + b'\x87')
        self._K2 = _lshift1(self._K1)
        if self._K1[0] & 0x80:
            self._K2 = _xor16(self._K2, b'\x00'*15 + b'\x87')

    def digest(self, data):
        if not data:
            last   = _xor16(b'\x80' + b'\x00'*15, self._K2)
            blocks = []
        else:
            blocks = [data[i:i+_BS] for i in range(0, len(data), _BS)]
            lb = blocks.pop()
            if len(lb) == _BS:
                last = _xor16(lb, self._K1)
            else:
                padded = lb + b'\x80' + b'\x00' * (_BS - len(lb) - 1)
                last   = _xor16(padded, self._K2)
        X = bytes(_BS)
        for bl in blocks:
            X = self._enc(_xor16(X, bl))
        return self._enc(_xor16(X, last))


# ─── CTR mode ─────────────────────────────────────────────────────────────────

class _CTR:
    def __init__(self, enc, iv):
        self._enc = enc
        self._ctr = bytearray(iv)

    def _inc(self):
        for i in range(_BS-1, -1, -1):
            self._ctr[i] = (self._ctr[i] + 1) & 0xFF
            if self._ctr[i]:
                break

    def process(self, data):
        out = bytearray(); off = 0
        while off < len(data):
            ks = self._enc(bytes(self._ctr)); self._inc()
            bl = data[off:off+_BS]
            out.extend(b ^ k for b, k in zip(bl, ks))
            off += _BS
        return bytes(out)


# ─── EAX mode ─────────────────────────────────────────────────────────────────

def _omac(cmac, pfx, data):
    return cmac.digest(b'\x00'*15 + bytes([pfx]) + data)

class _EAX:
    def __init__(self, enc):
        self._enc  = enc
        self._cmac = _CMAC(enc)

    def encrypt(self, nonce, pt, aad=b''):
        nt  = _omac(self._cmac, 0, nonce)
        ht  = _omac(self._cmac, 1, aad)
        ct  = _CTR(self._enc, nt).process(pt)
        tag = _xor16(_xor16(nt, ht), _omac(self._cmac, 2, ct))
        return ct, tag

    def decrypt(self, nonce, ct, tag, aad=b''):
        nt      = _omac(self._cmac, 0, nonce)
        pt      = _CTR(self._enc, nt).process(ct)
        ht      = _omac(self._cmac, 1, aad)
        exp_tag = _xor16(_xor16(nt, ht), _omac(self._cmac, 2, ct))
        if exp_tag != tag:
            raise ValueError("EAX authentication failed — file may be corrupt or unsupported version")
        return pt


# ─── PKA constants ────────────────────────────────────────────────────────────

_KEY  = bytes([0x89]) * 16   # Twofish key (hardcoded in binary)
_IV   = bytes([0x10]) * 16   # EAX nonce   (hardcoded in binary)
_SALT = bytes.fromhex('C0A801BE79392311A09BC602')  # MD5 salt (hardcoded in binary)


# ─── PKA decrypt / encrypt ────────────────────────────────────────────────────

def _decrypt_pka(raw: bytes) -> bytes:
    """Decode a .pka file and return the raw XML bytes."""
    if len(raw) < 17:
        raise ValueError("File too small to be a valid .pka")

    # Layer 1 — reverse + positional XOR
    L  = len(raw)
    s1 = bytes(raw[L-1-i] ^ ((L - i*L) & 0xFF) for i in range(L))

    # Layer 2 — Twofish-EAX decrypt (last 16 bytes = auth tag)
    eax = _EAX(_Twofish(_KEY).encrypt)
    dec = eax.decrypt(nonce=_IV, ct=s1[:-16], tag=s1[-16:])

    # Layer 3 — positional XOR (self-inverse)
    L2 = len(dec)
    s2 = bytes(b ^ ((L2 - i) & 0xFF) for i, b in enumerate(dec))

    # Layer 4 — Qt qCompress (4-byte BE size + zlib)
    if len(s2) < 4:
        raise ValueError("Decrypted data too short")
    sz = struct.unpack(">I", s2[:4])[0]
    try:
        xml = zlib.decompress(s2[4:])
    except zlib.error as e:
        raise ValueError(f"zlib decompression failed: {e}")
    if len(xml) != sz:
        raise ValueError(f"XML size mismatch: expected {sz}, got {len(xml)}")
    return xml


def _encrypt_pka(xml: bytes) -> bytes:
    """Re-encode XML back into a .pka file."""
    # Layer 4 — Qt qCompress
    comp = struct.pack(">I", len(xml)) + zlib.compress(xml, level=6)

    # Layer 3 — positional XOR
    L  = len(comp)
    s2 = bytes(b ^ ((L - i) & 0xFF) for i, b in enumerate(comp))

    # Layer 2 — Twofish-EAX encrypt
    eax    = _EAX(_Twofish(_KEY).encrypt)
    ct, tag = eax.encrypt(nonce=_IV, pt=s2)
    comb   = ct + tag

    # Layer 1 — reverse + positional XOR
    L2  = len(comb)
    out = bytearray(L2)
    for i in range(L2):
        out[L2-1-i] = comb[i] ^ ((L2 - i*L2) & 0xFF)
    return bytes(out)


# ─── Password hashing ─────────────────────────────────────────────────────────

def pka_hash(password: str) -> str:
    """Compute the PASS hash for a given password: MD5(SALT + password), uppercase hex."""
    return hashlib.md5(_SALT + password.encode('utf-8')).hexdigest().upper()


# ─── Main ─────────────────────────────────────────────────────────────────────

def main():
    ap = argparse.ArgumentParser(
        description="Cisco Packet Tracer .pka Activity Wizard password bypass",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  %(prog)s lab.pka -p cisco          # replace password with 'cisco'\n"
            "  %(prog)s lab.pka --info            # show current PASS hash\n\n"
            "Hashcat (recover original password):\n"
            "  hashcat -m 20 --hex-salt HASH:c0a801be79392311a09bc602 wordlist.txt\n"
        )
    )
    ap.add_argument("input",      help=".pka input file")
    ap.add_argument("-o", "--output", help="output path (default: <input>_bypass.pka)")
    ap.add_argument("-p", "--password", default="cisco",
                    help="new password to set (default: cisco)")
    ap.add_argument("--info", action="store_true",
                    help="show current PASS hash and exit without modifying the file")
    args = ap.parse_args()

    # ── Input validation ──────────────────────────────────────────────────────
    if not os.path.isfile(args.input):
        print(f"[-] File not found: {args.input}", file=sys.stderr)
        sys.exit(1)

    if not args.input.lower().endswith('.pka'):
        print(f"[!] Warning: file does not have a .pka extension — proceeding anyway")

    # ── Read & decrypt ────────────────────────────────────────────────────────
    try:
        with open(args.input, 'rb') as f:
            raw = f.read()
    except OSError as e:
        print(f"[-] Cannot read file: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"[*] Input : {args.input} ({len(raw):,} bytes)")

    try:
        xml = _decrypt_pka(raw)
    except ValueError as e:
        print(f"[-] Decryption failed: {e}", file=sys.stderr)
        print("    This may not be a valid .pka file, or it may be from an unsupported PT version.",
              file=sys.stderr)
        sys.exit(1)

    print(f"[*] Decrypted XML: {len(xml):,} bytes")

    # ── Find PASS attribute ───────────────────────────────────────────────────
    m = re.search(rb'<ACTIVITY\b[^>]*\bPASS="([^"]*)"', xml, re.DOTALL)
    if not m:
        print("[-] No PASS attribute found in <ACTIVITY> tag.", file=sys.stderr)
        print("    This .pka may not have Activity Wizard protection enabled.", file=sys.stderr)
        sys.exit(1)

    old_hash = m.group(1).decode('ascii', errors='replace')
    print(f"[*] Current PASS : {old_hash}")

    if args.info:
        print(f"[*] Hashcat input: {old_hash}:c0a801be79392311a09bc602")
        sys.exit(0)

    # ── Compute new hash ──────────────────────────────────────────────────────
    new_hash = pka_hash(args.password)
    print(f"[*] New PASS     : {new_hash}  (password: {args.password!r})")

    if old_hash == new_hash:
        print("[!] New hash is identical to current — password already set to this value.")
        sys.exit(0)

    # ── Patch XML ─────────────────────────────────────────────────────────────
    new_xml = xml[:m.start(1)] + new_hash.encode() + xml[m.end(1):]

    # ── Re-encrypt ────────────────────────────────────────────────────────────
    try:
        out_data = _encrypt_pka(new_xml)
    except Exception as e:
        print(f"[-] Re-encryption failed: {e}", file=sys.stderr)
        sys.exit(1)

    # ── Write output ──────────────────────────────────────────────────────────
    out_path = args.output or (
        os.path.splitext(args.input)[0] + "_bypass" + os.path.splitext(args.input)[1]
    )

    if os.path.exists(out_path) and not args.output:
        # auto-generated name collision unlikely, but handle it
        pass
    elif os.path.exists(out_path):
        print(f"[!] Warning: overwriting existing file: {out_path}")

    try:
        with open(out_path, 'wb') as f:
            f.write(out_data)
    except OSError as e:
        print(f"[-] Cannot write output: {e}", file=sys.stderr)
        sys.exit(1)

    print(f"[+] Saved : {out_path} ({len(out_data):,} bytes)")
    print(f"[+] Done  — open in Packet Tracer and enter password: {args.password!r}")


if __name__ == "__main__":
    main()