# pka-wizard-bypass

Replace the Activity Wizard password on Cisco Packet Tracer `.pka` files. Works by decrypting the file, swapping the password hash, and re-encrypting - no brute force, no Packet Tracer installation needed.

Single Python script, zero dependencies, works on any OS with Python 3.6+.

## How It Works

Packet Tracer's `.pka` files are encrypted through four layers (reverse XOR -> Twofish-128 EAX -> positional XOR -> zlib). The encryption keys and IV are hardcoded in the binary. The Activity Wizard password is stored inside the encrypted XML as `MD5(salt + password)`, where the 12-byte salt is also hardcoded.

This tool decrypts the file, replaces the hash with one for a password you choose, and re-encrypts it.

Full reverse engineering writeup: **[writeup.md](writeup.md)**

## Usage

```bash
# Replace the password with 'cisco'
python pka_bypass.py locked_lab.pka

# Replace with a custom password
python pka_bypass.py locked_lab.pka -p mypassword

# Specify output path
python pka_bypass.py locked_lab.pka -p cisco -o unlocked.pka

# View the current password hash without modifying the file
python pka_bypass.py locked_lab.pka --info
```

Output file defaults to `<filename>_bypass.pka` in the same directory.

## Recovering the Original Password

If you want to crack the original password instead of replacing it, use hashcat with salted MD5:

```bash
hashcat -m 20 --hex-salt HASH:c0a801be79392311a09bc602 wordlist.txt
```

Get the hash with `--info` first.

## Tested On

- Cisco Packet Tracer 9.0 (Windows x64)

Other versions may work if they use the same encryption constants. If you test on a different version, please open an issue with results.

## Requirements

- Python 3.6+
- No external packages — all crypto (Twofish, CMAC, CTR, EAX) is implemented inline

## Credits

- **[Unpacket](https://github.com/Punkcake21/Unpacket)** - Reversed the file encryption pipeline (Twofish-EAX + obfuscation layers)
- Tools used: Ghidra, x64dbg, Python 3

## Disclaimer

This tool is for educational and research purposes only. The Activity Wizard password is designed to prevent students from casually viewing lab answers not to protect sensitive data. Use responsibly and only on files you have legitimate access to.