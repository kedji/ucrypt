# ucrypt
Crypto auditing tool for Prolaag VPN

### Usage

```bash
**./ucrypt.rb [options...] <host>**

options: [-k key] [-i iv] [-x extra] [-p payload] [-t bytes] [-d] [-h] [-c] [-o] <host>
  -k: 256 bit AES key (in hex)
  -i: 16 byte initialization vector (in hex)
  -x: extra en/decryption rounds for perf tests
  -p: specify a payload on the command line rather than stdin
  -t: trim the given number of bytes off the end of the output
  -d: decrypt instead of encrypt
  -h: use hardware instead of software
  -c: output result in C-style hex
  -o: output raw octets instead of hex
```

### Example
Performing a simple encryption/decryption cycle

```bash
# Assuming UCrypt service being served by 10.1.1.1
#   -p: read the plaintext to be encrypted from command line rather than stdin
**./ucrypt.rb -p "This is only a test." 10.1.1.1**

    Encrypting 32 bytes on 10.1.1.1
    Extra: 0
    Flags: 0
    Key:   0101020305080d150101020305080d150101020305080d150101020305080d15
    IV:    00000000000000000000000000000000
    ========================
    e0 a0 c2 cc b7 9c 4e 7a b5 3c 38 c0 e4 32 97 55 0e 3b a9 49 53 5d de 7e 
    b1 27 85 99 34 de c2 7d 
    ========================
    Local time:       161 microseconds
    Trim 12 bytes

# 12 padding bytes were added to plaintext, so we need to trim them on decryption
#   -o: output raw bytes instead of hex
#   -t: trim bytes off the decrypted plaintext (to remove padding)
**./ucrypt.rb -p "This is only a test." -o 10.1.1.1 | ./ucrypt.rb -d -o -t 12 10.1.1.1**

    Decrypting 32 bytes on 10.1.1.1
    Extra: 0
    Flags: 1
    Key:   0101020305080d150101020305080d150101020305080d150101020305080d15
    IV:    00000000000000000000000000000000
    ========================
    This is only a test.
    ========================
    Local time:       130 microseconds
```
