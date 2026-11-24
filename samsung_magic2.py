#!/usr/bin/env python3
"""
samsung_magic2.py - decrypt current-era Samsung SSD firmware packages.

Samsung's older firmware packages used AES-128 in a 32-block CTR-style mode
with a byte-shuffle table (handled by chrivers' original samsung-firmware-magic,
see README). Newer fumagician builds switched to plain AES-256-ECB with a short
header. This script implements that newer scheme.

Container format (.enc):
    bytes 0..31 : 32-byte header, AES-256-ECB encrypted.
                  Decrypted it is:
                    - 16-byte magic  b"_icianMAG_@*!.8&"
                    - uint32 little-endian plaintext length at offset 16
                    - padding to 32 bytes
    bytes 32..  : payload, AES-256-ECB, zero-padded to a 16-byte boundary,
                  trimmed to the length from the header.

A firmware .enc decrypts to a ZIP that contains several inner .enc files;
each inner file is encrypted the same way, with the same key.

Usage:
    python samsung_magic2.py DSRD.enc                  print the XML list
    python samsung_magic2.py DSRD.enc out.xml          write decrypted output
    python samsung_magic2.py FW.enc fw.bin             write decrypted firmware
    python samsung_magic2.py FW.enc --unzip outdir     unzip + decrypt inner .enc

Requires: pycryptodome  (pip install -r requirements.txt)
"""
import base64
import io
import os
import struct
import sys
import zipfile

from Crypto.Cipher import AES

# AES-256 key, base64-encoded, extracted from Samsung's fumagician tool.
# If a future firmware package fails with a magic mismatch, Samsung has
# rotated this key; re-extract the base64 string in fumagician that decodes
# to exactly 32 bytes and replace it here.
KEY = base64.b64decode("j130W8JKesQtpglrwmb3poDVkPD+H2F6UsDaz38N0kk=")

MAGIC = b"_icianMAG_@*!.8&"


def decrypt_blob(data):
    """Decrypt one .enc container and return its plaintext payload."""
    if len(data) < 32:
        raise ValueError("file too short to contain a 32-byte header")
    aes = AES.new(KEY, AES.MODE_ECB)
    header = aes.decrypt(data[:32])
    if header[:16] != MAGIC:
        raise ValueError(
            "header magic mismatch; wrong key, or not a fumagician .enc file "
            "(got %r)" % header[:16]
        )
    length = struct.unpack("<I", header[16:20])[0]
    body = aes.decrypt(data[32:])
    return body[:length]


def guess_kind(data):
    if data[:4] == b"PK\x03\x04":
        return "ZIP archive"
    if data[:1] in (b"<", b"\xef"):
        return "XML/text"
    return "binary"


def do_unzip(plain, outdir):
    """Treat the payload as a ZIP, extract it, and decrypt inner .enc files."""
    os.makedirs(outdir, exist_ok=True)
    zf = zipfile.ZipFile(io.BytesIO(plain))
    seen = set()
    for name in zf.namelist():
        base = os.path.basename(name)
        if base in seen:
            continue
        seen.add(base)
        raw = zf.read(name)
        if base.lower().endswith(".enc"):
            try:
                inner = decrypt_blob(raw)
            except ValueError as exc:
                open(os.path.join(outdir, base), "wb").write(raw)
                print("kept (not encrypted)  %-28s [%s]" % (base, exc))
                continue
            out = os.path.join(outdir, base[:-4] + ".bin")
            open(out, "wb").write(inner)
            print("decrypted inner       %-28s -> %s (%d bytes)"
                  % (base, os.path.basename(out), len(inner)))
        else:
            open(os.path.join(outdir, base), "wb").write(raw)
            print("extracted             %s (%d bytes)" % (base, len(raw)))


def main(argv):
    if len(argv) < 2 or argv[1] in ("-h", "--help"):
        print(__doc__)
        return 0 if len(argv) >= 2 else 1

    plain = decrypt_blob(open(argv[1], "rb").read())

    if "--unzip" in argv:
        try:
            outdir = argv[argv.index("--unzip") + 1]
        except IndexError:
            print("error: --unzip needs an output directory", file=sys.stderr)
            return 2
        do_unzip(plain, outdir)
        return 0

    if len(argv) >= 3 and not argv[2].startswith("--"):
        open(argv[2], "wb").write(plain)
        print("wrote %s (%d bytes, looks like %s)"
              % (argv[2], len(plain), guess_kind(plain)))
    else:
        sys.stdout.buffer.write(plain)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
