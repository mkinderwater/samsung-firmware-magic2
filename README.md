# samsung-magic2

Decrypt current-era Samsung SSD firmware packages (the `.enc` files found in
Samsung's bootable firmware ISOs, inside `root/fumagician/`).

This is an updated companion to
[chrivers/samsung-firmware-magic](https://github.com/chrivers/samsung-firmware-magic).
All credit for the original work, the reverse engineering of the firmware
format, and the decryption approach goes to **chrivers**. This version only
adapts that work to Samsung's newer encryption scheme.

## Why a new version

The original tool targets older packages, which used AES-128 in a 32-block
CTR-style mode together with a byte-shuffle table, keyed by a constant baked
into Samsung's `fumagician` tool. Samsung has since changed the format and
rotated the key, so the original key no longer decrypts recent firmware. New
packages now use plain **AES-256-ECB** with a short header.

## Format

Each `.enc` container:

| Offset  | Contents                                                        |
|---------|-----------------------------------------------------------------|
| 0..31   | 32-byte header, AES-256-ECB encrypted                           |
| 32..    | payload, AES-256-ECB, zero-padded to a 16-byte boundary         |

The decrypted header is a 16-byte magic (`_icianMAG_@*!.8&`) followed by a
uint32 little-endian plaintext length at offset 16. The payload is trimmed to
that length.

`DSRD.enc` decrypts to an XML list of applicable firmware versions. A firmware
`.enc` decrypts to a ZIP archive containing several inner `.enc` files, each
encrypted the same way with the same key.

## Install

```
pip install -r requirements.txt
```

## Usage

```
# print the XML firmware list
python samsung_magic2.py DSRD.enc

# write a decrypted file
python samsung_magic2.py DSRD.enc DSRD.xml
python samsung_magic2.py 6B2QJXD7.enc firmware.zip

# decrypt a firmware package, unzip it, and decrypt the inner .enc files
python samsung_magic2.py 6B2QJXD7.enc --unzip out
```

On Windows `cmd`, redirecting to a file works too:

```
python samsung_magic2.py DSRD.enc > DSRD.xml
```

## Keys change

The AES-256 key in `samsung_magic2.py` is specific to a given `fumagician`
build. Samsung rotates it between firmware releases. If a package fails with a
`header magic mismatch`, the key has changed. Re-extract it the same way the
original project did: in the `fumagician` binary from the ISO, find the
base64 string that decodes to exactly 32 bytes and replace the `KEY` value.

## Credit

- Original tool, format research, and method:
  [chrivers/samsung-firmware-magic](https://github.com/chrivers/samsung-firmware-magic)
- AES-256-ECB scheme update: this repository.

## Disclaimer

For inspecting firmware you are authorised to work with (e.g. your own drives
or data-recovery work). Flashing firmware is done with Samsung's own tools and
at your own risk; this script only decrypts the packages.
