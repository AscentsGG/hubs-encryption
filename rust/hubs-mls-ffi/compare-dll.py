#!/usr/bin/env python3
"""Checks a rebuilt hubs_mls_ffi.dll against the one Hubs published.

    python3 compare-dll.py <your rebuild> <the published DLL, or the ZIP it is in>
    python3 compare-dll.py <one DLL>

The published DLL carries our Authenticode signature, so its plain SHA-256 can't
match a rebuild. This compares the Authenticode digest instead, the hash Windows
itself checks: SHA-256 over every byte of the file except the PE checksum, the
certificate table entry and the signature. Those are the only parts signing
changes, and none of them is loaded or run. Equal digests mean the two files are
identical except for our signature.

It needs only Python 3, on any system. REPRODUCIBLE.md says how to make the rebuild.
"""
import hashlib
import io
import struct
import sys
import zipfile

NAME = "hubs_mls_ffi.dll"
# SHA-256 inside the signature's DigestInfo: its object id, a NULL, then 32 bytes.
SIGNED_SHA256 = bytes.fromhex("0609608648016503040201050004" "20")


def read(path):
    """The DLL's bytes, from the file itself or from inside a ZIP."""
    with open(path, "rb") as source:
        data = source.read()
    if data[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            return archive.read(NAME)
    return data


def digest(data):
    """(Authenticode digest, the signature's bytes or None)."""
    if data[:2] != b"MZ":
        raise ValueError("not a Windows program file")
    pe = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe:pe + 4] != b"PE\0\0":
        raise ValueError("not a Windows program file")
    optional = pe + 24
    magic = struct.unpack_from("<H", data, optional)[0]
    if magic not in (0x10B, 0x20B):
        raise ValueError("an unknown kind of Windows program file")
    checksum = optional + 64
    entry = optional + (112 if magic == 0x20B else 96) + 4 * 8
    table, size = struct.unpack_from("<II", data, entry)
    end = len(data)
    if size:
        # Nothing may sit after the signature: every byte is either hashed or the signature itself.
        if table + size != len(data):
            raise ValueError("something follows the signature")
        end = table
    hashed = hashlib.sha256()
    hashed.update(data[:checksum])
    hashed.update(data[checksum + 4:entry])
    hashed.update(data[entry + 8:end])
    return hashed.hexdigest(), data[table:table + size] if size else None


def describe(label, data):
    found, signature = digest(data)
    print(f"{label}: {found}")
    print(f"  file SHA-256 {hashlib.sha256(data).hexdigest()}, {len(data)} bytes")
    if signature is None:
        print("  no signature")
    else:
        # What the signature itself says it covers, so you can see this is the hash Windows checks.
        # This reads that value; Windows, or signtool, is what proves who signed it.
        at = signature.find(SIGNED_SHA256)
        says = signature[at + len(SIGNED_SHA256):at + len(SIGNED_SHA256) + 32].hex() if at >= 0 else None
        print(f"  signed, and the signature {'covers this digest' if says == found else 'covers a DIFFERENT digest'}")
        if says != found:
            raise ValueError("the signature doesn't cover this file")
    return found


def main(paths):
    if len(paths) not in (1, 2):
        print(__doc__)
        return 2
    try:
        if len(paths) == 1:
            describe(paths[0], read(paths[0]))
            return 0
        same = describe("Your rebuild", read(paths[0])) == describe("Published", read(paths[1]))
    except (OSError, KeyError, ValueError, zipfile.BadZipFile, struct.error) as problem:
        print(f"Couldn't compare them: {problem}")
        return 2
    print("Identical except for our signature." if same else "DIFFERENT: these are not the same build.")
    return 0 if same else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
