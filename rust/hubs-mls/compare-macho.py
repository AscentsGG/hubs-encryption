#!/usr/bin/env python3
"""Checks a rebuilt HubsMLSFFI against the one Hubs for Mac published.

    python3 compare-macho.py <your rebuild> <the published ZIP, app, framework or library>
    python3 compare-macho.py <one of them>

Your rebuild is the framework (or the library inside it) that build-reproducible.sh
writes. The published one is the Hubs-<version>.zip from thehubs.gg, Hubs.app,
HubsMLSFFI.framework, or the library file itself.

The published library carries our Developer ID signature, so its plain SHA-256
can't match a rebuild. This compares each architecture's code digest instead:
SHA-256 over every byte before the signature, with the three fields signing
rewrites set to zero. Those are the signature's size in its load command and the
size of the __LINKEDIT segment that holds it (in memory and in the file). The
universal file's header, which lists each architecture's offset and size, is
left out the same way. None of it is code or data the app runs. Equal digests
mean the two are identical except for the signatures.

It also reads the published signature's code directory, which lists a hash for
each page of the library (16 KB for Apple silicon, 4 KB for Intel), and checks
those against your rebuild's pages.
When they all match, our signature covers exactly the code you built. This reads
the signature; macOS, or codesign --verify, is what proves who signed it.

It needs only Python 3, on any system. REPRODUCIBLE.md says how to make the rebuild.
"""
import hashlib
import io
import os
import struct
import sys
import zipfile

NAME = "HubsMLSFFI"
INSIDE = f"{NAME}.framework/Versions/A/{NAME}"
FAT, FAT64 = 0xCAFEBABE, 0xCAFEBABF
THIN64 = 0xFEEDFACF
LC_SEGMENT_64, LC_CODE_SIGNATURE = 0x19, 0x1D
SUPERBLOB, CODEDIRECTORY = 0xFADE0CC0, 0xFADE0C02
# Code directory flags: an ad hoc signature, and one the linker wrote.
ADHOC, LINKER_SIGNED = 0x2, 0x20000
CPU = {0x0100000C: "arm64", 0x01000007: "x86_64"}
HASHES = {1: ("sha1", 20), 2: ("sha256", 32), 3: ("sha256", 20), 4: ("sha384", 48)}


def read(path):
    """The library's bytes, from the file itself, a framework, an app or a ZIP of one."""
    if os.path.isdir(path):
        for inside in (os.path.join("Versions", "A", NAME),
                       os.path.join("Contents", "Frameworks", *INSIDE.split("/"))):
            if os.path.isfile(os.path.join(path, inside)):
                path = os.path.join(path, inside)
                break
        else:
            raise ValueError(f"no {NAME} library in that folder")
    with open(path, "rb") as source:
        data = source.read()
    if data[:2] == b"PK":
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            found = [entry for entry in archive.namelist() if entry.endswith(INSIDE)]
            if len(found) != 1:
                raise ValueError(f"the ZIP has {len(found)} copies of {INSIDE}")
            return archive.read(found[0])
    return data


def slices(data):
    """{architecture: its Mach-O bytes}, from a universal file or a single one."""
    magic = struct.unpack_from(">I", data, 0)[0]
    if magic in (FAT, FAT64):
        count = struct.unpack_from(">I", data, 4)[0]
        found = {}
        for index in range(count):
            if magic == FAT:
                cpu, _, offset, size, _ = struct.unpack_from(">iiIII", data, 8 + 20 * index)
            else:
                cpu, _, offset, size, _, _ = struct.unpack_from(">iiQQII", data, 8 + 32 * index)
            found[CPU.get(cpu & 0xFFFFFFFF, hex(cpu))] = data[offset:offset + size]
        return found
    if struct.unpack_from("<I", data, 0)[0] == THIN64:
        cpu = struct.unpack_from("<I", data, 4)[0]
        return {CPU.get(cpu, hex(cpu)): data}
    raise ValueError("not a Mac library")


def layout(data):
    """Where signing writes in one architecture's Mach-O: (signature offset, size, its size field, __LINKEDIT's two size fields)."""
    if struct.unpack_from("<I", data, 0)[0] != THIN64:
        raise ValueError("not a 64-bit Mac library")
    count, size = struct.unpack_from("<II", data, 16)
    at, end = 32, 32 + size
    signature = linkedit = None
    for _ in range(count):
        command, length = struct.unpack_from("<II", data, at)
        if length < 8 or at + length > end:
            raise ValueError("a broken load command")
        if command == LC_CODE_SIGNATURE:
            offset, length_ = struct.unpack_from("<II", data, at + 8)
            signature = (offset, length_, at + 12)
        elif command == LC_SEGMENT_64 and data[at + 8:at + 24].rstrip(b"\0") == b"__LINKEDIT":
            linkedit = (at + 32, at + 48)
        at += length
    if signature is None:
        raise ValueError("no code signature (the rebuild is signed by its linker; is this another file?)")
    if linkedit is None:
        raise ValueError("no __LINKEDIT segment")
    offset, length, field = signature
    if offset + length > len(data):
        raise ValueError("the signature runs past the end of the file")
    # Nothing but padding may follow the signature: every byte is either hashed or the signature itself.
    if data[offset + length:].strip(b"\0"):
        raise ValueError("something follows the signature")
    return offset, length, field, linkedit


def normalized(data):
    """The bytes before the signature, with the fields signing rewrites set to zero."""
    offset, _, field, (vmsize, filesize) = layout(data)
    out = bytearray(data[:offset])
    for at, width in ((field, 4), (vmsize, 8), (filesize, 8)):
        out[at:at + width] = bytes(width)
    return bytes(out)


def code_directories(data):
    """Each code directory in the signature: (hash name, hash size, page size, code limit, page hashes, identifier, team, flags)."""
    offset, length, _, _ = layout(data)
    blob = data[offset:offset + length]
    magic, _, count = struct.unpack_from(">III", blob, 0)
    if magic != SUPERBLOB:
        raise ValueError("an unknown kind of signature")
    found = []
    for index in range(count):
        _, at = struct.unpack_from(">II", blob, 12 + 8 * index)
        if struct.unpack_from(">I", blob, at)[0] != CODEDIRECTORY:
            continue
        (_, _, version, flags, hashes, ident, _, slots, limit, hash_size, hash_type, _, page_log) = \
            struct.unpack_from(">IIIIIIIIIBBBB", blob, at)
        if version >= 0x20300:
            limit = struct.unpack_from(">Q", blob, at + 56)[0] or limit
        team = None
        if version >= 0x20200:
            team_at = struct.unpack_from(">I", blob, at + 48)[0]
            if team_at:
                team = blob[at + team_at:blob.index(b"\0", at + team_at)].decode()
        name, size = HASHES.get(hash_type, (None, hash_size))
        if name is None or size != hash_size:
            raise ValueError(f"an unknown hash type {hash_type} in the signature")
        pages = [blob[at + hashes + i * size:at + hashes + (i + 1) * size] for i in range(slots)]
        identifier = blob[at + ident:blob.index(b"\0", at + ident)].decode()
        found.append((name, size, 1 << page_log if page_log else 0, limit, pages, identifier, team, flags))
    if not found:
        raise ValueError("the signature has no code directory")
    return found


def covers(published, rebuild):
    """Whether the published signature's page hashes are your rebuild's pages, laid out as signed."""
    offset, length, field, (vmsize, filesize) = layout(published)
    signed = bytearray(normalized(rebuild))
    if len(signed) != offset:
        return False, "the code is a different length"
    for at, width in ((field, 4), (vmsize, 8), (filesize, 8)):
        signed[at:at + width] = published[at:at + width]
    lines = []
    for name, size, page, limit, pages, identifier, team, _ in code_directories(published):
        if limit != offset:
            return False, f"the {name} code directory covers {limit} bytes, not {offset}"
        step = page or limit
        mine = [hashlib.new(name, signed[i:min(i + step, limit)]).digest()[:size] for i in range(0, limit, step)]
        if mine != pages:
            bad = sum(1 for a, b in zip(mine, pages) if a != b) + abs(len(mine) - len(pages))
            return False, f"{bad} of {len(pages)} {name} page hashes differ"
        lines.append(f"{len(pages)} {name} page hashes match ({identifier}{', team ' + team if team else ''})")
    return True, "; ".join(lines)


def describe(label, data):
    print(f"{label}: SHA-256 {hashlib.sha256(data).hexdigest()}, {len(data)} bytes")
    digests = {}
    for arch, code in sorted(slices(data).items()):
        digests[arch] = hashlib.sha256(normalized(code)).hexdigest()
        *_, team, flags = code_directories(code)[0]
        kind = ("signed by its linker" if flags & LINKER_SIGNED else "ad hoc signature" if flags & ADHOC
                else f"signed by team {team}" if team else "signed")
        print(f"  {arch}: {digests[arch]} ({kind})")
    return digests


def main(paths):
    if len(paths) not in (1, 2):
        print(__doc__)
        return 2
    try:
        if len(paths) == 1:
            describe(paths[0], read(paths[0]))
            return 0
        rebuild, published = read(paths[0]), read(paths[1])
        mine, theirs = describe("Your rebuild", rebuild), describe("Published", published)
        same = mine == theirs
        if same:
            built, shipped = slices(rebuild), slices(published)
            for arch in sorted(shipped):
                ok, line = covers(shipped[arch], built[arch])
                print(f"  {arch}: {line}")
                same = same and ok
    except (OSError, KeyError, ValueError, zipfile.BadZipFile, struct.error) as problem:
        print(f"Couldn't compare them: {problem}")
        return 2
    print("Identical except for our signature." if same else "DIFFERENT: these are not the same build.")
    return 0 if same else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
