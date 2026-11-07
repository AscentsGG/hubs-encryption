# Rebuilding HubsMLSFFI.framework

`HubsMLSFFI.framework` is the library that does the encryption in Hubs for Mac. It is `hubs-mls` from this repository, built as a dynamic library for Apple silicon and Intel in one file. Anyone can rebuild it and check that it is the one we ship, identical except for our signature.

Each Hubs for Mac release names, in its notes, the commit of this repository its library was built from and the library's code digest for each architecture. The library sits inside the app at `Hubs.app/Contents/Frameworks/HubsMLSFFI.framework`.

## Rebuilding it

Check out the commit the release names, then from the repository's top:

```bash
rust/hubs-mls/build-reproducible.sh
```

You need a Mac with rustup, and Apple's Command Line Tools 26.4 or Xcode 26.4.1. Both have the linker ld-1266.8, and their macOS 26.4 SDKs (builds 25E236 and 25E251) give the same library. The script gets the exact Rust itself and any folder works. It uses `/Applications/Xcode_26.4.1.app` when it is installed, as on GitHub's macOS runners, the Command Line Tools otherwise, or whatever `DEVELOPER_DIR` names, and it stops if the linker or the SDK is not the pinned one. It prints where the framework is, under `rust/target/mac`.

To see for yourself that the build doesn't depend on where it runs, `rust/hubs-mls/build-reproducible.sh --twice` builds it in two folders and checks that every file comes out the same.

Use the commit of the release you're checking: the result changes whenever the code, the lock file or a pin changes.

## Comparing it

This part needs only Python 3, on any system:

```bash
python3 rust/hubs-mls/compare-macho.py <your rebuild> <the release's ZIP, Hubs.app, or the framework from it>
```

It prints the code digest of each architecture in each file and says whether they match. The release's notes give the same digests.

## Why not a plain SHA-256

We sign the library we ship, with our Developer ID, as part of the app. macOS checks the signature of everything inside a signed app before it runs it, so we keep the signature and compare around it.

Signing changes only the signature itself, at the end of each architecture's code, and three size fields in front of it:

- the signature's size, 4 bytes in its load command
- the size of the `__LINKEDIT` segment that holds the signature, in memory and in the file, 8 bytes each
- the offsets and sizes in the header of the file that holds both architectures

The code digest is SHA-256 over every byte of an architecture's code up to its signature, with those fields set to zero. None of them is code or data the app runs, so equal digests mean every byte of code and data is the same. The script also refuses a file with anything after a signature.

It then reads our signature's code directory, the list of page hashes that macOS checks as it loads the library, and checks each one against your rebuild's pages. When they all match, our signature covers exactly the code you built. The script reads the signature but doesn't check who made it; `codesign --verify` or macOS does that.

## What is pinned, and why

We built the library again with each of the first five changed, one at a time, and compared it with our build. Each changed the library, so none of them is optional.

| Pin | Where | Without it |
|---|---|---|
| Rust 1.99.1 | `rust/rust-toolchain.toml` | Another compiler is another library: with Rust 1.97.0, about 2.6 million bytes differed |
| The linker ld-1266.8 and the macOS 26.4 SDK, build 25E236 (Command Line Tools 26.4) or 25E251 (Xcode 26.4.1) | `build-reproducible.sh` | The linker writes the file and the SDK's system libraries are linked into it: with Xcode 27.2's linker and SDK, about 123,000 bytes differed. The two 26.4 SDK builds were measured identical: Xcode 26.4.1 on GitHub's macOS runner, with 25E251, built the same SHA-256 as Command Line Tools 26.4 with 25E236 |
| The two `--remap-path-prefix` flags | `build-reproducible.sh` | Your folders end up in the panic messages: about 131,000 bytes differed in a build from another folder |
| `-Wl,-S` (no debug map) | `build-reproducible.sh` | A build from another folder got a different UUID in each architecture: 96 bytes differed, the UUIDs and the page hashes over them |
| macOS 15.0 as the minimum | `build-reproducible.sh` | The minimum macOS is written into each architecture's header: with 14.0, 98 bytes differed |
| `-Wl,-adhoc_codesign` | `build-reproducible.sh` | The Intel half has no signature of its own, so it can't be compared with a signed one: the linker signs only Apple silicon code unless told to |
| `Cargo.lock`, built with `--locked` | `rust/Cargo.lock` | Other versions of the crates |
| `ZERO_AR_DATE=1` | `build-reproducible.sh` | No difference today: the dates of the archives the linker reads reach a library only through its debug map, which `-S` leaves out. It keeps them out if that ever changes |

The library's UUID comes from its contents, so the same build gets the same UUID wherever it runs.

Keep the layout as it is: `hubs-mls` and `vendor/mls-rs` under `rust/`, because the path dependencies are relative and the build maps the repository's top to `.`.
