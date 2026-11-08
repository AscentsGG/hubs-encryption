# Rebuilding hubs_mls_ffi.dll

`hubs_mls_ffi.dll` is the library that does the encryption in Hubs for Windows. It is built from this repository, and anyone can rebuild it and check that it is the one we ship, identical except for our signature.

Each Hubs for Windows release names, in its notes, the commit of this repository its library was built from and the library's Authenticode digest. The library sits at the top of the release's ZIP, next to `Hubs.exe`.

## Rebuilding it

Check out the commit the release names, then in PowerShell, from the repository's top:

```powershell
rust\hubs-mls-ffi\build-reproducible.ps1
```

You need rustup, and Visual Studio or its Build Tools with MSVC 14.44.35207 (the component `Microsoft.VisualStudio.Component.VC.14.44.17.14.x86.x64`). The script gets the exact Rust and the Windows SDK libraries itself, and any folder works. It prints where the DLL is, under `rust\target`.

Use the commit of the release you're checking: the result changes whenever the code, the lock file or a pin changes.

## Comparing it

This part needs only Python 3, on any system:

```bash
python3 rust/hubs-mls-ffi/compare-dll.py <your rebuild> <the release's ZIP, or the DLL from it>
```

It prints the Authenticode digest of each file and says whether they match. The release's notes give the same digest, and so does its signed statement in [hubs-releases](https://github.com/AscentsGG/hubs-releases) (`apps/windows/<version>.json`, from 0.3.51 on).

On a Windows PC, `pwsh tools/check-windows-release.ps1` does every step for the release thehubs.gg serves now: it checks the statement's signature, rebuilds at the commit the statement names, downloads the release and compares. The `windows-release` job in this repository runs it every day.

## Why not a plain SHA-256

We sign the DLL we ship, so its plain SHA-256 can't match a rebuild. Windows' Smart App Control can block an unsigned DLL inside a signed app, which would break private conversations and updates on those PCs, so we keep the signature and compare around it.

The Authenticode digest is the hash Windows itself checks: SHA-256 over every byte of the file except three things, which are the only parts signing changes:

- the PE checksum, 4 bytes in the header
- the certificate table entry, 8 bytes in the header
- the signature itself, at the end of the file

None of those is loaded or run, so equal digests mean every byte of code and data is the same. The script also refuses a file with anything after the signature, and it checks that the signature covers the digest it computed. It reads that value but doesn't validate the certificate; Windows or `signtool verify /pa` does that.

## What is pinned, and why

Each of these changed the DLL when we tested it, so none of them is optional.

| Pin | Where | Without it |
|---|---|---|
| Rust 1.99.1 | `rust/rust-toolchain.toml` | Another compiler is another DLL |
| MSVC 14.44.35207 | `build-reproducible.ps1` | The linker and the C runtime go into the DLL: about 41,000 bytes differed between two Windows images |
| Windows SDK package 10.0.26100.9457, by its SHA-256 | `build-reproducible.ps1` | `kernel32.lib` differs between SDK builds in folders with the same name, which changes the import hints |
| `/Brepro` and the two `--remap-path-prefix` flags | `build-reproducible.ps1` | A build time in the headers, and your folders in the panic messages |
| `Cargo.lock`, built with `--locked` | `rust/Cargo.lock` | Other versions of the crates |
| One workspace, with every path dependency inside it | `rust/Cargo.toml` | Cargo puts the absolute path of a path dependency outside its workspace into symbol names, which reorders the whole DLL: about a million bytes differed between two folders |

Keep the layout as it is: `hubs-mls-ffi`, `hubs-mls` and `vendor/mls-rs` under `rust/`, because the path dependencies are relative and the build maps the repository's top to `.`.
