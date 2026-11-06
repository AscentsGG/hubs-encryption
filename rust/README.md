# Rust implementation

The end-to-end encryption for Hubs private messages, as used by the native
apps. The TypeScript implementation the website uses is in `../typescript/`.
Both produce the same bytes, and the tests here check that against fixed
vectors and against the TypeScript code running live.

| Folder | What it is |
| --- | --- |
| `hubs-mls/` | The core: MLS (RFC 9420) on mls-rs, the Hubs device credential, message franking, the key package policy, and UniFFI bindings for Swift and Kotlin. See its README. |
| `hubs-mls-ffi/` | A C ABI over the core that takes and returns JSON, used by the Windows app. Its tests call every operation with hostile fields through the C entry points. |
| `uniffi-bindgen/` | Host tool that writes the Swift and Kotlin bindings. Never linked into an app. |
| `vendor/mls-rs/` | mls-rs 0.56.0 with three small changes, used through `[patch.crates-io]`. See `vendor/mls-rs/CHANGES.md`. |

Every direct dependency is pinned to an exact version, and `Cargo.lock`
pins the rest, so a `--locked` build uses exactly these versions.

## Tests

```
cargo test --workspace --locked
```

`hubs-mls/tests/live_ts_mls.rs` runs the TypeScript implementation through
Node. It needs Node 24 and `npm ci` in `../typescript/` first. To run
without Node, set `HUBS_SKIP_LIVE_TS_MLS=1`:

```
HUBS_SKIP_LIVE_TS_MLS=1 cargo test --workspace --locked
```

| Variable | Effect |
| --- | --- |
| `HUBS_SKIP_LIVE_TS_MLS=1` | Skip the live TypeScript tests. |
| `HUBS_TYPESCRIPT_DIR` | Folder of the TypeScript package to test against. The default is `../typescript/`. |
| `HUBS_NODE` | The node binary to run. The default is `node` on the `PATH`. |

The cross-platform vectors are read from `../test-vectors/`, the same files
the TypeScript tests read.

## Audit

```
cargo audit
```

`.cargo/audit.toml` ignores one advisory, RUSTSEC-2026-0387 in
crypto-bigint 0.5.5, and says why: it comes in only through the P-256 and
P-384 curves of the RustCrypto provider, which ciphersuite 1 never uses.

## Bindings

Build the library and the bindgen tool, then generate the bindings from
the library. The Swift module names come from `hubs-mls/uniffi.toml`.

```
cargo build --locked --release -p hubs-mls
cargo build --locked -p uniffi-bindgen
target/debug/uniffi-bindgen generate --library target/release/libhubs_mls.a \
    --language swift --out-dir out/swift
target/debug/uniffi-bindgen generate --library target/release/libhubs_mls.a \
    --language kotlin --out-dir out/kotlin
```

## License

The code in `hubs-mls/`, `hubs-mls-ffi/` and `uniffi-bindgen/` is licensed
under the GNU Affero General Public License v3.0 only (see LICENSE at the
root of this repository). `vendor/mls-rs/` keeps its own Apache-2.0 or MIT
license and copyright, with its license files in that folder.
