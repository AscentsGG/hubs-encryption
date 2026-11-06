# hubs-mls

The Rust core of Hubs private messages: MLS (RFC 9420) on mls-rs 0.56.0,
the Hubs device credential, message franking and the key package lifetime
policy. The iPhone and Mac apps use it through UniFFI, and the Windows app
through `../hubs-mls-ffi`. It reads and writes the same bytes as the
TypeScript implementation the website uses (`typescript/` at the root of
this repository).

## Interface

Apps see bytes, records and two objects, never mls-rs types:

- `MlsDevice`: one device's keys. It makes key packages, starts a
  conversation, joins one from a welcome, and loads a saved snapshot.
- `MlsGroup`: one conversation on that device. It adds and removes devices
  in one commit (kept pending until the server accepts it), encrypts a
  message with its franking commitment, receives messages and commits, and
  saves a snapshot.
- Free functions for the Hubs layer: device certificates, the credential
  JSON, the payload rule, the membership rule and the key package policy.

The core keeps nothing on disk. The app stores key package private halves
and group snapshots in its own encrypted store.

## Removals, missing messages, backups and calls

These follow the TypeScript implementation byte for byte, and the vectors
pin each one.

- **Signed device removals.** `device_removal_body`, `self_remove_body` and
  `signed_removals_body` build the exact bytes; sign them with
  `sign_ed25519` (raw Ed25519, never MLS SignWithLabel).
  `verify_removal` checks a `RemovalProof` against the member as the group
  has it, `verify_removal_statement` checks an account's statement that
  its removals are signed, and `removal_proof_state` with `removal_counts`
  is the rule a device applies to a member the server stopped listing.
- **Missing messages.** `MlsGroup::message_header` reads an application
  message's epoch, sender leaf and generation from its sender data without
  opening it, so a message that then fails to open still counts.
  `track_generation` and `due_generations` are the rule over a
  `GenerationTrack`; the app stores the tracks.
- **Backup counter.** `backup_rollback_problem` refuses a passkey backup
  older than one the device has seen. The seal itself is unchanged and
  stays in the app.
- **Last-resort key package.** An ordinary key package from
  `create_key_packages`; `join_from_welcome` never consumes the app's
  private half, so one half opens any number of welcomes.
- **Calls.** `verify_ed25519` is strict Ed25519 (no small-order keys, a
  canonical S, exact sizes) for the call connection bindings, their device
  certificates and roster statements, which the apps build.

## Changes to mls-rs

The core builds on a vendored copy of mls-rs 0.56.0 (`../vendor/mls-rs`,
used through `[patch.crates-io]` in `../Cargo.toml`). Each change is marked
in its file. Apart from leaving out the examples, tests and benches,
nothing else differs from the crates.io release. `../vendor/mls-rs/CHANGES.md`
lists every change and how to check the list.

- `src/group/secret_tree.rs`: the receiver limits on skipped message keys
  (at most 200 generations ahead, the 10 newest skipped generations kept),
  as ts-mls keeps them.
- `src/group/padding.rs`: `PaddingMode::PadUntil256`, the website's padding
  (see Message padding below).
- `src/group/mod.rs`: `Group::application_sender_data`, an addition. It
  opens an application message's sender data (RFC 9420, section 6.3.2)
  with the sender data secret of the message's epoch and returns the
  sender's leaf index and generation, without decrypting the content.
  mls-rs decrypts the sender data only inside `process_incoming_message`,
  and its public types report the generation only for a message that opens
  (behind `export_key_generation`). The missing message rule needs it for
  every message, including ones that then fail to open.
  `MlsGroup::message_header` calls it on a copy of the group, so reading a
  header never changes the conversation's state.

## Message padding

Every private message is padded the way ts-mls pads by default
(`defaultPaddingConfig`, `{ kind: "padUntilLength", padUntilLength: 256 }`):
the encoded `PrivateMessageContent` (the content, then the signature, and
for a commit the confirmation tag) is filled with zero bytes up to 256
bytes, and content of 256 bytes or more gets no padding. This applies to
application messages and commits alike, since commits are sent as private
messages too. The receiver strips the padding (RFC 9420, section 6.3.1).

mls-rs 0.56.0 has no mode with this rule, so the vendored copy in
`../vendor/mls-rs` adds `PaddingMode::PadUntil256` (see its
`CHANGES.md`). mls-rs pads the same bytes ts-mls does, so the sizes match to
the byte, and the size of a message does not show whether a phone, a Mac,
Windows or a browser sent it.

A Hubs payload is JSON with ids, times and a 44-character franking key.
With the 64-byte signature, its content is already above 256 bytes even
with an empty body, so in practice neither side adds padding and the wire
size follows the length of the text. The 256-byte floor covers shorter
content. A larger padding bucket would need every client to change at the
same time.

## Tests

```
cargo test
```

- `tests/vectors.rs` replays `test-vectors/mls-interop-vectors.json`: MLS
  messages, key packages and a welcome made by the TypeScript
  implementation with fixed keys and seeded randomness.
- `tests/e2ee_vectors.rs` replays the cross-platform vectors in
  `test-vectors/e2ee-test-vectors.json` at the root of this repository.
- `tests/skipped_keys.rs` and `tests/skipped_parity.rs` check the limits on
  skipped message keys, and that the core opens the same late messages as
  the TypeScript implementation.
- `tests/generations.rs`, `tests/proposal.rs`, `tests/rejoin.rs`,
  `tests/retention.rs`, `tests/signatures.rs` and
  `tests/wrong_conversation.rs` cover message headers, refused standalone
  proposals, a device added back to a conversation, kept epochs, strict
  signatures and welcomes for the wrong conversation.
- The padding tests in `src/device.rs` check every size in
  `tests/padding-vectors.json`.
- `tests/live_ts_mls.rs` runs the TypeScript implementation live through
  Node, in both directions. It needs Node 24 and the TypeScript package
  with its dependencies installed (`npm ci` in `typescript/`). Set
  `HUBS_TYPESCRIPT_DIR` to use the package from another folder,
  `HUBS_NODE` to pick a node binary, or `HUBS_SKIP_LIVE_TS_MLS=1` to skip
  these tests.

The Node scripts in `tests/` (`ts-mls-peer.mts`, `mls-vectors.mts`,
`padding-vectors.mts`) load the TypeScript package through
`tests/typescript-package.mts`. To rewrite a vector file, run its script
from the TypeScript package's folder, for example:

```
cd typescript
node --import tsx ../rust/hubs-mls/tests/padding-vectors.mts
node --import tsx ../rust/hubs-mls/tests/mls-vectors.mts generate \
    ../test-vectors/mls-interop-vectors.json
```
