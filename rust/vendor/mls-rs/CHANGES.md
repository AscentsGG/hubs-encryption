# Changes in this copy of mls-rs

This folder is mls-rs 0.56.0 as published on crates.io (from
https://github.com/awslabs/mls-rs, commit
8f1b43f447a792ff9307f1c2c7f54da63914870e), with the changes below. It is
used in place of the crates.io release through `[patch.crates-io]` in
`../../Cargo.toml`. mls-rs is licensed under Apache-2.0 or MIT, at your
option; see `LICENSE-APACHE` and `LICENSE-MIT`. Each changed file says so in
its first line.

## 1. Lower limits on skipped message keys

File: `src/group/secret_tree.rs`

- `MAX_RATCHET_BACK_HISTORY` is 200 instead of 1024. A private message more
  than 200 generations ahead of the next one a receiver expects is refused
  with `InvalidFutureGeneration`.
- New constant `MAX_SKIPPED_GENERATIONS_KEPT` (10). When a receiver moves a
  sender's ratchet forward, it keeps the keys of only the 10 newest skipped
  generations for that sender, however old they are, and drops the oldest
  ones first. Upstream keeps every skipped key until the epoch is dropped.

Why: a sender controls the generation number in its messages. With the
upstream limits, each message can make a receiver derive and store up to
1024 more keys for that sender, and the stored keys stay in memory and in
the saved group state for the rest of the epoch. The new limits are the ts-mls defaults (`defaultKeyRetentionConfig`:
`maximumForwardRatchetSteps: 200`, `retainKeysForGenerations: 10`), which
the Hubs website uses. ts-mls drops old keys the same way
(`removeOldGenerations`), so every Hubs client accepts and refuses the same
late and out-of-order messages.

Upstream's unit test `test_out_of_order_keys` in this file expects every
skipped key to be kept, so it fails with this change. The tests in
`hubs-mls/tests/skipped_keys.rs` cover the new behavior.

## 2. `PaddingMode::PadUntil256`

File: `src/group/padding.rs`

A new padding mode: the encoded `PrivateMessageContent` is padded with zero
bytes up to 256 bytes, and content of 256 bytes or more is not padded. It
comes with a unit test, `test_pad_until_256`.

Why: this is the ts-mls default padding (`defaultPaddingConfig`,
`{ kind: "padUntilLength", padUntilLength: 256 }`), which the Hubs website
uses. None of the upstream modes (`StepFunction`, `Padme`, `None`) produces
the same sizes. With the same rule on every client, the size of a message
does not show whether it came from the website or a native app. Padding is
stripped by the receiver (RFC 9420, section 6.3.1), so this change does not
affect what any client can decrypt.

## 3. `Group::application_sender_data`

File: `src/group/mod.rs`

A new public method, an addition only. It opens an application message's
sender data (RFC 9420, section 6.3.2) with the sender data secret of the
message's epoch (the current one, or a prior one the group keeps) and
returns the sender's leaf index and generation, without decrypting the
content. It returns `None` for anything that is not an application message
in a private message. No existing code path calls it, and nothing else in
the file changed.

Why: mls-rs decrypts the sender data only inside
`process_incoming_message`, and its public types report the generation only
for a message that opens. Hubs tells a person when a message from a
contact never arrived, and for that it needs each message's generation,
including for a message that then fails to open. `hubs-mls` calls this on a
copy of the group, so reading a header never changes a conversation's
state. Only the sender data's own AEAD is checked, so the result is a hint
until the message is processed.

## 4. Package contents

File: `Cargo.toml`

The crate's `benches/`, `examples/` and `tests/` folders are left out of
this copy, along with `Cargo.lock`, `Cargo.toml.orig`, `.cargo/`,
`.cargo_vcs_info.json` and `webdriver.json`. The `[[example]]`, `[[test]]`
and `[[bench]]` entries for the left out files are removed from
`Cargo.toml`. Nothing else in the manifest changed.

`LICENSE-APACHE` and `LICENSE-MIT` are `LICENSE-apache` and `LICENSE-mit`
from the mls-rs repository at the commit above, copied byte for byte,
because the published crate does not include them. This file,
`CHANGES.md`, is new.

## Checking this list

Every file not named above is byte for byte the same as in the crates.io
release (`mls-rs-0.56.0.crate`, SHA-256
`4392c3b3ed7d835ca8f318f85ca65d3f0d3e879538d6e70679827a2f3af72029`, as
listed in the crates.io index). To check, unpack that crate next to this
folder and compare:

```
curl -sSfLO https://static.crates.io/crates/mls-rs/mls-rs-0.56.0.crate
tar xzf mls-rs-0.56.0.crate
diff -r mls-rs-0.56.0 rust/vendor/mls-rs
```

The only differences are the four files above, the license files and this
file, and the folders and files section 4 leaves out.
