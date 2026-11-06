# Hubs encryption

This is the end-to-end encryption behind private conversations and encrypted DM calls in [Hubs](https://thehubs.gg). We publish it so anyone can check how private messages are protected, try to break it, and tell us when something is wrong.

The rest of Hubs (the server, the website and the apps around this code) is not open source. What is here is the code that handles private message text, call keys and the keys that protect them, on every platform we ship.

## What is in this repository

| Folder | What it is | Where it runs |
| --- | --- | --- |
| `typescript/` | The encryption engine, the device client and the call encryption, built on [ts-mls](https://github.com/LukaJCB/ts-mls) | The Hubs website |
| `rust/` | The same protocol in Rust, built on [mls-rs](https://github.com/awslabs/mls-rs), with Swift bindings and a small C interface | The iPhone, iPad, Mac and Windows apps |
| `test-vectors/` | Known answers that both implementations must reproduce, and the link v2 reference that makes its own | Both test suites |
| `docs/` | The protocol, the threat model, the security reviews and release fingerprints | |
| `tools/` | `check-release.mjs`, which checks the live site against the signed release statements in [hubs-releases](https://github.com/AscentsGG/hubs-releases), and the release signing key | Your computer |

The two implementations talk to each other: a message sent from the website opens on a phone and the other way around. The test vectors and a live cross-check keep them in step.

## How it works

Private conversations use MLS ([RFC 9420](https://www.rfc-editor.org/rfc/rfc9420)) with ciphersuite 1: X25519, AES-128-GCM, SHA-256 and Ed25519. Every device a person uses is its own member of the conversation, so there is no shared device key to copy around.

- Each account has an identity key that never leaves the person's devices, except sealed inside an optional passkey backup.
- Each device has its own key, signed by the identity key. Every MLS operation checks that signature, so the server cannot slip in a device of its own.
- Two people can compare a 60-digit safety code in person or on a call. If someone's identity key changes later, the conversation says so, and a verified mark is cleared.
- A new device joins by linking from an existing one or by restoring the passkey backup. The link code has a secret part that never reaches the server, so the new device can tell the keys came from the person's own device, and it can bring that device's message history along, locked so only the new device can open it ([docs/link-v2.md](docs/link-v2.md)).
- Removing a device takes a signature from the account's identity key or from the device itself, so the server alone cannot make anyone drop a person's device once that person's devices all sign removals.
- If a message from the other person never arrives, the conversation shows one line where it would have been.
- Messages disappear after one week by default. The timer is announced inside the encryption, so the server cannot turn it off.
- Reporting a message uses message franking: the report proves the message was really sent by that person, without the server ever reading messages that nobody reports.
- One-to-one and group DM calls are end-to-end encrypted too. Each call connection is signed by a device key that the account's identity key certifies, and the device decides from the conversation itself that a call must be encrypted.

We did not write any cryptographic primitives. Signatures, HPKE, AES-GCM, HKDF, HMAC and hashing all come from the MLS libraries' ciphersuites, and calls use WebCrypto. Our code puts those calls together and defines a few byte formats, which the test vectors pin down. The details are in [docs/protocol.md](docs/protocol.md).

## What the server sees

The server relays and stores ciphertext until it is delivered or its timer runs out. It never sees message text, private keys or reactions, and search runs only on the device.

It does see who talks to whom, when, from which device, and roughly how long each message is. MLS pads short messages to the same size, but it does not hide size entirely. [docs/threat-model.md](docs/threat-model.md) lists exactly what we protect against and what we do not.

## Known limits

- No outside audit of this code has been done yet. Our internal reviews and every finding from them are in [docs/reviews.md](docs/reviews.md). ts-mls has not had an independent audit either. The Rust side relies on mls-rs, which is maintained by AWS.
- The website's code is served by the same people who run the server. A bad release of the website could leak keys, and no encryption design can rule that out by itself. This is the main limit of encryption in a browser, and it is why we publish this code and a signed list of what each release serves (see Checking a release below).
- The first identity key a device sees for a contact is trusted without proof. Comparing safety codes is how you check it.
- The server could still withhold messages or devices. It cannot read them, forge them or change who is in a conversation without the devices noticing.
- Message history reaches a new device only when it is linked from a device that has it. A passkey backup restores keys, not messages.

## Building and testing

TypeScript (Node 24.10 or later):

```bash
cd typescript
npm ci
npm run typecheck
npm test
```

Rust (1.91 or later, which the pinned dependencies need):

```bash
cd rust
cargo test --workspace --locked
cargo audit
```

The Rust tests include a live check against the TypeScript implementation, so run `npm ci` in `typescript/` first, or set `HUBS_SKIP_LIVE_TS_MLS=1` to skip it. `cargo audit` needs [cargo-audit](https://crates.io/crates/cargo-audit); `rust/.cargo/audit.toml` explains the one advisory it ignores. Both suites read the same files in `test-vectors/`. The workflow in `.github/workflows/test.yml` runs all of this on every push and pull request.

## Checking a release

With every web release we publish a signed statement of every file the release serves, in [github.com/AscentsGG/hubs-releases](https://github.com/AscentsGG/hubs-releases). To check that thehubs.gg serves exactly what the statement for its current release lists (Node 20 or later, nothing to install):

```bash
node tools/check-release.mjs --current
```

It reads the release the site is running, fetches the signed statement, verifies the signature with the release signing key built into the script, then fetches the pages, headers and files and compares their hashes. The public key is also in `tools/release-signing-key.pem`:

```
-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAqw24MtztP9Gp2UKAhgVIjx4Y+Y0kM8IxpabNhN3K3ks=
-----END PUBLIC KEY-----
```

### Rebuild the encryption files

The website doesn't bundle this code into its own files. It runs the two files `typescript/build.mjs` makes, unchanged, and the build gives the same bytes on any computer. To check that thehubs.gg runs exactly the code in this repository:

```bash
cd typescript
npm ci
npm run build
cd ..
node tools/check-release.mjs --current --rebuilt typescript/dist
```

It ends with "Your rebuild matches this release" when every byte is the same. The `rebuild` job in `.github/workflows/test.yml` runs this every day. When a release changes the encryption code, this repository gets a tag named after that release.

[docs/release-fingerprints.md](docs/release-fingerprints.md) explains what a statement covers, what it does not, and how to check a signature with OpenSSL alone.

## Reporting a security problem

Please do not open a public issue for a security problem. See [SECURITY.md](SECURITY.md).

## License

Copyright 2026 Ascent Collective LLC. Licensed under the [GNU Affero General Public License v3.0](LICENSE) only.

You are free to read, run, study and verify this code. If you build it into something you distribute or run as a service, the AGPL asks you to share your source too.

`rust/vendor/mls-rs` is a copy of mls-rs 0.56.0 by Amazon, which keeps its own Apache 2.0 or MIT license, with the small changes listed in [rust/vendor/mls-rs/CHANGES.md](rust/vendor/mls-rs/CHANGES.md).

## Contributing

Bug reports and questions are welcome as issues. For anything security related, use [SECURITY.md](SECURITY.md) instead. We don't merge code from outside contributors into this repository, but a pull request that shows a problem is still useful: we'll read it and make the fix ourselves.
