# Security reviews

Everything on this page comes from internal reviews: reviews by the team that builds Hubs, not by an outside firm. They are preparation for an independent audit, not a substitute for one. **No outside audit of this code has been done yet, and we want one.** If you would like to review it, please get in touch through [SECURITY.md](../SECURITY.md).

Each finding below has its severity, one line on what it was, and its status. We leave out the steps to reproduce each one. The fixes, the tests that hold them, and the protocol they produce are in this repository.

Severity: **Critical** lets an attacker in the threat model defeat end-to-end encryption outright. **High** breaks a stated end-to-end property against an attacker in the threat model. **Medium** weakens one, or needs an unlikely precondition. **Low** is defense in depth or denial of service. **Info** is a note for reviewers.

The main adversary for end-to-end encryption is a malicious or compromised Hubs server ([threat-model.md](threat-model.md)), so most findings are about what such a server could do.

## Part 1, October 2026: private conversations and encrypted calls

The first internal review, on October 12, 2026, read the encryption engine, the device client and its store, the shared protocol rules, the server's private conversation and call encryption routes, the call key code, and the build settings, end to end against RFC 9420 practice and the threat model. Private conversations were not yet available to anyone.

| ID | Severity | Area | Finding | Status |
| --- | --- | --- | --- | --- |
| F1 | High | Conversations | Welcomes were not bound to the conversation's group | Fixed |
| F2 | High | Conversations | No membership policy on the device, so a third account or a forged device of your own account could join | Fixed |
| F3 | High | Conversations | The link check was too short to stop a server from swapping in its own link key | Fixed |
| F4 | High | Calls | The call code did not cover the call key | Fixed |
| F5 | Medium | Conversations | No post-compromise healing without device changes | Fixed: a weekly key update from every device |
| F6 | Medium | Conversations | The disappearing message timer was controlled by the server | Fixed: the timer is announced inside the encryption |
| F7 | Medium | Conversations | The key change notice was easy to miss, and sending to a verified contact went on | Fixed |
| F8 | Medium | Calls | The call screen said a matching code alone meant nobody else could listen | Fixed, and the cause fixed in calls protocol 3 (O1) |
| F9 | Low | Conversations | A link hand-off could be sealed a second time, replacing the first | Fixed |
| F10 | Low | Conversations | The server accepted commits sent as MLS public messages | Fixed |
| F11 | Low | Conversations | Key package claims had no rate limit | Fixed; last-resort key packages followed under O8 |
| O1 | High | Calls | Call keys were not bound to identities, so the server decided who received the key | Fixed in calls protocol 3 |
| O2 | Medium | Calls | A 12-digit call code over epochs and keys the server chose | Fixed in calls protocol 3: a 20-digit call code and an identity check per person |
| O3 | Medium | Libraries | ts-mls has had no third-party audit, and we use one of its internal modules | Open: this is what an outside audit should cover |
| O4 | Medium | Website | Keys and decrypted history were stored unencrypted in the browser | Fixed, with the limits in the threat model |
| O5 | Medium | Server | Resetting an identity, changing the backup and removing a device needed only a session | Fixed: "Confirm it's you" guards these, and removing a device ends its sessions |
| O6 | Low | Server | The franking stamp key lived in the database | Fixed: stamp keys come from the server's secret configuration, with key ids |
| O7 | Low | Server | The server was an unsigned device directory | Removals fixed (signed removals and the removal rule); additions stay certificate-only |
| O8 | Low | Conversations | Key packages never expired, and there was no last-resort key package | Fixed |
| O9 | Low | Metadata | Metadata was kept longer than delivery needs | Fixed; padding unchanged |
| O10 | Low | Backup | The passkey backup had no rollback protection | Fixed: a counter inside the sealed backup |
| O11 | Low | Website | Replayed or junk envelopes add "could not be opened" lines | Open |
| O12 | Info | Calls | The raw ECDH output was used as the wrapping key | Fixed in calls protocol 3: HKDF bound to both statements |
| O13 | Info | Calls | The call key was not replaced when someone left | Fixed in protocol 3 calls, against an honest server (see C-3) |
| O14 | Info | Conversations | Retained epochs widen the forward secrecy window | Accepted |
| O15 | Info | Conversations | Devices away for more than 30 days lose the conversation | Documented |
| O16 | Info | Conversations | Group conversations are not supported, and clients enforce one-to-one | Note |

### Second internal review, November 4, 2026: calls protocol 3

A review of calls protocol 3: the binding, the rule for who gets the call key, the wrap and the call code.

| ID | Severity | Finding | Status |
| --- | --- | --- | --- |
| C-1 | Critical | Nothing checked that the call key came from a connection the call lists | Fixed: the rules in [protocol.md](protocol.md), Where the call key comes from |
| C-2 | Medium | The server could move a protocol 3 pair down to protocol 2 | Fixed for the app's own connection. Another person shown as an older app stays a documented limit until protocol 2 closes |
| C-3 | Low | Replacing the call key when someone leaves is decided by the server | Documented, and partly mitigated: each app keeps showing who it gave the key to |
| C-4 | Info | The media frame key is AES-128-GCM, derived from the 256-bit call key | Documented |
| C-5 | Info | The website's Security page claimed more than the protocol delivered | Fixed |

### Second internal review, November 4, 2026: protocol, MLS composition and devices

This review found no way for the server or a contact to read message content. The MLS core, the credential binding, the one-to-one membership rule and the franking construction held up. The problems were in what surrounds MLS: who can make a device drop another device, what happens to a device that gets dropped, and what trust state a new device starts with.

| ID | Severity | Finding | Status |
| --- | --- | --- | --- |
| P-1 | Medium | The signed removals statement reached contacts only through the server | Fixed: commits carry it as the signed removals note |
| P-2 | Medium | A device removed by a commit stayed stuck | Fixed |
| P-3 | Medium | Linked and restored devices lost the verified marks | Fixed |
| P-4 | Low | Removing a lost session's devices could take devices that session had only named | Fixed |
| P-5 | Low | A group that gave way to a welcome had already passed that welcome | Fixed |
| P-6 | Low | A welcome under a changed key was joined before the person reviewed it | Fixed |
| P-7 | Low | A group with no device of the other person was still used | Fixed |
| P-8 | Info | Last-resort key package retention and healing | Fixed |
| P-9 | Info | Whether a device can sign removals came from its User-Agent | Fixed |
| P-10 | Info | Missing message tracking trusts sender data | Accepted, noted in the threat model |
| P-11 | Info | A message sent before a removal and delivered after it is refused | Accepted by design |
| P-12 | Info | The backup counter floor took any value from the server | Fixed |
| P-13 | Info | ts-mls discards the result of one sender data check | Reported to ts-mls; harmless here, since Hubs checks the sender leaf itself |
| P-14 | Medium | An answer to a key package claim could add a device nobody asked for | Fixed |
| P-15 | Medium | A reinit commit could close a conversation for good | Fixed: devices refuse it |
| P-16 | Low | An old welcome played back to a device could stop its sync | Fixed |

## Part 2, November 2026: client, build, words, server, privacy and the native core

The second half of the review took each area on its own and tried to disprove every finding before keeping it.

### Website, build and words

| ID | Severity | Finding | Status |
| --- | --- | --- | --- |
| W-1 | Critical | A malicious server could make a DM call run without end-to-end encryption | Fixed on the website and in the iPhone, Windows and Mac apps: a device decides from the conversation itself |
| W-2 | Medium | A tapped link in a private conversation was sent to the server | Fixed: links are checked on the device |
| W-3 | Medium | One script run could poison the browser's cache and outlive a fix | Fixed: the service worker serves only files whose hash it holds |
| W-4 | Medium | Other companies' scripts ran on the origin that holds the keys | Fixed: their players run in frames on their own origins |
| W-5 | Medium, latent | Private conversation keys could sit on an organization's own domain | Fixed: private conversations are refused there |
| W-6 | Medium | Signing out and deleting an account left keys and history in the browser | Fixed |
| W-7 | Low | Disappeared messages stayed on disk until a conversation was reopened | Fixed |
| W-8 | Low | The page's security policy failed open, and no release checked it | Fixed |
| W-9 | Info | The browser store still read unsealed values after migrating | Fixed |
| W-10 | Info | Browser translation and cloud spellcheck could read private text | Fixed |
| B-1 | Medium | The CDN served the encryption code with no integrity check | Fixed: the page pins every built file by hash |
| B-2 | Low | A release could carry files that no build had made | Fixed: a carried file must match, byte for byte, what an earlier build made |
| B-3 | Info | A release could change the encryption code with nobody outside noticing | Fixed: signed release fingerprints and a public check ([release-fingerprints.md](release-fingerprints.md)) |
| N-1 | Medium | The Help Center called ordinary DMs private conversations | Fixed |
| N-2 | Low | Public wording did not match the code | Fixed |
| N-3 | Medium | A swapped key was one tap from accepted | Fixed |
| N-4 | Low | Starting over did not say what it does | Fixed |
| N-5 | Low | Linking a device had no warning | Fixed |

### Server, metadata and privacy

| ID | Severity | Finding | Status |
| --- | --- | --- | --- |
| SV-1 | Medium | Reported private text was copied into staff members' ordinary inbox | Fixed, and stored notices rewritten |
| SV-2 | Medium | Two claims at once could get the same one-time key package | Fixed |
| SV-3 | Medium | Nothing bounded stored ciphertext | Fixed: a daily limit per account and the sending limit |
| SV-4 | Low | Deleting an account escaped a report | Fixed |
| SV-5 | Low | Someone who reads the database could still forge stamps | Partly fixed. Back-dated stamps stay possible until the old database stamp key is retired, which is an open decision |
| SV-6 | Low | Linking and backups stopped working at about 65 contacts | Fixed |
| SV-7 | Low | A stolen session cookie could replace a device's key packages | Fixed |
| SV-8 | Low | A welcome was lost when a page of envelopes ended on its commit | Fixed |
| SV-9 | Low | Other gaps between a read and a write in the server's database code | Fixed |
| SV-10 | Info | Retention notes | Partly fixed. How long to keep reported text is an open decision |
| SV-11 | Info | Small hardening notes | Partly fixed. Asking "Confirm it's you" before ending a conversation is still open |

### Native core and C interface

| ID | Severity | Finding | Status |
| --- | --- | --- | --- |
| RF-1 | Medium | A device added back to a conversation could never follow it again | Fixed in the core |
| RF-2 | Low | The core opened fewer late messages than the website | Fixed in the core: skipped keys are kept by count, as ts-mls keeps them |
| RF-3 | Low | A refused welcome deleted the past epochs of the conversation it named | Fixed in the core |
| RF-4 | Low | Secrets are wiped less than the comments said | Partly fixed: keys are out of `Debug`. The rest is open |
| RF-5 | Info | MLS signature checks were not strict for small-order device keys | Fixed in the core |
| RF-6 | Info | Base64 strictness differed between the website and the core | Fixed |
| RF-7 | Info | The C interface dropped `removeLeaves` entries it could not read | Fixed in Windows 0.3.40 |
| RF-8 | Info | Publication notes: an advisory that cannot be reached, license text, test-only exports | Fixed in this repository: the advisory ignore with its reason in `rust/.cargo/audit.toml`, the mls-rs license text and change notices, a bounds check in `interop.rs`, and test-only exports documented as such |

The core fixes reach people as each app ships a build with them.

### Found while bringing the fixes to the apps

| ID | Severity | Finding | Status |
| --- | --- | --- | --- |
| PT-1 | Medium | A device holding a welcome for a safety code review could be left behind by a commit made during the review | Fixed on the website and in Windows 0.3.40, Mac 0.1.59 and the iPhone app |
| PT-2 | Info | A server that attaches a meeting to a group DM could show a meeting screen with no encrypted call, and a ring there joined without the key exchange | Fixed on the website and in Windows 0.3.40 and Mac 0.1.61, and ready for the iPhone app: a ring or a Call button stays encrypted, and so does its rejoin |

## Part 3, November 6, 2026: a fresh review of the encryption

A third internal review looked again at the conversations, calls and server routes, with the same malicious server in mind. The website fixes ship in the same release this repository was published with. The apps get theirs in their next builds.

| ID | Severity | Area | Finding | Status |
| --- | --- | --- | --- | --- |
| AE-2 | Medium | Calls | Answering a one-to-one ring ran the call under the group rule, so a third account could be handed the call key | Fixed on the website; apps in their next builds |
| AE-3 | Medium | Conversations | Starting over dropped every contact's pinned key, so a swapped key joined with no alert | Fixed on the website; apps in their next builds |
| AE-4 | Medium | Conversations | A disappearing timer announcement delivered late could replace a newer one | Fixed on the website; apps in their next builds |
| LK-1 | Medium | Linking | A new device cannot tell that a link hand-off came from the person's own device, so a malicious server could hand it keys of its own; contacts would see a safety code change | Fixed by link v2 ([link-v2.md](link-v2.md)): on the website, Mac and Windows; iPhone in its next build |
| AE-1 | Low | Calls | Rejoining from a reminder could join a former encrypted call without the key exchange | Fixed on the website; apps in their next builds |
| AE-5 | Low | Conversations | A held welcome played back during a review could leave the device an epoch behind | Fixed on the website; apps in their next builds |
| AE-6 | Low | Server | Key package uploads were not signature checked | Fixed |
| AE-7 | Low | Conversations | The server's key package answer can remove the private half a held welcome needs, so a reviewed join can fail without a notice | Open |
| AE-8 | Low | Calls | A key holder can send a junk key copy to a newcomer on an older app first | Open: ends when the older call protocol closes |
| AE-9 | Low | Calls | One connection on the older call protocol turns off key rotation on leave for everyone | Open: ends when the older call protocol closes |
| AE-10 | Low | Reports | The reporter's own words share one field with the verified quotes in a staff case | Open |
| AE-11 | Info | Calls | Whether a call is one-to-one, and whether a group is a meeting, still come from the server's conversation fields | Open |
| AE-12 | Info | Rust core | The core's copy of the test vectors predates one recent rule | Open |
| AE-13 | Info | Conversations | A welcome at exactly the epoch a removal left behind can still be joined | Open |
| AE-14 | Info | Website | Sealed browser storage can be rolled back to older values by someone with the device | Open: documented |
| AE-15 | Info | Calls | The call's key state shows bindings for group members who are not in the call | Open |
| AE-16 | Info | Server | Two read-then-write gaps remain on PostgreSQL | Open |
| AE-17 | Info | Conversations | A device takes the server's word that its own removals statement is already filed | Open |

LK-1 came up while designing history transfer to a newly linked device, which uses the same fix.

## Part 4, November 6, 2026: link v2 and history transfer

Link v2 (the fix for LK-1) and history transfer to a newly linked device were designed, reviewed and built the same day. The design was attacked by a reviewer before any code was written, every implementation replays the same known answers, and each implementation then had its own review: the website at the highest effort, and the Mac and Windows apps together.

**Design review.** No way for the server to forge a hand-off without the secret. Changes made before building: Confirm it's you before anything is uploaded, the check number bound to the secret so a typo shows as numbers that don't match, a state machine on the new device so a link is spent before anything is opened, an exact size for every history part, one 15-minute lifetime, strict checks on every imported field, ASCII-only code parsing, and part counts padded to 1, 4, 16 or 64.

**Website and server.**

| ID | Severity | Finding | Status |
| --- | --- | --- | --- |
| LW-1 | Medium | A browser tab still running the previous release could read the new link record and open an old-style hand-off with its key | Fixed: the new record has its own name, and an old one is cleared |
| LW-2 | Medium | The history upload could be used to store data with no real limit | Fixed: a private conversation device is required, plus a daily cap, a total cap and a strict shape check |
| LW-3 | Low | Two tabs, or a retry, could register a second device from one link | Fixed |
| LW-4 | Low | A busy history slot was counted as a part already sent | Fixed |
| LW-5 | Low | An abandoned link kept its secret on the device | Fixed: it ends after 15 minutes |
| LW-6 | Low | During a screen share the code was only blurred and the check number stayed visible | Fixed: neither is drawn while sharing |
| LW-7 | Low | A failed link told the server to finish, hiding the "another device answered first" warning from the old device | Fixed |
| LW-8 | Low | Merging a very large history was slow | Fixed |
| LW-9 to LW-12, LW-15 | Info | Stricter number and timer checks, check numbers kept out of page translation, a race on the server, no retries past the link's time | Fixed |
| LW-13 | Info | The sealed bundle's length reveals a few bits (whether history was cut short, how many contacts are verified) | Open |

**Mac and Windows apps.** No Critical, High or Medium findings. Low and Info findings (number parsing, timer field checks, a link's secret kept after it was abandoned, text suggestions on the code field, a partial import on a storage error, large answers read whole before their size check, the code shown if the capture shield failed, a waiting link that never expired, history lost on a network error during import) are being fixed: most of the Windows ones in the release that ships link v2 and the rest in its next update, and the Mac ones in its next update.

## What the reviews checked and found sound

- Server authorization: every private conversation route checks the session; conversation routes check membership; envelope routes check the caller's own active device; welcomes and claims may only target member devices; blocks stop sending and claims. Call encryption routes check the channel, that it is a DM, and the caller's own live voice connection.
- No plaintext logging.
- No downgrade or fallback: one ciphersuite, MLS private messages only, and browsers without WebCrypto Ed25519 and X25519 get "unsupported", never a plaintext path. DM calls refuse to join without encryption support.
- Sender binding: the payload's user and device must equal the MLS sender leaf's credential and the server's sender label.
- Franking: the commitment is MLS authenticated data, so the AEAD binds it; receivers check it; the stamp covers the commitment, sender, conversation and time; the report route recomputes both with a constant-time comparison.
- Replay: MLS consumes message keys, and duplicates are ignored.
- Backups: the PRF secret goes through HKDF with a random salt; the account id is in the AAD and checked after opening; a wrong passkey fails.
- Push notifications carry no content.

## What is still wanted

- **An outside audit** of this code and of ts-mls, the first library without one (O3).
- A signed full device list, so additions are bound by the identity key as removals now are (O7).
- The fix for LK-1, so a new device can tell a link hand-off came from the person's own device.
- The open items above: O11, RF-4, AE-7 to AE-17, and the decisions under SV-5, SV-10 and SV-11.
