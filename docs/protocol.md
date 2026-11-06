# Protocol

This page describes private conversations and encrypted calls as every Hubs client implements them: the website (`typescript/`) and the iPhone, iPad, Mac and Windows apps (`rust/`). Byte formats are pinned by [test-vectors/test-vectors.json](../test-vectors/test-vectors.json), and every step below is exercised by [test-vectors/e2ee-test-vectors.json](../test-vectors/e2ee-test-vectors.json). Both test suites read the same files. Bytes travel as standard base64 with padding inside JSON, and a second spelling of the same bytes is refused.

`‖` means byte concatenation, and `\0` is a single zero byte.

## Choices

| Choice | Value | Why |
| --- | --- | --- |
| Protocol | MLS 1.0, RFC 9420 | Forward secrecy, post-compromise security, authenticated senders, and every device is its own member |
| Ciphersuite | `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (suite 1) | The mandatory suite, and it runs on WebCrypto in every current browser |
| Web library | ts-mls 1.6.4, with @hpke/core 1.9.0, @noble/hashes 2.0.1 and @noble/ciphers 2.1.1 | Maintained, small, and it passes the RFC 9420 interoperability vectors |
| Native library | mls-rs 0.56.0 with mls-rs-crypto-rustcrypto 0.22.1 | Maintained by AWS. We carry three small changes, listed in `rust/vendor/mls-rs/CHANGES.md` |
| Credential | MLS basic credential carrying `{v, userId, deviceId, identityPublicKey, certificate}` | Binds each device key to the account's identity key without a certificate authority |
| Group id | The conversation id | Ties each MLS group to one conversation |
| Ratchet tree | Sent in the welcome | The server never needs the tree |
| Wire format | MLS private messages only, for application messages and commits | The server sees no membership details in the clear |
| Key retention | 4 past epochs, the 10 newest skipped generations, at most 200 forward steps | Handles out-of-order delivery without keeping old keys around |
| Padding | Pad until 256 bytes | Short messages all look the same size, on every platform |
| Key packages | 20 per device, one-time, valid 90 days, replaced after 30 days, plus one last-resort key package per device | Lets someone add a device that is offline, with a bounded lifetime. The last-resort package (RFC 9420, section 16.8) keeps a device reachable when its one-time packages run out |
| Device removal | Signed by the account's identity key or by the device itself; other devices remove a member only under the removal rule | The server alone cannot make devices drop a person's device |
| Missing messages | Each device counts the other person's MLS generations per epoch and sender, and shows one line when a gap stays open for 2 minutes | The server cannot drop a message in the middle of an epoch unnoticed |
| Key updates | Each device commits fresh keys at least every 7 days | Post-compromise security even when no device changes |

We considered libsignal and its ports (AGPL or GPL), Wire's core-crypto (GPL), Olm (deprecated, with known timing issues) and the Matrix crypto SDK (it would have meant adopting Matrix's whole device and sync model).

No cryptographic primitive is ours. For conversations, signatures, HPKE, AEAD, KDF, HMAC, hashing and random numbers all come from the ciphersuite of the MLS library on each platform. Calls use WebCrypto directly (P-256 ECDH, HKDF, AES-256-GCM, HMAC, SHA-256, and Ed25519 called the same way the ciphersuite calls it), so the call code loads no MLS code.

## Formats we define

| Format | Definition |
| --- | --- |
| Device certificate body | `"hubs private dms device v1\0"` ‖ userId ‖ `"\0"` ‖ deviceId ‖ `"\0"` ‖ device public key (32 bytes) |
| Safety code | For each person, SHA-256(`"hubs safety code v1\0"` ‖ userId ‖ `"\0"` ‖ identity public key). Six groups from consecutive 5-byte big-endian chunks, each mod 100000 and zero padded to 5 digits. The two people's halves are ordered by user id, so both screens show the same 60 digits. |
| Link code | The first 6 bytes, in hex, of SHA-256(`"hubs private dms link id v1\0"` ‖ link public key) |
| Link check | SHA-256(`"hubs link check\0"` ‖ link public key), first 4 bytes as a big-endian number mod 1,000,000, zero padded to 6 digits |
| Link hand-off | HPKE base mode seal of the identity bundle JSON, info `"hubs private dms link v1"`, empty AAD |
| Passkey backup | PRF input SHA-256(`"hubs private dms backup prf v1"`). Key = HKDF-Expand(HKDF-Extract(salt, PRF output), `"hubs private dms backup v1"`, 16). AES-128-GCM with a random 12-byte nonce and AAD `"hubs private dms backup v1"` ‖ account id. |
| Backup counter | The sealed backup bundle carries `counter`, one more than any backup the saving device knew of. A link bundle carries `backupCounter`. The seal and its labels are unchanged. |
| Franking commitment | HMAC-SHA256(franking key, canonical payload bytes), carried as the MLS authenticated data |
| Canonical payload bytes | `JSON.stringify(["hubs private dms message v1", v, id, kind, body, sentAt, expiresInSeconds, userId, deviceId])`, exactly as JavaScript writes it |
| Server stamp | HMAC-SHA256(server stamp key, JSON `["hubs private dms stamp v1", commitment, sender, conversation, time]`). The envelope also names the stamp key's id, and a report sends it back. |
| Self-removal proof | The device key's Ed25519 signature over `"hubs private dms self-remove v1\0"` ‖ userId ‖ `"\0"` ‖ deviceId ‖ `"\0"` ‖ at, where `at` is the time in milliseconds, in decimal with no leading zeros, and there is no zero byte at the end |
| Device removal | The identity key's Ed25519 signature over `"hubs private dms remove device v1\0"` ‖ userId ‖ `"\0"` ‖ deviceId ‖ `"\0"` ‖ at ‖ `"\0"` ‖ the removed device's public key (32 bytes) |
| Signed removals statement | The identity key's Ed25519 signature over `"hubs private dms signed removals v1\0"` ‖ userId ‖ `"\0"` ‖ identity public key (32 bytes) |
| Signed removals note | A commit's authenticated data once the sender's account has made the statement: `"hubs private dms signed removals note v1\0"` then the statement's 64-byte signature. The commit's signature and encryption cover it, and clients that do not know it ignore it. |
| Message generation | Read from the MLS sender data of an application message (RFC 9420, section 6.3.2) without opening its content: the epoch, the sender's leaf and the generation |
| Browser store at rest | Each stored value as JSON, sealed with AES-256-GCM under a non-extractable WebCrypto key kept in the same database, a random 12-byte IV, and additional data `"hubs private dms store v1\0"` ‖ userId ‖ `"\0"` ‖ value key. The website only: the apps keep their own protected stores. |

Every removal signature is a raw Ed25519 signature over the body, never MLS SignWithLabel, and is verified strictly: no small-order keys, a canonical S, and exact sizes. A time that is not a safe JavaScript integer never verifies.

## Rules every client follows

### Library settings

1. MLS 1.0 with ciphersuite 1 only. No other suite and no plaintext fallback, ever.
2. Basic credentials whose identity bytes are exactly the JSON `{"v":1,"userId":...,"deviceId":...,"identityPublicKey":...,"certificate":...}`, in that key order.
3. Every credential is checked: the certificate must be a strict Ed25519 signature by the named identity key over the device certificate body. A device key of small order is refused.
4. Commits and application messages are private messages only. Public messages are refused. Only a commit changes a conversation: standalone proposals are refused, and any an older client stored are dropped when a group loads.
5. Key packages are valid from an hour in the past to 90 days ahead. A client refuses to add a key package that is valid for longer, expired, or not yet valid.

### Keys on the device

6. The identity key is made on the first device and never leaves the person's devices, except sealed for linking or inside the passkey backup.
7. Private keys, group state and stored messages live in the platform's protected storage. A client saves the group state after every change and before sending anything that used it, so a message key is never used twice.

### Setting up a device

8. The first device registers its identity key, device key and certificate. If the account already has an identity key, the client links or restores instead, and only replaces the identity when the person explicitly chooses to start over. Contacts then see a key change notice.
9. Linking, on the new device: make an X25519 HPKE key pair, open a link, check that the server's code matches the link key, and show the code and the 6-digit check.
10. Linking, on the old device: fetch the link key for the code the person typed, refuse it unless its fingerprint equals the code and the person confirms the check number matches, then seal the identity bundle to it once. Together the code and the check stop the server from swapping in its own link key. Links expire after 10 minutes.
11. Passkey backup: seal the identity bundle with the backup key above. A client refuses a bundle that belongs to another account, and refuses a backup whose counter (0 when missing) is below the highest it has seen, by saving, restoring, or from the device that linked it. Where a passkey or browser cannot produce a PRF output, the backup is not offered.
12. A link or backup bundle carries the pins, the verified marks, open key change alerts and the removal statements a device has seen, so a new device holds sending and refuses unsigned removals as the old one does.
13. Starting over, linking again and restoring a backup make a new device id. A new device id never continues an old group or opens a welcome made for the old one, so a device drops all of those.

### Each conversation

14. Pin the other person before opening any welcome, and pin each person's identity key the first time it is seen.
15. Process envelopes in order:
    - A welcome for one of your key packages: join, but only if the group id is this conversation's id and the membership rule passes. Then delete that key package, unless it is the last-resort one. A refused welcome changes nothing in any other conversation.
    - A welcome whose other person carries an identity key other than the pinned one: raise the key change alert, pin the new key, and keep the welcome unopened until the person compares codes or dismisses the alert. While it waits, a welcome under the key pinned before it is joined instead.
    - Your own device's envelope: skip it.
    - Ciphertext you already handled: skip it quietly. Clients remember the SHA-256 fingerprints of the last 1000.
    - A commit: process it. If the membership rule fails, keep the state from before. Release the old epoch's secrets only after the commit is accepted.
    - A message: decrypt it and parse the plaintext as strict UTF-8 JSON. Refuse it unless the payload rules pass, the authenticated data equals the franking commitment, and the payload's user and device match both the MLS sender's credential and the server's sender label. A refused message never changes state.
16. Membership rule: every device of your own account carries your identity key; there is at most one other account, and it is the pinned person; all of that person's devices share one identity key.
17. Payload rules: exactly the fields `v, id, kind, body, sentAt, expiresInSeconds, userId, deviceId, frankingKey`. `v` is 1. `id` matches `[A-Za-z0-9_-]{1,64}`. `kind` is `text` or `timer`. `body` is well-formed text of at most 4000 UTF-16 units, and empty for a timer. `sentAt` is a non-negative safe integer in milliseconds. `expiresInSeconds` is one of 0, 300, 3600, 28800, 86400, 604800 or 2419200. `userId` (up to 128 characters) and `deviceId` (up to 64) are not empty. `frankingKey` is 32 bytes.
18. When a person's identity key changes: show a notice in the conversation, raise an alert until it is reviewed, and clear the verified mark. If the person had been verified, hold sending until the codes are compared again or the alert is dismissed. A new device under the same identity key shows nothing.
19. Adding and removing devices: keep only the two people's devices (your own only with your identity key), verify each certificate, claim one key package per missing device, and post one commit plus a welcome for each added device. A device the server stopped listing is removed in the same commit only when the removal rule below allows it. The resulting group must pass the membership rule before the commit is sent. If another device committed first, throw the commit away, catch up and try again. A group a device made itself gives way at once to a welcome for the same conversation.
20. Removal rule: a removal counts when its proof verifies (the identity key signed the device removal, or the device signed its own self-removal), and never when a proof is present and fails. Without a proof it counts only when the person started over in the same commit (a key package claimed for that commit carries a valid certificate for that person under another identity key, which every device shows as a safety code change), or when this device has not seen that identity key's signed removals statement. A device the server merely lists under another key is not a start over.
21. Once an account has made the signed removals statement, every commit from its devices carries the signed removals note, and each conversation gets one such commit soon after. A contact's device learns the statement from the group even if the server never shows it.
22. A device removed by a commit stores no group, keeps its messages, shows a notice and takes the next welcome. A device added back to a conversation follows it again from that welcome.
23. If a change leaves no device of the other person in a conversation, the device shows a notice and holds new text messages until one is back.
24. If a device has not committed in a conversation for 7 days, it commits an update with no proposals. A device that joined through its last-resort key package commits new keys on its next sync, and keeps that package's private half only until the server's queue time has passed after a newer one replaced it, so no welcome made for the old one can still be waiting.

### Sending

25. Build the payload with a fresh random id, the device's clock as `sentAt`, the timer last announced inside the encryption, the user and device ids, and a fresh random 32-byte franking key. The commitment over the canonical bytes becomes the MLS authenticated data. Save the group state, then post.
26. A timer change is a `timer` payload with an empty body. Before any announcement, a client uses one week; the server's copy of the timer can never turn disappearing messages off on its own.

### Showing and keeping messages

27. A received message is shown at `min(now, max(sentAt, relay time minus 10 minutes))`, so a sender's clock cannot place it far in the future or the past.
28. A message disappears `expiresInSeconds` after the device received it, and a sent message that long after it was sent. Expired messages are deleted from the device.
29. Search runs only over the device's own copy. Private text is never sent to any server feature.
30. Missing messages: for each epoch and sender leaf of the other person, a device tracks the next generation it expects and the gaps below it, from each application message's header (read before the content is opened, so a message that then fails to open still counts). A gap still open 2 minutes after it was seen becomes one line where the message would have been: "A message from Ana didn't arrive." If the message comes after all, the line goes away. A message withheld at the very end of an epoch, with nothing later from the same sender in that epoch, cannot be told apart from no message.

### Reporting

31. A report carries up to 5 messages from one other person, each with its payload, commitment, the server's stamp and the envelope's time. The server recomputes the commitment and its own stamp, and only accepts the report when both match. A changed message, sender or time fails. After a conversation ends, only its two people can still report from it, for 30 days.

### Ending and removal

32. Ending a conversation deletes all of its ciphertext on the server for both people. Each device deletes its own copy and the group state. A device that is removed deletes every key, group state and message it holds.
33. Removing a device of your own: the website signs the device removal with the identity key, and an app signing out sends its own self-removal proof. The server accepts a self-removal only for a device of the signed-in account that is not already removed, with a valid signature and a time within 5 minutes of the server's clock. Removing a device signs out every session that registered or used it. For a lost or stolen device, the website then offers starting over with a new identity, since that device still holds the identity key.
34. The signed removals statement is made once every device of an account runs a client that signs removals. A request can only mark a device as able to sign removals, never take that back, so naming a device with an old client cannot hold the statement off.

### Proving it

35. Each implementation replays `test-vectors/e2ee-test-vectors.json` in its own tests: every primitive, every format above, every rule table, and every MLS step in order, reaching the same plaintexts, members and epochs, and refusing every refusal without changing state. The Rust tests also replay `test-vectors/mls-interop-vectors.json` and run a live conversation against the TypeScript implementation in both directions.

## Encrypted calls

One-to-one and group DM calls are end-to-end encrypted. A device decides from the conversation itself that a call is end-to-end encrypted, never from what the server says, so the server cannot turn the encryption off for a call that should have it.

| Choice | Value | Why |
| --- | --- | --- |
| Media encryption | LiveKit end-to-end encryption with a shared key. The frame key is HKDF from the call key with LiveKit's salt `"LKFrameEncryptionKey"`, and it is an AES-128-GCM key (LiveKit's default), so media is protected at 128 bits even though the call key is 256 bits | The media server forwards frames it cannot read |
| Connection keys | ECDH P-256, a fresh pair per connection, private key non-extractable, `deriveBits` only | Available everywhere WebCrypto is |
| Call key | 32 random bytes, made by the connection the server names key maker, when the call lists that connection | |
| Binding (protocol 3) | The connection key signed by the device's private conversation device key (Ed25519), which the account identity key certifies | Ties each connection to an account identity every app pins, so the server cannot add a listener unseen |
| Wrapping (protocol 3) | AES-256-GCM under HKDF-SHA256 of the ECDH secret, with info and AAD binding the call, the epoch, the key slot and both statements | Only the bound sender, or the recipient, can make a copy that opens |
| Call code (protocol 3) | 20 digits: an HMAC under an HKDF of the call key over every connection's statement | The group call check. One-to-one calls rely on the safety code |
| Protocol 2 | The wrap under the raw ECDH secret and a 12-digit code, kept for pairs with an older app until that path closes. An older app always shows as Not verified | Shipped apps keep working |

The code is `typescript/src/calls.ts`: the formats and the rule, standalone, with no MLS code. The known answers are the `calls` section of `test-vectors/e2ee-test-vectors.json`.

### Call formats (protocol 3)

lp(s) is a 2-byte big-endian length then the UTF-8 bytes, at most 255 bytes, and a string with a lone UTF-16 surrogate is refused. Labels are ASCII then one zero byte. u8 and u16 are big-endian. P-256 public keys are 65 bytes (0x04 ‖ X ‖ Y). Ed25519 is RFC 8032. HKDF is RFC 5869 with SHA-256 and a salt of 32 zero bytes.

| Format | Definition |
| --- | --- |
| Binding body B | `"hubs-call-binding-v3\0"` ‖ lp(channelId) ‖ lp(leaseId) ‖ lp(userId) ‖ lp(deviceId) ‖ identityPublicKey (32) ‖ devicePublicKey (32) ‖ connectionPublicKey (65). The signature is Ed25519(device key, B). A binding is valid when the device key signed B and the identity key signed the device certificate body for the same userId and deviceId. The verifier builds B from its own channel id and the listed lease, account and connection key. |
| Unbound statement U | `"hubs-call-unbound-v3\0"` ‖ lp(channelId) ‖ lp(leaseId) ‖ lp(userId) ‖ connectionPublicKey (65), not signed |
| Connection hash h | SHA-256(B) for a connection with a binding whose fields have their exact sizes (whether or not it verifies), else SHA-256(U) |
| Wrap info | `"hubs-call-wrap-v3\0"` ‖ lp(channelId) ‖ lp(epoch) ‖ u8(keyIndex) ‖ h of the sender ‖ h of the recipient |
| Wrap | Z is the P-256 ECDH X coordinate (32 bytes). wrapKey = HKDF(Z, info, 32). sealed = AES-256-GCM(wrapKey, 12 random bytes, callKey, aad = info), 48 bytes. |
| Call code | codeKey = HKDF(callKey, `"hubs-call-code-v3"`, 32). T = `"hubs-call-code-v3\0"` ‖ lp(channelId) ‖ lp(epoch) ‖ u8(keyIndex) ‖ u16(n) ‖ every h sorted ascending bytewise. mac = HMAC-SHA256(codeKey, T). Four groups of five digits, each the big-endian 40-bit number at mac[5i..5i+4] mod 100000. |
| Roster statement V | `"hubs-call-view-v3\0"` ‖ lp(channelId) ‖ lp(leaseId) ‖ lp(epoch) ‖ u8(keyIndex) ‖ SHA-256(T), signed by the connection's device key. It holds no secret. |
| Protocol 2 wrap | AES-256-GCM under Z itself, with AAD `"hubs-call-key\n"` ‖ channel ‖ `"\n"` ‖ epoch |
| Protocol 2 code | HMAC-SHA256(callKey, `"hubs-call-code-v2\n"` ‖ epoch ‖ `"\n"` ‖ the sorted public keys joined by `"\n"`), six 2-digit values from 16-bit chunks mod 100 |

### Who gets the call key

Each app decides for every other connection, in this order (`callPeerDecision`, and `callPeerDecisions` for the whole list). It wraps the key only for connections it shares with, and accepts a copy only from one. A copy's protocol is the pair's: 3 when both are on 3, else 2.

1. Its own connection: skipped.
2. A binding that does not verify, or an older app that sends one: refused.
3. In a one-to-one call, an account that is neither this account nor the other person: refused.
4. Once the older path is closed, an older app: refused, and told it needs an update.
5. This account: bound under this device's identity key is "you, on another device". Bound under another key is refused. Bound while this device has no identity is "you, on another device", not checked. Unbound or an older app is refused when this device has an identity, and is "you, on a device that isn't linked" when it has none. A device with an identity treats its own account as verified, so, as for a verified contact, a device of its own that isn't linked gets no key from it, because the server could claim such a device at will. A device without an identity cannot tell its own devices apart, so it lets them in, shown as not linked.
6. Another account, unbound or an older app: held when this device verified that person (or has an unreviewed change from a verified contact), otherwise shared as Not verified.
7. Another account, bound: with no identity on this device, Not verified. With no pin yet, pinned now and Not verified. Pinned and verified under that key, Verified. Pinned and not verified, Not verified. Under another key, the change is recorded (the alert is raised and a verified mark is cleared), and the connection is held if the contact was verified, otherwise shared as Safety code changed. With an unreviewed change, held if the contact was verified, otherwise Safety code changed.
8. One account bound under two identity keys in the same call: the connections under a key other than the pinned one are refused (all of them when none matches the pin), and no change is recorded from them.

Pins and alerts are the same ones private conversations use, so calls and conversations share one trust state. A refused copy is reported to the server, which deletes it, stops that sender's copies for this connection in this epoch, and shows the connection as waiting to the other holders. Each app refuses an epoch it held or saw replaced during the connection, and a new key must name the epoch it replaces.

### Where the call key comes from

The rule above says who may hold the key. These rules say where an app may take it from, so the server cannot hand anyone a key it chose, from a sender nobody sees.

1. A copy counts only when its sender is a connection the call lists right now, whose binding this app checked and which the rule shares with. The copy's sender fields must match that listing, its protocol must be the pair's (a protocol 2 copy from a sender listed on protocol 3 is refused), and it must open. A copy from a sender the call does not list is refused for good, even when the sender really left: another holder sends one, or the server starts a new key.
2. The app makes the key only when the call names it key maker. It never follows a key maker the call does not list. It waits for a copy from a listed sender, and if none comes within 20 seconds while the named key maker is still unlisted, the call is not secure ("This call is not secure. Join again."), whether joining or during a key change.
3. Each connection is listed once. A connection listed twice ends the call as not secure.
4. The app's own row must be exactly what it posted: its account, connection key, protocol 3 and the binding it sent (or none, when it joined unbound). A row listed lower, without its binding, or with another one ends the call as not secure. The app never falls back to protocol 2 for itself.
5. For the key held now, the app remembers the connection it came from and every connection it handed it to. They stay in the people list, as last listed and marked as left, until the key changes, even if the server stops listing them. The source is marked in the list ("Gave you this call's key."). The call code and roster statements still cover the listed connections only.

An honest server never does any of the things that end a call here.

## Rotation

- MLS epoch secrets change on every commit, and every device commits fresh keys at least weekly.
- Key packages are one-time and topped up to 20 whenever a device opens a private conversation. The server stores only key packages inside the lifetime policy with at least 60 days left, and never hands out one that a client would refuse.
- An identity key changes only when its owner starts over.
- The server's stamp key carries a key id. Rotating puts a new key first and keeps the old ids for verifying older stamps.
- The browser store key is made once per browser profile and account and never leaves the browser's database.
- Call keys are new for every call, and in a call where every app is on protocol 3 a new key replaces the old one whenever someone leaves. The server decides when that happens: see [threat-model.md](threat-model.md).

## Release fingerprints

The website's code is what runs these rules in a browser. With every web release we publish a signed statement of every file the release serves, and anyone can check the live site against it. See [release-fingerprints.md](release-fingerprints.md).
