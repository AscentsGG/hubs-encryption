# Threat model

This covers one-to-one private conversations in Hubs and end-to-end encrypted DM and group DM calls. Ordinary messages, hub channels, hub voice rooms and meetings are not end-to-end encrypted, and are out of scope here.

## What we protect

1. The content of private messages, including timer changes.
2. The media of DM and group DM calls.
3. Private keys: identity keys, device keys, MLS group secrets, key package private keys, link keys, call keys and call connection keys.
4. Who is in a conversation or a call, and who sent each message.
5. The identity keys each device has pinned and the verified marks people set.
6. The integrity of reports: a report proves what was really sent, and by whom.
7. Metadata, as far as we can (see the limits below).

## Who we protect against

| Attacker | What they can do | What they want |
| --- | --- | --- |
| Network observer | Sees TLS traffic | Content, metadata |
| Someone who reads the database | Reads the server's database, backups or logs, but not live memory | Content, keys |
| A malicious or compromised API server | Controls every API response: the device list, conversation members, envelopes and ordering, call participant lists and epochs. It can change the website's code only through a release, and Cloudflare, which serves the website's built files, could change them on the way (see Out of scope). | Content, impersonation, silent membership changes, forged reports |
| A malicious media server | Sees and forwards media packets | Call media |
| A session thief | Holds a person's session cookie, but not their devices or passkeys | Read or join private conversations as them |
| A malicious contact | Is a real member of the conversation | Forge reports, deny sending, add devices, flood |
| A device thief or malware | Reads one device's storage at one point in time | Past and future content |
| Script injection on the website | Runs script on the app's origin | Keys in the device store, and staying after the hole is closed |
| Anyone else with an account | Is not in the conversation | Read, join or disrupt |

## Goals and how we meet them

| Goal | Against | How |
| --- | --- | --- |
| Messages stay confidential | Network, database, API server, others | MLS with ciphersuite 1; the server only ever holds ciphertext |
| Call media stays confidential | Network, database, media server; the API server, with the limits below | Frame encryption with a call key wrapped for each connection. Each connection is signed by its device key and checked against the pinned identity before it gets the key, and an app takes a key only from a connection the call lists and the rule shares with ([protocol.md](protocol.md), Encrypted calls) |
| Calls stay encrypted | API server | A device decides from the conversation itself that a DM or group DM call is end-to-end encrypted, never from what the server says |
| Senders are authenticated | API server, contacts, others | MLS signatures by device keys, device certificates by the identity key, and the payload's user and device must match the MLS sender |
| Membership can't be changed silently | API server, others | Only members can commit; devices accept only the two people, and for their own account only their own identity key; a welcome must be for this conversation's group; device certificates are checked before anyone is added; standalone proposals are refused |
| A swapped identity is noticed | API server | Pinned identity keys, the key change alert, 60-digit safety codes, and sending to a verified contact waits after a change. A device not yet in the conversation keeps a welcome under a changed key unopened until the person reviews it. In calls, a verified contact's changed or unlinked device is held until reviewed |
| Who holds a call key is shown | API server | The call lists every connection with its state. An app takes the key only from a listed connection it shares with, never follows a key maker the call does not list, and keeps the connection its key came from and every one it handed the key to in the list until the key changes. A one-to-one call refuses a third account. Group calls have a 20-digit call code over every signed statement, and signed roster statements report a connection shown to one holder only |
| Device removals are the person's | API server | A removal counts for other devices only with the identity key's signature, the device's own proof, or as part of starting over in the same commit. Once an account's identity key has stated that its removals are signed, its unsigned removals are ignored, and the statement also travels inside the group on every commit from that account, where the server cannot strip it |
| Removing a device takes effect | Session thief, device thief | Removing a device signs out every session that registered or used it, and removes the devices those sessions registered. For a lost or stolen device the website offers starting over with a new identity |
| A dropped message is noticed | API server | Each device counts the other person's MLS generations per epoch and sender; a gap that stays open for 2 minutes shows one line |
| Forward secrecy | Device thief | MLS ratchets and epochs; used keys are erased; old epochs are kept only for late messages (4 epochs, the 10 newest skipped generations) |
| Recovery after a compromise | Device thief | A commit on every device change and a weekly key update from every device |
| Linking a device safely | API server | The link code is a 48-bit fingerprint of the link key plus a 6-digit check, about 2^68 work to swap within the 10 minutes a link lasts, and each link is sealed only once |
| The backup stays private | Database, API server, session thief | The passkey's PRF output, HKDF to AES-GCM, and the account id in the AAD |
| The backup is the newest | API server | A counter inside the sealed backup. A device that saw a newer one refuses an older one, and the server keeps only the newest |
| Keys at rest in the browser | Device thief with a copy of stored values | Every stored value is sealed with AES-256-GCM under a non-extractable WebCrypto key. Once sealed, a plain value is refused |
| Reports can't be forged | Contacts, API server | Message franking: a commitment in the authenticated data, checked by the receiver and stamped by the server. After a conversation ends, only its two people can report from it, for 30 days |
| The timer can't be turned off by the server | API server | Devices follow the last timer announced inside the encryption |
| No downgrade | API server | One ciphersuite, private messages only, no plaintext fallback. An older call app (protocol 2) always shows as Not verified until that path closes. A protocol 3 app checks the server's listing of its own connection against what it posted and ends the call rather than speak protocol 2 itself, and refuses a protocol 2 copy from a sender listed on protocol 3 |
| Notifications carry nothing | Push providers | A push says "New private message" and nothing else |
| The website serves the published code | API server, Cloudflare | Release fingerprints: a signed statement of every file each web release serves, which anyone can check against the live site ([release-fingerprints.md](release-fingerprints.md)). The page names the hash of every script, stylesheet, WebAssembly file and model it may load, so the browser refuses a file the CDN changed |

## What we trust

1. The person's device and its storage.
2. The Hubs API for availability, routing, the device directory and signing people in, but never with content.
3. The media server for forwarding only.
4. The person's passkey authenticator.
5. ts-mls, @hpke/core, @hpke/common, the @noble libraries and WebCrypto on the website, and mls-rs with RustCrypto in the apps, as the cryptographic base. This is the main thing an outside review should test.

## Limits we accept and tell people about

- Trust on first use. The first identity key a device sees for a contact is pinned without proof. Comparing safety codes is the check.
- The server is the device directory. It can withhold devices or messages. It can make devices remove a contact's device only with that person's signature, as part of a visible identity change, or by listing the device as removed while the account has not stated that its removals are signed (some app builds cannot sign yet). Once it has, every commit from that account carries the statement, so a contact's device stops honoring unsigned removals after the next commit it processes from that person, whatever the server shows it. Before that commit reaches it, the server can still remove that person's devices on it. When no device of the other person is left in a conversation, the device says so and holds new messages.
- A message withheld at the very end of an epoch, with nothing later from the same sender in that epoch, cannot be told apart from no message at all.
- Missing message lines trust sender data, which every member can read and write. The other person can forge a header to show messages as missing, or hide real gaps. They could also just not send, so this is noise, not a break.
- A message a device sent before it was removed, delivered after its removal, is refused. Accepting it would let a removed device keep talking in an old epoch through a malicious server.
- A brand-new device restoring a passkey backup has seen no counter, so it trusts the server to hand it the newest backup.
- In Chrome, Edge, Firefox and Electron the browser store key sits in the same profile files as the sealed values, so a copy of the whole profile, decoded with knowledge of the browser's storage format, still opens them. Script running on the page can use the key while it runs.
- The server sees who talks to whom, when, from which device, and roughly how big each message is.
- A key change is a warning, not a block, unless the contact was verified.
- Message history is not copied to new devices.
- Calls: first contact is trust on first use, as in private conversations. A server that is malicious from the start can impersonate someone this device has never pinned. They show as Not verified, and comparing safety codes once closes it.
- Calls: people without private conversations and older apps join unbound. The server can add a connection claiming to be one of them, and it shows as Not verified (or as a second device of theirs).
- Group calls: the server controls who is in the group and can show an added connection to one holder only. That holder sees it, the call codes differ, and roster statements report the disagreement to everyone after 10 seconds. A holder can still share with someone it sees as Not verified.
- Calls: a server can replay an old binding of someone from an earlier call on the same channel to make them look present. That connection's private key is gone, so it cannot hear anything.
- Calls: a stolen device that has not been removed is a valid device of its owner and shows as theirs.
- Calls: a new key when someone leaves depends on the server, which decides when a connection has left. A server that never changes the key leaves it with anyone who held it, including a connection it listed only briefly. Each app still shows every connection it gave the key to, or took it from, marked as left, until the key changes. The people that connection never reached see nothing. An app that starts a new key on its own when someone it saw leaves is a later improvement.
- Calls: the media frame key is AES-128-GCM, derived from the 256-bit call key, so media is protected at 128 bits.
- Calls: a device that has an identity refuses its own account on a device that isn't linked. Someone in a call from two of their own devices, one not linked, gets the key on the unlinked one only from others who let it in, and is told to link that device.

## Out of scope

- A device or operating system that is compromised at the time, and malicious browser extensions.
- A malicious release of the website. The website is served by the same people who run the API, so a bad release could leak keys. Release fingerprints make that visible: every web release publishes a signed list of every file it serves, made and signed on a computer that is not one of our servers after checking what the site actually serves, and anyone can check the live site against it. That shows a change; it does not prevent one, and a server could still send one account different files. The website's built files come from `cdn.thehubs.gg` through Cloudflare, a second operator, but the page itself comes from thehubs.gg and pins the hash of every file it loads. The Mac and Windows apps built on Electron load the website, so their installer signatures do not cover this code; the same pinning and fingerprints do. This is the main structural limit of encryption delivered through a browser.
- Traffic analysis beyond the metadata above, and timing side channels in the platforms' crypto backends.
- Denial of service by the server or the network.
- Ordinary messages, hub calls, recordings and captions, which are not end-to-end encrypted.
- Private group conversations, which are not built yet. Clients enforce one-to-one.

## Questions we would like reviewers to look at

1. Is a basic credential plus a certificate signed by the identity key enough? Removals are now signed by the identity key or the device itself, with an unsigned path kept until an account states otherwise. Additions remain certificate-only: should the identity key also sign the full device list with a version counter?
2. Calls bind each connection to the account identity with the private conversation device key instead of the MLS exporter. Are the binding, the per-person rule and the HKDF wrap sound, and are the call code and roster statements enough for group calls?
3. Is Not verified the right treatment for unbound people and older apps until the older protocol is closed?
4. Are the key retention and padding settings right for this use?
5. The website uses ts-mls's `decryptSenderData` (an internal module) to learn the sender before processing a message, and both implementations read the sender data before processing to count generations. Is that safe and stable?
6. Is the franking construction sound against a sender who controls the franking key?
7. Is the missing message rule (generation gaps per epoch and sender, shown after 2 minutes) sound?
8. Is the removal rule and the signed removals statement a sound transition while some app builds cannot sign?
