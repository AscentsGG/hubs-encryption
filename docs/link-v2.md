# Device linking (link v2) and history transfer

November 6, 2026. One design for the website, iPhone and iPad, Mac and Windows. Android follows when it gets private conversations.

Three changes ship together:

1. **Link v2** fixes LK-1 ([reviews.md](reviews.md)): a new device can tell that the link hand-off came from the person's own device.
2. **History transfer**: when a device links from another one, it can bring that device's private conversation history, sealed so only the new device can open it.
3. **Keeping browser data** (website only).

The byte formats are fixed by [`test-vectors/link-v2/reference.mjs`](../test-vectors/link-v2/reference.mjs) and its output `vectors.json`, and by `outer-vector.json` for the outer HPKE layer. Every client replays both files in its tests. The reference wins if this text and it ever disagree.

## The problem link v2 fixes

Today the new device posts its link public key to the server, and the old device seals the identity bundle to that key with HPKE base mode. Base mode does not authenticate the sender, and the server stores the key, so a malicious server can seal a bundle of its own (an identity and contact pins it controls) and the new device takes it.

## Link v2

### On the new device (beginLink)

1. Make the link key pair as today (X25519, HPKE).
2. Make a **link secret**: 5 random bytes from the platform's secure random source.
3. Post only the public key, exactly as today. The secret never leaves this device in any form: not in a request, URL, header, log, analytics event, crash report, notification or clipboard.
4. Keep the secret with the link private key, under the same protection, and delete both when the link finishes, fails or is abandoned.
5. Show the **full code**: the 12-character link id (hex) then the secret as 8 Crockford base32 characters, grouped in fours: `a1b2 c3d4 e5f6 04HM ASW9`. Show the **v2 check number** (below), not v1's.
6. No Copy button for the code. Hide the code while the screen is captured or shared (the apps' capture shields; on the website, while this device shares its screen in a Hubs call).

### The v2 check number

`check = (first 4 bytes of SHA-256("hubs link check v2\0" || link public key || secret) as an unsigned big-endian integer) mod 1,000,000`, shown as 6 digits with leading zeros.

The old device computes it from the key it fetched and the secret it was given, and shows it. The person compares it with the new device's. A typo in the secret makes the numbers differ before anything is sealed. The check never reaches the server.

### Typing the code (old device)

- One field takes the whole code. Turn off spellcheck, autocorrect, autocomplete and text suggestions on it (`spellcheck="false"`, `autocomplete="off"`, `autocorrect="off"`, `autocapitalize="off"` on the web; the platform equivalents in the apps). No paste history is kept.
- Normalize it exactly like `normalizeCode` in the reference: remove ASCII space, tab and hyphen-minus; refuse the whole input if any other character is outside ASCII 0-9, A-Z, a-z (so no locale case rules and no Unicode folding); then ASCII upper case.
- It must be 20 characters. The first 12 must be hex; they are sent to the server in lower case, as today. The last 8 are the secret: Crockford base32 with O read as 0 and I or L read as 1. Anything else is refused.
- A 12-character code (an older app's) is refused with: "The new device needs the latest version of Hubs. Update it, then start linking again."
- The secret is never sent anywhere and is forgotten when the approval finishes or is cancelled.

### Approving and sealing (approveLink, old device)

In this order:

1. The numbers match (the person confirms the v2 check).
2. **Confirm it's you**, the same step-up `/seal` already needs, before anything is uploaded. The approval screen says what will be shared: "This device's private conversation keys will go to the new device" and, when the switch is on, "and its messages".
3. If history is on: build the history once, upload every part (below). A retry reuses the same sealed parts.
4. Seal the bundle and post it to `/seal`.

Sealing:

1. `K = HKDF-SHA256(salt = link public key bytes, ikm = secret bytes, info = "hubs link v2 key", length 32)`.
2. Inner layer: `nonce (12 random bytes) || AES-256-GCM(K, nonce, plaintext, aad)` with a 16-byte tag. For the bundle, `aad = "hubs link v2\nbundle\n0\n1\n" + userId + "\n" || link public key` (UTF-8, then the raw key bytes).
3. Outer layer: HPKE base mode (suite 1, as `sealForLink` today) to the link public key over the inner layer's bytes, with info `"hubs private dms link v2"`.
4. Wire: `{"v":2,"enc":<base64>,"ct":<base64>}`, standard padded base64, keys in that order.

If `/seal` answers 409 (another seal is already there), the old device shows: "Another device answered this link first. Don't use the new device. Start linking again." and stops.

### Opening (finishLink, new device): a state machine

States, kept in the device store: **waiting**, **spent**, **registered**, **imported**, **failed**.

- Only one finishLink runs at a time; a poll while one runs is skipped.
- **waiting**: fetch the seal. Nothing there: stay waiting. Something there:
  1. If the wire value does not parse, or its `v` is not the number 2: go to **failed** with "Update Hubs on your other device, then start linking again." Do not open it. A v2 app never calls v1 `openLink`.
  2. Refuse if more than 15 minutes have passed since beginLink by this device's clock: **failed**, "That link took too long. Start again."
  3. Mark the link **spent** in the store, durably, before opening anything. From now on no other seal value is ever opened for this link.
  4. Open the outer layer, then the inner layer with K and the bundle AAD. Every failure here looks the same and goes to **failed** with "This link didn't come from your other device, so nothing was set up. Start again from your other device." Delete the link keys and secret, stop polling, register nothing.
  5. Parse the bundle (strict, see "Parsing rules"). `v` must be the number 2 and `userId` this account. Its identity key must match the identity key the server lists for this account's existing devices; if the account has devices and none matches, **failed** with the same sentence as step 4.
  6. Keep the verified bundle in the store.
- **spent** with a kept bundle: register from it (as today, including step-up and retries). Then **registered**. Errors here may retry; they never reopen a seal.
- **registered**: if the bundle has history, import it (below). Then **imported**, then `/finish`, then delete the link keys, secret and bundle.

## History transfer

### What is sent

- Only from a link the person approved on the old device after Confirm it's you. The switch **Bring messages to the new device** is on by default.
- Every private conversation this device has local messages for that has not ended. For each one:
  - `conversationId` (the server's id, a UUID), `peer` (the other person's account id), and the conversation's timer state under AE-4: `{ seconds, sentAt, id }` of the newest timer announcement, or null.
  - Its messages of kind `text` and `timer` (never `notice`), minus anything expired (`expiresAt` at or before now) or deleted on this device.
  - A text message: `{ id, kind: "text", body, sentAt, expiresAt, senderUserId }` plus `proof` when this device holds one.
  - A timer message: `{ id, kind: "timer", body: "", seconds, sentAt, expiresAt: null, senderUserId }`. The new device writes the line's words itself, as it does for a received timer.
- Newest messages first if the history would pass the cap; then `truncated: true`.

### Format

- JSON `{ "v": 1, "conversations": [ ... ] }`, UTF-8, no byte order mark, no duplicate keys, integers as plain decimal digits (no exponent, no fraction).
- Split across parts so each part's JSON is at most 262,140 bytes. A conversation may continue into the next part; it then appears again with the rest of its messages. The new device takes a conversation's `peer` and `timer` from its first appearance, and a message id seen twice keeps the first.
- Each part's plaintext is exactly 262,144 bytes: 4-byte big-endian length, the JSON, then zero bytes. A reader refuses a length over 262,140 or any non-zero padding byte.
- The number of parts is padded up to 1, 4, 16 or 64 with empty parts (`{"v":1,"conversations":[]}`), so the server learns the size only in those four steps. More than 64 parts' worth keeps the newest and sets `truncated`.
- The bundle carries `history: null | { parts: 1 | 4 | 16 | 64, digest, truncated }`. `digest` is the hex SHA-256 over every part's padded plaintext, in order. The part count always comes from the bundle, never from the server.
- Each part is sealed like the bundle: inner AES-256-GCM under K with `aad = "hubs link v2\nhistory\n" + index + "\n" + count + "\n" + userId + "\n" || link public key` (index from 0, decimal, no leading zeros), then the outer v2 HPKE seal. Every sealed part is exactly 349,652 characters on the wire.

### Routes (server)

- `POST /api/private-dms/links/:id/history` with `{ index, count, sealed }`, then the bundle on `/seal`, then the new device's `GET /api/private-dms/links/:id/history/:index` for each part, then `/finish` as today.
- Upload uses the same Confirm it's you check as `/seal`, with the same native-app rule `/seal` has today.
- Only the account that opened the link may upload or fetch, only while the link is open and not finished.
- `count` is 1, 4, 16 or 64 and the same for every part of a link; `index` is below it. `sealed` must be exactly 349,652 characters (refuse anything else before storing). The first upload of an index wins: 409 after, and the old device treats 409 as already sent.
- One link with history per account at a time.
- Links keep one lifetime, 15 minutes, matching the new device's rule. Expired links and their parts are deleted by the existing sweep; `/finish` deletes them at once.
- Rate limits like `/seal`. The server stores only the sealed value, the index, the count and times, and never logs the body.

### Importing (new device)

1. Fetch every part first, then open. Refuse a part of the wrong size before decrypting. Any failure (missing, wrong size, outer or inner open, padding, UTF-8, JSON, digest) imports **nothing** and looks the same: keep the device set up and show "Your messages couldn't be brought over. New messages will still arrive here."
2. Check the digest over the padded plaintexts against the bundle's.
3. Check every field before storing anything:
   - `conversationId` is a UUID (lower-case hex, the server's format). `peer` is a non-empty account id; adopt it only if this device has no peer for that conversation yet, and skip the conversation if it has a different one.
   - Message `id` matches `^[A-Za-z0-9_-]{1,64}$`. `kind` is `text` or `timer`.
   - Text: `body` is a well-formed string of at most 4,000 UTF-16 code units.
   - Timer: `body` is empty and `seconds` passes `isPrivateDmTimer`.
   - `sentAt` is a safe integer with `0 <= sentAt <= now + PRIVATE_DM_CLOCK_SKEW_MS`; `expiresAt` is null or a safe integer.
   - `senderUserId` is this account or that conversation's peer.
   - `proof` is kept only if its payload passes `privateDmPayloadProblem` and its `id`, `body` and `userId` equal the message's; otherwise the message is kept without it (it just can't be reported from this device).
   - Drop a message that fails, and drop anything expired by now.
4. Store each conversation's messages in the same store and sealing as received ones. Never replace a message this device already holds. Imported messages expire on their own `expiresAt`.
5. Timer: adopt the carried timer state only if it is newer than this device's under the AE-4 order (sentAt, then id), and only if `seconds` passes `isPrivateDmTimer`.
6. A conversation the device isn't in yet keeps its imported messages until it joins. A conversation that has ended is skipped.
7. Show a quiet line above what was brought: "Earlier messages, from your other device."

### What this does not change

- The new device still joins each conversation through MLS. History transfer only fills the screen; it gives no group secrets.
- The server never keeps message history beyond the link's 15 minutes, and never in a form it can open.

## Threats and answers

| Threat | Answer |
| --- | --- |
| The server seals its own bundle or history to the new device | The inner layer needs the secret. One wrong seal ends the link (a chance of 1 in 2^40 per link). |
| The server guesses the secret offline from the real hand-off | It sees only HPKE output to the link key and cannot open it. |
| The server swaps the link key toward the old device (F3) | The 48-bit code fingerprint still has to match, and the v2 check now also needs the secret, so the server can't aim at it. If a swap ever succeeded, the server could find the 40-bit secret offline, so the inner layer adds nothing in that direction: the fingerprint and check carry it, as before. |
| A phished approval (stolen session plus a talked-into code) | Nothing leaves the old device before Confirm it's you, and the screen says keys and messages will go. |
| A typo | The v2 check numbers differ, before anything is sealed. |
| Someone with a session on the account races a seal or history | `/seal` keeps the first; a 409 tells the person not to use the new device; the new device checks the bundle's identity against the account's devices; parts are bound by the digest. |
| Replayed, dropped, reordered, swapped or mixed parts | Index, count and account are in the AAD; count comes from the bundle; the digest covers every part; import is all or nothing. |
| AES-GCM is not key-committing | Every failure looks the same, all parts are fetched before any is opened, sizes are checked first, and one failure ends the link or the import. |
| Polling races | The state machine: one finishLink at a time, spent before the first open, a kept bundle, and no reopening. |
| Storage abuse on the server | Exact part size, one link with history per account, 15-minute lifetime, rate limits. |
| The secret leaks off the device | No requests, logs or clipboard; spellcheck and suggestions off; hidden during capture. |
| Metadata | The server learns that history was sent and its size in four steps (1, 4, 16, 64 parts). |
| Old and new apps mixed | A new device always shows a v2 code. An updated old device refuses a 12-character code. A v1 seal ends the link unopened with an update message. Nothing falls back to v1. |

## Parsing rules (every client)

- UTF-8 decoding is strict (fatal on invalid bytes); a byte order mark is refused.
- The wire value's `v` and the bundle's `v` must be the JSON number 2; history `v` the number 1.
- Writers never emit duplicate keys. A reader whose parser reports duplicates refuses them; a reader that can't tell may take either, since only the person's own device can produce these bytes.
- Base64 is standard with padding; refuse anything else.

## Keeping browser data (website)

- When private conversations are set up on the website, and at most once per start after that, call `navigator.storage.persist()` only on Chromium-based browsers and Safari or other WebKit browsers, never on Firefox (it shows a prompt).
- Show one card in the private conversations area, once per device, on any iPhone or iPad browser and on Safari for Mac, when not running as a Home Screen app, whatever `persisted()` says: "Your browser can erase this device's private conversations if you don't open Hubs for 7 days. Save a passkey backup to be safe." with **Save a backup** and **Not now**.
- The apps keep their own storage and need none of this.

## Also in this change (website and every app)

AE-3's second path: setting up with `resetIdentity` (the "Start over on this device" path on a device with no identity) keeps each contact's pinned key, removals statement and open alerts, exactly like `startOver`.

## Tests every client needs

- Replay `vectors.json`: secret encoding and decoding, every `parses` and `refused` input, the v2 check (and that the typo changes it), K, the bundle's inner layer, the history padding, padded counts, digest, AAD, and the bad-padding refusal.
- Open `outer-vector.json` and get its inner bytes.
- Link v2 end to end with a fake server: a real link with history works; a forged seal (no secret) fails with the sentence and registers nothing, and the link is spent; a v1 seal fails unopened with the update message; a 12-character code is refused; a hand-off after 15 minutes is refused; a second poll during a slow finishLink does nothing; a 409 on `/seal` shows the "answered first" message.
- History: expired and notice messages are not sent; timer lines carry seconds and no body; a missing, swapped, reordered, wrong-size or bad-padding part imports nothing; each bad field drops only its message; an existing message is never replaced; the timer is adopted only when newer and valid; over the cap keeps the newest and says truncated; the part count is padded.
- The secret appears in no request body, URL, header or log the fake server records.
- Website: upload and `/seal` both need Confirm it's you; the server refuses a part of the wrong size, a second link with history, and a fetch from another account; parts are gone after `/finish` and after 15 minutes.

## Clarifications

Every client follows these.

1. **The GET part answer** is `{"sealed": "<the sealed part as uploaded>"}`. The server may add other fields; clients read only `sealed`.
2. **Nothing to send** with the switch on: the bundle carries `history: null` and nothing is uploaded. A receiver also accepts `parts: 1` with one empty part.
3. **The approval sentences**, exactly: with the switch off, "This device's private conversation keys will go to the new device." With it on, "This device's private conversation keys and its messages will go to the new device."
4. **`proof`** carries every field the device stored, including `frankingKeyId` when present, so a report from the new device verifies like one from the old device.
5. **Numbers** are written as plain integers (`2`, never `2.0`); a reader refuses anything else where the spec says "the number".
6. **A timer message** has `expiresAt: null`; the carried timer's `sentAt` is 0 or more and its `id` follows the message id rule.
7. **A failed link** does not call `/finish`; the sweep removes it. A 404 on `/finish` counts as done.
8. **The vectors**: the history example is 2 real parts padded to a count of 4.
