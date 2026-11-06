import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import {
  PRIVATE_DM_HISTORY_JSON_MAX,
  PRIVATE_DM_HISTORY_PART_BYTES,
  PRIVATE_DM_HISTORY_SEALED_CHARS,
  ciphersuite,
  createLinkKeys,
  decodeLinkSecret,
  encodeLinkSecret,
  fromBase64,
  historyDigest,
  isOldLinkCode,
  linkCheckV2,
  linkInnerAad,
  linkKeyV2,
  normalizeLinkCode,
  openLinkInner,
  openLinkOuter,
  openLinkV2,
  padHistoryPart,
  paddedHistoryCount,
  parseLinkCode,
  readLinkWire,
  sealLinkInner,
  sealLinkV2,
  showLinkCode,
  toBase64,
  unpadHistoryPart,
} from "../src/index.js";

/*
 * Link v2 (LK-1) and history transfer. link-v2-vectors.json and
 * link-v2-outer-vector.json are copies of the link v2 known answers, made by
 * the link v2 reference implementation (reference.mjs). Every client
 * replays them.
 */
const vectors = JSON.parse(
  readFileSync(new URL("./link-v2-vectors.json", import.meta.url), "utf8"),
);
const outer = JSON.parse(
  readFileSync(new URL("./link-v2-outer-vector.json", import.meta.url), "utf8"),
);
const hex = (bytes: Uint8Array) => Buffer.from(bytes).toString("hex");
const bytes = (text: string) => Uint8Array.from(Buffer.from(text, "hex"));
const b64 = (text: string) => toBase64(bytes(text));
const te = new TextEncoder();
const sha256 = async (data: Uint8Array) =>
  hex(
    new Uint8Array(
      await crypto.subtle.digest("SHA-256", data as Uint8Array<ArrayBuffer>),
    ),
  );

const linkPublicKey = b64(vectors.linkPublicKey);
const secret = bytes(vectors.secret.bytes);

test("the secret encodes and decodes as Crockford base32", () => {
  assert.equal(encodeLinkSecret(secret), vectors.secret.text);
  assert.equal(
    hex(decodeLinkSecret(normalizeLinkCode(vectors.secret.text))!),
    vectors.secret.bytes,
  );
  assert.equal(
    hex(decodeLinkSecret(vectors.secret.otherText)!),
    vectors.secret.otherBytes,
  );
  assert.throws(() => encodeLinkSecret(new Uint8Array(4)));
  assert.equal(decodeLinkSecret(null), null);
  assert.equal(decodeLinkSecret("0000000U"), null);
});

test("the full code shows in groups of four and every listed input parses or is refused", () => {
  const parsed = parseLinkCode(vectors.fullCode.text)!;
  assert.equal(showLinkCode(parsed.id, parsed.secret), vectors.fullCode.shown);
  for (const [input, expected] of vectors.fullCode.parses) {
    const result = parseLinkCode(input);
    assert.ok(result, JSON.stringify(input));
    assert.deepEqual(
      { id: result.id, secret: hex(result.secret) },
      expected,
      JSON.stringify(input),
    );
  }
  for (const [input, expected] of vectors.fullCode.refused) {
    assert.equal(expected, null);
    assert.equal(parseLinkCode(input), null, JSON.stringify(input));
  }
  // The last refused input is an older app's 12-character code.
  assert.equal(isOldLinkCode(vectors.fullCode.refused.at(-1)[0]), true);
  assert.equal(isOldLinkCode(vectors.fullCode.text), false);
});

test("the v2 check needs the secret, so a typo changes it", async () => {
  assert.equal(await linkCheckV2(linkPublicKey, secret), vectors.check.v2);
  const typo = Uint8Array.from(secret);
  typo[4] ^= 1;
  assert.equal(
    await linkCheckV2(linkPublicKey, typo),
    vectors.check.v2WithTypo,
  );
  assert.notEqual(vectors.check.v2, vectors.check.v2WithTypo);
});

test("K and the bundle's inner layer are byte for byte", async () => {
  const key = await linkKeyV2(linkPublicKey, secret);
  assert.equal(hex(key), vectors.key);
  const aad = linkInnerAad("bundle", 0, 1, vectors.userId, linkPublicKey);
  assert.equal(hex(aad), vectors.bundle.aad);
  const inner = await sealLinkInner(
    key,
    bytes(vectors.bundle.plaintext),
    aad,
    bytes(vectors.bundle.nonce),
  );
  assert.equal(hex(inner), vectors.bundle.inner);
  assert.equal(
    hex(await openLinkInner(key, inner, aad)),
    vectors.bundle.plaintext,
  );
  // Another AAD (another account) does not open it.
  await assert.rejects(
    openLinkInner(
      key,
      inner,
      linkInnerAad("bundle", 0, 1, "u_mallory", linkPublicKey),
    ),
  );
});

test("history padding, padded counts, the digest, the AAD and each inner layer", async () => {
  const h = vectors.history;
  assert.equal(h.partBytes, PRIVATE_DM_HISTORY_PART_BYTES);
  assert.equal(h.jsonMax, PRIVATE_DM_HISTORY_JSON_MAX);
  assert.equal(h.sealedPartChars, PRIVATE_DM_HISTORY_SEALED_CHARS);
  for (const [parts, count] of h.paddedCounts)
    assert.equal(paddedHistoryCount(parts), count, String(parts));
  const part0 = padHistoryPart(
    JSON.stringify({
      v: 1,
      conversations: [
        {
          conversationId: "6f9619ff-8b86-4011-b42d-00c04fc964ff",
          peer: "u_bob",
          timer: { seconds: 3600, sentAt: 1762430000000, id: "t1" },
          messages: [
            {
              id: "m1",
              kind: "text",
              body: "Hello",
              sentAt: 1762430001000,
              expiresAt: 1763034801000,
              senderUserId: "u_bob",
            },
            {
              id: "t1",
              kind: "timer",
              body: "",
              seconds: 3600,
              sentAt: 1762430000000,
              expiresAt: null,
              senderUserId: "u_alice",
            },
          ],
        },
      ],
    }),
  );
  // The second real part: the same conversation continuing (vectors fixed
  // at dfb66c6db: 2 real parts padded up to a count of 4).
  const part1 = padHistoryPart(
    JSON.stringify({
      v: 1,
      conversations: [
        {
          conversationId: "6f9619ff-8b86-4011-b42d-00c04fc964ff",
          peer: "u_bob",
          timer: null,
          messages: [
            {
              id: "m2",
              kind: "text",
              body: "Still here",
              sentAt: 1762430002000,
              expiresAt: 1763034802000,
              senderUserId: "u_alice",
            },
          ],
        },
      ],
    }),
  );
  const empty = padHistoryPart(JSON.stringify({ v: 1, conversations: [] }));
  assert.equal(hex(part0.subarray(0, 48)), h.part0Head);
  assert.equal(await sha256(part0), h.part0Sha256);
  assert.equal(await sha256(part1), h.part1Sha256);
  assert.equal(await sha256(empty), h.emptySha256);
  assert.equal(h.realParts, 2);
  assert.equal(paddedHistoryCount(h.realParts), h.count);
  const parts = [part0, part1, empty, empty];
  assert.equal(parts.length, h.count);
  assert.equal(await historyDigest(parts), h.digest);
  const key = bytes(vectors.key);
  const nonce = bytes(vectors.bundle.nonce);
  for (let i = 0; i < parts.length; i++) {
    const aad = linkInnerAad(
      "history",
      i,
      h.count,
      vectors.userId,
      linkPublicKey,
    );
    assert.equal(hex(aad), h.aad[i]);
    assert.equal(
      await sha256(await sealLinkInner(key, parts[i], aad, nonce)),
      h.innerSha256[i],
    );
  }
  assert.ok(unpadHistoryPart(part0));
  const bad = Uint8Array.from(empty);
  bad[bad.length - 1] = 1;
  assert.equal(unpadHistoryPart(bad), h.badPadding.lastByteSetTo1);
  // A length over the most JSON a part holds, a short part and a byte order mark are refused too.
  const long = Uint8Array.from(empty);
  new DataView(long.buffer).setUint32(0, PRIVATE_DM_HISTORY_JSON_MAX + 1);
  assert.equal(unpadHistoryPart(long), null);
  assert.equal(unpadHistoryPart(empty.subarray(1)), null);
  assert.equal(unpadHistoryPart(padHistoryPart("﻿{}")), null);
  assert.throws(() =>
    padHistoryPart("x".repeat(PRIVATE_DM_HISTORY_JSON_MAX + 1)),
  );
});

test("the outer vector opens to the bundle's inner layer", async () => {
  assert.equal(outer.info, "hubs private dms link v2");
  assert.equal(outer.innerHex, vectors.bundle.inner);
  const inner = await openLinkOuter(outer.linkPrivateKey, outer.wire);
  assert.equal(hex(inner), outer.innerHex);
  // The same through the library's own HPKE call, with the info string.
  const cs = await ciphersuite();
  const wire = JSON.parse(outer.wire);
  assert.deepEqual(Object.keys(wire), ["v", "enc", "ct"]);
  const opened = await cs.hpke.open(
    await cs.hpke.importPrivateKey(fromBase64(outer.linkPrivateKey)),
    fromBase64(wire.enc),
    fromBase64(wire.ct),
    te.encode(outer.info),
  );
  assert.equal(hex(new Uint8Array(opened)), outer.innerHex);
});

test("a sealed history part is exactly the fixed number of characters", async () => {
  const keys = await createLinkKeys();
  const key = await linkKeyV2(keys.publicKey, secret);
  const aad = linkInnerAad("history", 0, 1, "u_alice", keys.publicKey);
  const wire = await sealLinkV2(
    keys.publicKey,
    key,
    padHistoryPart('{"v":1,"conversations":[]}'),
    aad,
  );
  assert.equal(wire.length, PRIVATE_DM_HISTORY_SEALED_CHARS);
  assert.match(wire, /^\{"v":2,"enc":"[A-Za-z0-9+/=]{44}","ct":"/);
  const opened = await openLinkV2(keys.privateKey, key, wire, aad);
  assert.equal(opened.length, PRIVATE_DM_HISTORY_PART_BYTES);
  // Another index, another key or a v1 seal does not open.
  await assert.rejects(
    openLinkV2(
      keys.privateKey,
      key,
      wire,
      linkInnerAad("history", 1, 1, "u_alice", keys.publicKey),
    ),
  );
  await assert.rejects(
    openLinkV2(
      keys.privateKey,
      await linkKeyV2(keys.publicKey, new Uint8Array(5)),
      wire,
      aad,
    ),
  );
  assert.deepEqual(readLinkWire('{"enc":"a","ct":"b"}'), { kind: "other" });
  assert.deepEqual(readLinkWire('{"v":"2","enc":"a","ct":"b"}'), {
    kind: "other",
  });
  assert.deepEqual(readLinkWire("not json"), { kind: "other" });
  assert.equal(readLinkWire(wire).kind, "v2");
  // Base64 is standard with padding: anything else is refused.
  const loose = JSON.parse(wire);
  await assert.rejects(
    openLinkOuter(
      keys.privateKey,
      JSON.stringify({ ...loose, enc: loose.enc.replace(/=+$/, "") }),
    ),
  );
});

test("the wire's v must be written as the number 2 (LW-9)", () => {
  const enc = "A".repeat(43) + "=";
  assert.equal(readLinkWire(`{"v":2,"enc":"${enc}","ct":"AAAA"}`).kind, "v2");
  for (const v of ["2.0", "2e0", '"2"', "1"])
    assert.equal(
      readLinkWire(`{"v":${v},"enc":"${enc}","ct":"AAAA"}`).kind,
      "other",
      v,
    );
});
