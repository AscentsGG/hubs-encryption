// Reference for link v2 (LK-1) and history transfer: the byte formats every
// client must produce, with fixed inputs. It prints vectors.json beside it.
//
//   node test-vectors/link-v2/reference.mjs > test-vectors/link-v2/vectors.json
//
// The outer layer is the existing link HPKE seal with the v2 info string.
// Because HPKE sealing is randomized, its vector (outer-vector.json) was made
// once by outer-vector.mts with the website's own engine, and clients test
// that they open it.
import { webcrypto as crypto } from "node:crypto";

const te = new TextEncoder();
const hex = (bytes) => Buffer.from(bytes).toString("hex");
const concat = (...parts) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
};

// Crockford base32, upper case, no check symbol.
export const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/**
 * What a person typed, cleaned: ASCII space, tab and hyphen-minus removed,
 * then ASCII upper case. Any other character, ASCII or not, refuses the
 * whole input (null). No locale rules, no Unicode case folding.
 */
export function normalizeCode(text) {
  let out = "";
  for (const char of text) {
    const code = char.codePointAt(0);
    if (code === 0x20 || code === 0x09 || code === 0x2d) continue;
    if (code >= 0x30 && code <= 0x39) out += char;
    else if (code >= 0x41 && code <= 0x5a) out += char;
    else if (code >= 0x61 && code <= 0x7a) out += String.fromCharCode(code - 32);
    else return null;
  }
  return out;
}

export function encodeSecret(bytes) {
  if (bytes.length !== 5) throw new Error("The link secret is 5 bytes.");
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  let out = "";
  for (let i = 7; i >= 0; i--)
    out += ALPHABET[Number((value >> BigInt(i * 5)) & 31n)];
  return out;
}

/** 8 normalized characters to 5 bytes. O reads as 0, I and L as 1. */
export function decodeSecret(normalized) {
  if (normalized === null || normalized.length !== 8) return null;
  const mapped = normalized.replace(/O/g, "0").replace(/[IL]/g, "1");
  let value = 0n;
  for (const char of mapped) {
    const index = ALPHABET.indexOf(char);
    if (index < 0) return null;
    value = (value << 5n) | BigInt(index);
  }
  const out = new Uint8Array(5);
  for (let i = 4; i >= 0; i--) {
    out[i] = Number(value & 255n);
    value >>= 8n;
  }
  return out;
}

/** The full code the old device takes: 12 hex (the link id, sent lower case), then the 8-character secret. */
export function parseFullCode(text) {
  const normalized = normalizeCode(text);
  if (normalized === null || normalized.length !== 20) return null;
  const id = normalized.slice(0, 12).toLowerCase();
  if (!/^[0-9a-f]{12}$/.test(id)) return null;
  const secret = decodeSecret(normalized.slice(12));
  return secret ? { id, secret } : null;
}

const sha256 = async (bytes) =>
  new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));

/** The v2 check number: it needs the secret, so a typo shows as numbers that don't match. */
export async function linkCheckV2(linkPublicKey, secret) {
  const digest = await sha256(
    concat(te.encode("hubs link check v2\0"), linkPublicKey, secret),
  );
  const value = new DataView(digest.buffer).getUint32(0) % 1_000_000;
  return String(value).padStart(6, "0");
}

export async function linkKeyV2(linkPublicKey, secret) {
  const ikm = await crypto.subtle.importKey("raw", secret, "HKDF", false, [
    "deriveBits",
  ]);
  return new Uint8Array(
    await crypto.subtle.deriveBits(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: linkPublicKey,
        info: te.encode("hubs link v2 key"),
      },
      ikm,
      256,
    ),
  );
}

/**
 * The inner layer's AAD: the kind of part, its place, the account and the
 * link key. index and count are plain decimal with no leading zeros.
 */
export function innerAad(kind, index, count, userId, linkPublicKey) {
  return concat(
    te.encode(`hubs link v2\n${kind}\n${index}\n${count}\n${userId}\n`),
    linkPublicKey,
  );
}

/** Inner layer: nonce (12) || AES-256-GCM ciphertext with its 16-byte tag. */
export async function innerSeal(key, nonce, plaintext, aad) {
  const k = await crypto.subtle.importKey("raw", key, "AES-GCM", false, [
    "encrypt",
  ]);
  const ct = new Uint8Array(
    await crypto.subtle.encrypt(
      { name: "AES-GCM", iv: nonce, additionalData: aad, tagLength: 128 },
      k,
      plaintext,
    ),
  );
  return concat(nonce, ct);
}

export const HISTORY_PART_BYTES = 262144;
export const HISTORY_JSON_MAX = HISTORY_PART_BYTES - 4;
/**
 * A sealed history part on the wire is always this many characters:
 * {"v":2,"enc":"<44>","ct":"<349584>"} with standard padded base64, keys in
 * that order (outer plaintext 12 + 262144 + 16 bytes, plus HPKE's 16-byte tag).
 */
export const SEALED_PART_CHARS = 349652;
/** Part counts are padded up to one of these, so the size shows only in four steps. */
export const PART_COUNTS = [1, 4, 16, 64];
export const paddedCount = (parts) =>
  PART_COUNTS.find((count) => count >= parts) ?? null;

/** A history part's plaintext: 4-byte big-endian length, the JSON, then zeros to 256 KiB. */
export function padPart(json) {
  const body = te.encode(json);
  if (body.length > HISTORY_JSON_MAX) throw new Error("Part too large.");
  const out = new Uint8Array(HISTORY_PART_BYTES);
  new DataView(out.buffer).setUint32(0, body.length);
  out.set(body, 4);
  return out;
}

/** The JSON of a padded part, or null if the length or the padding is wrong. */
export function unpadPart(part) {
  if (part.length !== HISTORY_PART_BYTES) return null;
  const length = new DataView(part.buffer, part.byteOffset).getUint32(0);
  if (length > HISTORY_JSON_MAX) return null;
  for (let i = 4 + length; i < part.length; i++) if (part[i] !== 0) return null;
  try {
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(
      part.subarray(4, 4 + length),
    );
  } catch {
    return null;
  }
}

async function main() {
  const secret = Uint8Array.from([0x01, 0x23, 0x45, 0x67, 0x89]);
  const linkPublicKey = new Uint8Array(32).fill(0x11);
  const linkId = "a1b2c3d4e5f6";
  const userId = "u_alice";
  const key = await linkKeyV2(linkPublicKey, secret);
  const nonce = Uint8Array.from({ length: 12 }, (_, i) => i);
  const bundle = te.encode('{"v":2,"userId":"u_alice"}');
  const bundleAad = innerAad("bundle", 0, 1, userId, linkPublicKey);
  const part0 = padPart(
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
  // A second real part (the same conversation continuing), so the history
  // needs 2 parts and its count pads up to 4 with two empty parts.
  const part1 = padPart(
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
  const empty = padPart(JSON.stringify({ v: 1, conversations: [] }));
  const realParts = 2;
  const count = paddedCount(realParts);
  const parts = [part0, part1, ...Array(count - realParts).fill(empty)];
  if (parts.length !== count) throw new Error("parts must equal count");
  const secretText = encodeSecret(secret);
  const typo = Uint8Array.from(secret);
  typo[4] ^= 1;
  const otherSecretText = "0110ABCD";
  const otherSecret = decodeSecret(otherSecretText);
  const parse = async (input) => {
    const parsed = parseFullCode(input);
    return [input, parsed && { id: parsed.id, secret: hex(parsed.secret) }];
  };
  const vectors = {
    note: "Link v2 (LK-1) and history transfer, from docs/e2ee-work/link-v2/reference.mjs. Fixed inputs; every client must produce these bytes. The outer HPKE layer's vector is outer-vector.json.",
    secret: {
      bytes: hex(secret),
      text: secretText,
      otherText: otherSecretText,
      otherBytes: hex(otherSecret),
    },
    fullCode: {
      text: `${linkId}${secretText}`,
      shown: `${linkId.slice(0, 4)} ${linkId.slice(4, 8)} ${linkId.slice(8)} ${secretText.slice(0, 4)} ${secretText.slice(4)}`,
      parses: await Promise.all(
        [
          `${linkId.slice(0, 4)} ${linkId.slice(4, 8)} ${linkId.slice(8)} ${secretText.slice(0, 4)} ${secretText.slice(4)}`,
          `${linkId}${secretText.toLowerCase()}`,
          `${linkId.toUpperCase()}${secretText}`,
          `${linkId}-${secretText.slice(0, 4)}-${secretText.slice(4)}`,
          `${linkId}\t${secretText}`,
          `${linkId}oIlOabcd`,
          `${linkId}OiLoABCD`,
        ].map(parse),
      ),
      refused: await Promise.all(
        [
          `${linkId}${secretText.slice(0, 7)}`,
          `${linkId}${secretText}X`,
          `${linkId}${secretText.slice(0, 7)}U`,
          `${linkId.slice(0, 11)}O${secretText}`,
          `${linkId}${secretText.slice(0, 7)}ı`,
          `${linkId} ${secretText}`,
          `${linkId}–${secretText}`,
          `${linkId}　${secretText}`,
          `﻿${linkId}${secretText}`,
          linkId,
        ].map(parse),
      ),
    },
    linkPublicKey: hex(linkPublicKey),
    userId,
    check: {
      v2: await linkCheckV2(linkPublicKey, secret),
      v2WithTypo: await linkCheckV2(linkPublicKey, typo),
    },
    key: hex(key),
    bundle: {
      plaintext: hex(bundle),
      aad: hex(bundleAad),
      nonce: hex(nonce),
      inner: hex(await innerSeal(key, nonce, bundle, bundleAad)),
    },
    history: {
      partBytes: HISTORY_PART_BYTES,
      jsonMax: HISTORY_JSON_MAX,
      sealedPartChars: SEALED_PART_CHARS,
      paddedCounts: [0, 1, 2, 4, 5, 16, 17, 64, 65].map((n) => [
        n,
        n < 1 ? null : paddedCount(n),
      ]),
      realParts,
      count,
      part0Head: hex(part0.subarray(0, 48)),
      part0Sha256: hex(await sha256(part0)),
      part1Sha256: hex(await sha256(part1)),
      emptySha256: hex(await sha256(empty)),
      digest: hex(await sha256(concat(...parts))),
      aad: parts.map((_, i) =>
        hex(innerAad("history", i, count, userId, linkPublicKey)),
      ),
      innerSha256: await Promise.all(
        parts.map(async (part, i) =>
          hex(
            await sha256(
              await innerSeal(
                key,
                nonce,
                part,
                innerAad("history", i, count, userId, linkPublicKey),
              ),
            ),
          ),
        ),
      ),
      badPadding: (() => {
        const bad = Uint8Array.from(empty);
        bad[bad.length - 1] = 1;
        return { lastByteSetTo1: unpadPart(bad) };
      })(),
    },
  };
  // Self-checks.
  if (encodeSecret(decodeSecret(normalizeCode(secretText))) !== secretText)
    throw new Error("secret round trip");
  for (const [input, result] of vectors.fullCode.parses)
    if (!result) throw new Error(`should parse: ${JSON.stringify(input)}`);
  for (const [input, result] of vectors.fullCode.refused)
    if (result) throw new Error(`should refuse: ${JSON.stringify(input)}`);
  if (vectors.check.v2 === vectors.check.v2WithTypo)
    throw new Error("a typo should change the check");
  if (unpadPart(part0) === null) throw new Error("unpad");
  for (const [, result] of vectors.fullCode.parses.slice(-2))
    if (result.secret !== vectors.secret.otherBytes)
      throw new Error("O, I and L should read as 0, 1 and 1");
  process.stdout.write(`${JSON.stringify(vectors, null, 2)}\n`);
}

if (import.meta.url === `file://${process.argv[1]}`) await main();
