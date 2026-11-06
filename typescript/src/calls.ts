/**
 * End-to-end encrypted calls, protocol version 3: the bytes each call
 * statement, signature, wrapped key and code covers, and the rule every app
 * applies to the connections in a call.
 *
 * Each connection to a call makes a fresh P-256 key pair. A device that has
 * a private conversation device key signs a binding over its connection key,
 * the call, its connection id and its account, and the account identity key
 * vouches for that device key with the usual device certificate. Every app
 * checks the binding and compares the identity key with the one it pinned
 * for that person, so the server cannot add a listener under someone's name
 * without the call showing it. The call key itself is 32 random bytes made
 * by one connection and wrapped for each other connection under a key from
 * ECDH and HKDF, bound to the call, the epoch, the key slot and both
 * connections' statements.
 *
 * Protocol version 2 (the wrap under the raw ECDH secret and the 12-digit
 * code) stays here for calls with an app that has not moved to version 3.
 *
 * Everything runs on WebCrypto (browsers and Node): P-256 ECDH, HKDF,
 * AES-256-GCM, HMAC and SHA-256, and Ed25519 the same way the ciphersuite
 * uses it, so this file does not load the MLS library.
 */
import { deviceCertificateBody, isWellFormedText } from "./protocol.js";

/** The call protocol this code speaks. Version 2 is still read and written for older apps. */
export const CALL_PROTOCOL_VERSION = 3;
/** The call key is 32 random bytes. */
export const CALL_KEY_BYTES = 32;
/** Keyring slots a call uses for its keys (0 to 15). */
export const CALL_KEYRING_SIZE = 16;

export const CALL_BINDING_LABEL = "hubs-call-binding-v3";
export const CALL_UNBOUND_LABEL = "hubs-call-unbound-v3";
export const CALL_WRAP_LABEL = "hubs-call-wrap-v3";
export const CALL_CODE_LABEL = "hubs-call-code-v3";
export const CALL_VIEW_LABEL = "hubs-call-view-v3";

const te = new TextEncoder();
const subtle = () => globalThis.crypto.subtle;
/** Copies into a fresh ArrayBuffer, which every WebCrypto call accepts. */
const buffer = (bytes: Uint8Array) => new Uint8Array(bytes) as Uint8Array<ArrayBuffer>;

function toBase64(bytes: Uint8Array): string {
  let text = "";
  for (const byte of bytes) text += String.fromCharCode(byte);
  return btoa(text);
}
function fromBase64(text: string): Uint8Array {
  const raw = atob(text);
  const bytes = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
  return bytes;
}
/** Base64 of exactly `size` bytes, or null. Standard alphabet with padding only. */
function exactBase64(text: unknown, size: number): Uint8Array | null {
  if (typeof text !== "string" || text.length !== Math.ceil(size / 3) * 4)
    return null;
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(text)) return null;
  try {
    const bytes = fromBase64(text);
    // atob ignores bits it drops, so re-encode to refuse a second spelling.
    return bytes.length === size && toBase64(bytes) === text ? bytes : null;
  } catch {
    return null;
  }
}
const concat = (...parts: Uint8Array[]) => {
  const out = new Uint8Array(parts.reduce((n, part) => n + part.length, 0));
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
};
const compareBytes = (a: Uint8Array, b: Uint8Array) => {
  for (let i = 0; i < Math.min(a.length, b.length); i++)
    if (a[i] !== b[i]) return a[i] - b[i];
  return a.length - b.length;
};
const equalBytes = (a: Uint8Array, b: Uint8Array) =>
  a.length === b.length && compareBytes(a, b) === 0;

/** A label and its 0x00 terminator. */
const label = (name: string) => concat(te.encode(name), new Uint8Array([0]));
/**
 * A string as a 2-byte big-endian length, then its UTF-8 bytes. Strings
 * longer than 255 bytes, or with a lone UTF-16 surrogate (which platforms
 * encode differently), are refused.
 */
export function lengthPrefixed(text: string): Uint8Array {
  if (!isWellFormedText(text))
    throw new Error("A call field is not well-formed text.");
  const bytes = te.encode(text);
  if (bytes.length > 255) throw new Error("A call field is too long.");
  return concat(new Uint8Array([0, bytes.length]), bytes);
}
const u8 = (n: number) => {
  if (!Number.isInteger(n) || n < 0 || n > 255)
    throw new Error("A call number is out of range.");
  return new Uint8Array([n]);
};
const u16 = (n: number) => {
  if (!Number.isInteger(n) || n < 0 || n > 0xffff)
    throw new Error("A call number is out of range.");
  return new Uint8Array([n >> 8, n & 0xff]);
};
const keySlot = (keyIndex: number) => {
  if (!Number.isInteger(keyIndex) || keyIndex < 0 || keyIndex >= CALL_KEYRING_SIZE)
    throw new Error("The key slot is out of range.");
  return u8(keyIndex);
};

async function sha256(bytes: Uint8Array) {
  return new Uint8Array(await subtle().digest("SHA-256", buffer(bytes)));
}
/** HKDF-SHA256 with a salt of 32 zero bytes (the same as an empty salt). */
async function hkdf(ikm: Uint8Array, info: Uint8Array, length = 32) {
  const key = await subtle().importKey("raw", buffer(ikm), "HKDF", false, [
    "deriveBits",
  ]);
  return new Uint8Array(
    await subtle().deriveBits(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: new Uint8Array(32),
        info: buffer(info),
      },
      key,
      length * 8,
    ),
  );
}
async function hmacSha256(key: Uint8Array, message: Uint8Array) {
  const imported = await subtle().importKey(
    "raw",
    buffer(key),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  return new Uint8Array(await subtle().sign("HMAC", imported, buffer(message)));
}
/** Ed25519 signing with a PKCS#8 key, as the ciphersuite does. Deterministic (RFC 8032). */
async function ed25519Sign(pkcs8: Uint8Array, message: Uint8Array) {
  const key = await subtle().importKey("pkcs8", buffer(pkcs8), "Ed25519", false, [
    "sign",
  ]);
  return new Uint8Array(await subtle().sign("Ed25519", key, buffer(message)));
}
/** Ed25519 verification of a raw 32-byte key; false for anything that does not verify. */
async function ed25519Verify(
  publicKey: Uint8Array,
  message: Uint8Array,
  signature: Uint8Array,
) {
  try {
    const key = await subtle().importKey(
      "raw",
      buffer(publicKey),
      "Ed25519",
      false,
      ["verify"],
    );
    return await subtle().verify(
      "Ed25519",
      key,
      buffer(signature),
      buffer(message),
    );
  } catch {
    return false;
  }
}

/** Whether this platform's WebCrypto has Ed25519, which checking bindings needs. */
export async function callSignaturesSupported(): Promise<boolean> {
  try {
    await subtle().importKey(
      "raw",
      new Uint8Array(32).fill(1),
      "Ed25519",
      false,
      ["verify"],
    );
    return true;
  } catch {
    return false;
  }
}

/* ---------- Connection keys and the call key ---------- */

/** A connection public key on the wire: base64 of 65 uncompressed P-256 bytes. */
export const CALL_PUBLIC_KEY_PATTERN = /^[A-Za-z0-9+/]{86}[A-Za-z0-9+/=]{2}$/;
export function validCallPublicKey(value: string): boolean {
  const bytes = exactBase64(value, 65);
  return !!bytes && bytes[0] === 4;
}

/**
 * A fresh P-256 key pair for one connection. The private key cannot be
 * exported and is used only to derive shared secrets.
 */
export async function makeConnectionKeys(): Promise<{
  privateKey: CryptoKey;
  publicKey: string;
}> {
  const pair = (await subtle().generateKey(
    { name: "ECDH", namedCurve: "P-256" },
    false,
    ["deriveBits"],
  )) as CryptoKeyPair;
  const publicKey = toBase64(
    new Uint8Array(await subtle().exportKey("raw", pair.publicKey)),
  );
  return { privateKey: pair.privateKey, publicKey };
}

/** A new random call key. */
export function makeCallKey(): Uint8Array {
  return globalThis.crypto.getRandomValues(new Uint8Array(CALL_KEY_BYTES));
}

/** The 32-byte X coordinate of the P-256 ECDH shared point. */
export async function callSharedSecret(
  privateKey: CryptoKey,
  otherPublicKey: string,
): Promise<Uint8Array> {
  const raw = exactBase64(otherPublicKey, 65);
  if (!raw || raw[0] !== 4) throw new Error("That is not a call public key.");
  const other = await subtle().importKey(
    "raw",
    buffer(raw),
    { name: "ECDH", namedCurve: "P-256" },
    false,
    [],
  );
  return new Uint8Array(
    await subtle().deriveBits({ name: "ECDH", public: other }, privateKey, 256),
  );
}

async function sealCallKey(
  key: Uint8Array,
  callKey: Uint8Array,
  aad: Uint8Array,
  iv: Uint8Array,
) {
  if (callKey.length !== CALL_KEY_BYTES) throw new Error("Wrong key size.");
  if (iv.length !== 12) throw new Error("The IV must be 12 bytes.");
  const aes = await subtle().importKey("raw", buffer(key), "AES-GCM", false, [
    "encrypt",
  ]);
  const sealed = await subtle().encrypt(
    { name: "AES-GCM", iv: buffer(iv), additionalData: buffer(aad) },
    aes,
    buffer(callKey),
  );
  return { wrapped: toBase64(new Uint8Array(sealed)), iv: toBase64(iv) };
}
async function openCallKey(
  key: Uint8Array,
  sealed: { wrapped: string; iv: string },
  aad: Uint8Array,
) {
  const iv = exactBase64(sealed.iv, 12);
  const body = exactBase64(sealed.wrapped, CALL_KEY_BYTES + 16);
  if (!iv || !body) throw new Error("That wrapped key is not well formed.");
  const aes = await subtle().importKey("raw", buffer(key), "AES-GCM", false, [
    "decrypt",
  ]);
  const plain = new Uint8Array(
    await subtle().decrypt(
      { name: "AES-GCM", iv: buffer(iv), additionalData: buffer(aad) },
      aes,
      buffer(body),
    ),
  );
  if (plain.length !== CALL_KEY_BYTES) throw new Error("Wrong key size.");
  return plain;
}
const freshIv = () => globalThis.crypto.getRandomValues(new Uint8Array(12));

/* ---------- Statements: who holds each connection key ---------- */

/** A connection's binding as it travels in JSON (standard base64). */
export type CallBinding = {
  deviceId: string;
  /** The account identity key, 32 bytes. */
  identityPublicKey: string;
  /** This device's key, 32 bytes. */
  devicePublicKey: string;
  /** The identity key's signature over the device certificate body, 64 bytes. */
  certificate: string;
  /** The device key's signature over the binding body, 64 bytes. */
  signature: string;
};
/** One connection to a call, as the call's key exchange lists it. */
export type CallConnection = {
  leaseId: string;
  userId: string;
  /** Base64 of the 65-byte P-256 public key. */
  publicKey: string;
  /** The call protocol the connection speaks; missing means 2. */
  v?: number;
  binding?: CallBinding | null;
};
/** What a binding decodes to when every field has its exact size. */
type DecodedBinding = {
  deviceId: string;
  identityPublicKey: Uint8Array;
  devicePublicKey: Uint8Array;
  certificate: Uint8Array;
  signature: Uint8Array;
};
function decodeBinding(binding: unknown): DecodedBinding | null {
  if (!binding || typeof binding !== "object") return null;
  const value = binding as Record<string, unknown>;
  const deviceId = value.deviceId;
  if (
    typeof deviceId !== "string" ||
    !deviceId ||
    !isWellFormedText(deviceId) ||
    te.encode(deviceId).length > 255
  )
    return null;
  const identityPublicKey = exactBase64(value.identityPublicKey, 32);
  const devicePublicKey = exactBase64(value.devicePublicKey, 32);
  const certificate = exactBase64(value.certificate, 64);
  const signature = exactBase64(value.signature, 64);
  if (!identityPublicKey || !devicePublicKey || !certificate || !signature)
    return null;
  return {
    deviceId,
    identityPublicKey,
    devicePublicKey,
    certificate,
    signature,
  };
}

/**
 * The bytes a device key signs to bind one connection key:
 * label, channel, connection id, account, device, identity key (32),
 * device key (32) and the connection key (65).
 */
export function callBindingBody(input: {
  channelId: string;
  leaseId: string;
  userId: string;
  deviceId: string;
  identityPublicKey: Uint8Array;
  devicePublicKey: Uint8Array;
  connectionPublicKey: Uint8Array;
}): Uint8Array {
  if (
    input.identityPublicKey.length !== 32 ||
    input.devicePublicKey.length !== 32 ||
    input.connectionPublicKey.length !== 65
  )
    throw new Error("A call key has the wrong size.");
  return concat(
    label(CALL_BINDING_LABEL),
    lengthPrefixed(input.channelId),
    lengthPrefixed(input.leaseId),
    lengthPrefixed(input.userId),
    lengthPrefixed(input.deviceId),
    input.identityPublicKey,
    input.devicePublicKey,
    input.connectionPublicKey,
  );
}

/** The statement of a connection with no binding. It is not signed. */
export function callUnboundBody(input: {
  channelId: string;
  leaseId: string;
  userId: string;
  connectionPublicKey: Uint8Array;
}): Uint8Array {
  if (input.connectionPublicKey.length !== 65)
    throw new Error("A call key has the wrong size.");
  return concat(
    label(CALL_UNBOUND_LABEL),
    lengthPrefixed(input.channelId),
    lengthPrefixed(input.leaseId),
    lengthPrefixed(input.userId),
    input.connectionPublicKey,
  );
}

const connectionKeyBytes = (publicKey: string) => {
  const bytes = exactBase64(publicKey, 65);
  if (!bytes || bytes[0] !== 4) throw new Error("That is not a call public key.");
  return bytes;
};

/**
 * A connection's statement: the binding body when it carries a binding
 * whose fields all have their exact sizes (whether or not it verifies),
 * otherwise the unbound statement.
 */
export function callStatement(
  channelId: string,
  connection: CallConnection,
): Uint8Array {
  const connectionPublicKey = connectionKeyBytes(connection.publicKey);
  const decoded = connection.binding ? decodeBinding(connection.binding) : null;
  return decoded
    ? callBindingBody({
        channelId,
        leaseId: connection.leaseId,
        userId: connection.userId,
        deviceId: decoded.deviceId,
        identityPublicKey: decoded.identityPublicKey,
        devicePublicKey: decoded.devicePublicKey,
        connectionPublicKey,
      })
    : callUnboundBody({
        channelId,
        leaseId: connection.leaseId,
        userId: connection.userId,
        connectionPublicKey,
      });
}

/** A connection's hash: SHA-256 of its statement. */
export async function callConnectionHash(
  channelId: string,
  connection: CallConnection,
): Promise<Uint8Array> {
  return sha256(callStatement(channelId, connection));
}

/**
 * Signs the binding for this device's connection. `device` holds the device
 * key as PKCS#8 and the identity key's certificate, as the private
 * conversation client stores them.
 */
export async function signCallBinding(
  device: {
    userId: string;
    deviceId: string;
    identityPublicKey: string;
    publicKey: string;
    signKey: string;
    certificate: string;
  },
  call: { channelId: string; leaseId: string; connectionPublicKey: string },
): Promise<CallBinding> {
  const identityPublicKey = fromBase64(device.identityPublicKey);
  const devicePublicKey = fromBase64(device.publicKey);
  const body = callBindingBody({
    channelId: call.channelId,
    leaseId: call.leaseId,
    userId: device.userId,
    deviceId: device.deviceId,
    identityPublicKey,
    devicePublicKey,
    connectionPublicKey: connectionKeyBytes(call.connectionPublicKey),
  });
  const signature = await ed25519Sign(fromBase64(device.signKey), body);
  return {
    deviceId: device.deviceId,
    identityPublicKey: toBase64(identityPublicKey),
    devicePublicKey: toBase64(devicePublicKey),
    certificate: device.certificate,
    signature: toBase64(signature),
  };
}

/**
 * What a connection's binding proves, checked against the call's own channel
 * id and the connection's id, account and key as listed:
 * - "none": no binding;
 * - "valid": the identity key certified the device key for this account and
 *   device, and the device key signed this exact connection;
 * - "invalid": a binding that is malformed or does not verify.
 */
export type CallBindingCheck =
  | { status: "none" }
  | { status: "valid"; identityPublicKey: string; devicePublicKey: string }
  | { status: "invalid" };
export async function checkCallBinding(
  channelId: string,
  connection: CallConnection,
): Promise<CallBindingCheck> {
  if (!connection.binding) return { status: "none" };
  const decoded = decodeBinding(connection.binding);
  if (!decoded) return { status: "invalid" };
  let body: Uint8Array;
  let certificateBody: Uint8Array;
  try {
    body = callStatement(channelId, connection);
    if (!isWellFormedText(connection.userId)) return { status: "invalid" };
    certificateBody = deviceCertificateBody(
      connection.userId,
      decoded.deviceId,
      decoded.devicePublicKey,
    );
  } catch {
    return { status: "invalid" };
  }
  const [signed, certified] = await Promise.all([
    ed25519Verify(decoded.devicePublicKey, body, decoded.signature),
    ed25519Verify(
      decoded.identityPublicKey,
      certificateBody,
      decoded.certificate,
    ),
  ]);
  return signed && certified
    ? {
        status: "valid",
        identityPublicKey: toBase64(decoded.identityPublicKey),
        devicePublicKey: toBase64(decoded.devicePublicKey),
      }
    : { status: "invalid" };
}

/* ---------- Wrapping the call key ---------- */

/** The HKDF info and AES-GCM additional data of a version 3 wrap. */
export function callWrapInfo(input: {
  channelId: string;
  epoch: string;
  keyIndex: number;
  senderHash: Uint8Array;
  recipientHash: Uint8Array;
}): Uint8Array {
  if (input.senderHash.length !== 32 || input.recipientHash.length !== 32)
    throw new Error("A connection hash must be 32 bytes.");
  return concat(
    label(CALL_WRAP_LABEL),
    lengthPrefixed(input.channelId),
    lengthPrefixed(input.epoch),
    keySlot(input.keyIndex),
    input.senderHash,
    input.recipientHash,
  );
}

/** The version 3 wrapping key: HKDF-SHA256 over the ECDH secret with the wrap info. */
export async function callWrapKey(
  privateKey: CryptoKey,
  otherPublicKey: string,
  info: Uint8Array,
): Promise<Uint8Array> {
  return hkdf(await callSharedSecret(privateKey, otherPublicKey), info);
}

/**
 * Wraps the call key for one recipient connection (version 3). `iv` is for
 * test vectors only; a fresh random IV is used otherwise.
 */
export async function wrapCallKeyV3(
  callKey: Uint8Array,
  privateKey: CryptoKey,
  recipientPublicKey: string,
  info: Uint8Array,
  iv: Uint8Array = freshIv(),
): Promise<{ wrapped: string; iv: string }> {
  return sealCallKey(
    await callWrapKey(privateKey, recipientPublicKey, info),
    callKey,
    info,
    iv,
  );
}
/** Opens a version 3 wrapped call key; throws unless it was made for this connection, call, epoch and slot. */
export async function unwrapCallKeyV3(
  sealed: { wrapped: string; iv: string },
  privateKey: CryptoKey,
  senderPublicKey: string,
  info: Uint8Array,
): Promise<Uint8Array> {
  return openCallKey(
    await callWrapKey(privateKey, senderPublicKey, info),
    sealed,
    info,
  );
}

/** The version 2 additional data: "hubs-call-key\n" channel "\n" epoch. */
export const callWrapContextV2 = (channelId: string, epoch: string) =>
  `hubs-call-key\n${channelId}\n${epoch}`;
/** Wraps the call key for an older app (version 2): AES-256-GCM under the raw ECDH secret. */
export async function wrapCallKeyV2(
  callKey: Uint8Array,
  privateKey: CryptoKey,
  recipientPublicKey: string,
  context: string,
  iv: Uint8Array = freshIv(),
): Promise<{ wrapped: string; iv: string }> {
  return sealCallKey(
    await callSharedSecret(privateKey, recipientPublicKey),
    callKey,
    te.encode(context),
    iv,
  );
}
/** Opens a version 2 wrapped call key. */
export async function unwrapCallKeyV2(
  sealed: { wrapped: string; iv: string },
  privateKey: CryptoKey,
  senderPublicKey: string,
  context: string,
): Promise<Uint8Array> {
  return openCallKey(
    await callSharedSecret(privateKey, senderPublicKey),
    sealed,
    te.encode(context),
  );
}

/* ---------- Codes ---------- */

/**
 * The version 2 code, kept while an older app is in the call: twelve digits
 * from HMAC-SHA256 under the call key over the epoch and every connection
 * key in sorted order.
 */
export async function callCodeV2(
  epoch: string,
  publicKeys: readonly string[],
  callKey: Uint8Array,
): Promise<string> {
  const mac = await hmacSha256(
    callKey,
    te.encode(["hubs-call-code-v2", epoch, ...[...publicKeys].sort()].join("\n")),
  );
  let digits = "";
  for (let i = 0; i < 6; i++)
    digits += String(((mac[i * 2] << 8) | mac[i * 2 + 1]) % 100).padStart(2, "0");
  return `${digits.slice(0, 4)} ${digits.slice(4, 8)} ${digits.slice(8, 12)}`;
}

/**
 * The transcript the version 3 Call code and roster statements cover: the
 * call, the epoch, the key slot and every connection's hash, sorted.
 */
export function callCodeTranscript(input: {
  channelId: string;
  epoch: string;
  keyIndex: number;
  hashes: readonly Uint8Array[];
}): Uint8Array {
  if (input.hashes.some((hash) => hash.length !== 32))
    throw new Error("A connection hash must be 32 bytes.");
  const sorted = [...input.hashes].sort(compareBytes);
  return concat(
    label(CALL_CODE_LABEL),
    lengthPrefixed(input.channelId),
    lengthPrefixed(input.epoch),
    keySlot(input.keyIndex),
    u16(sorted.length),
    ...sorted,
  );
}
/** SHA-256 of a transcript, the value a roster statement signs. */
export const callTranscriptDigest = (transcript: Uint8Array) =>
  sha256(transcript);

/** The key the Call code's HMAC uses, from the call key. */
export const callCodeKey = (callKey: Uint8Array) =>
  hkdf(callKey, te.encode(CALL_CODE_LABEL));

/** Twenty digits in four groups of five, from the first 20 bytes of the MAC. */
export function callCodeDigits(mac: Uint8Array): string {
  const groups: string[] = [];
  for (let i = 0; i < 4; i++) {
    let value = 0;
    for (let j = 0; j < 5; j++) value = value * 256 + mac[i * 5 + j];
    groups.push(String(value % 100000).padStart(5, "0"));
  }
  return groups.join(" ");
}

/**
 * The version 3 Call code everyone in a group call compares. It covers the
 * call key, the epoch, the slot and every connection's statement, so it
 * commits to identity keys, devices and connection keys.
 */
export async function callCodeV3(
  callKey: Uint8Array,
  transcript: Uint8Array,
): Promise<string> {
  return callCodeDigits(await hmacSha256(await callCodeKey(callKey), transcript));
}
/** The MAC behind a Call code, for test vectors. */
export async function callCodeMac(callKey: Uint8Array, transcript: Uint8Array) {
  return hmacSha256(await callCodeKey(callKey), transcript);
}

/* ---------- Roster statements ---------- */

/**
 * The bytes a bound connection signs to say which connections it sees in
 * the call: the call, its own connection id, the epoch, the slot and the
 * transcript's SHA-256. It holds no secret.
 */
export function callViewBody(input: {
  channelId: string;
  leaseId: string;
  epoch: string;
  keyIndex: number;
  transcriptDigest: Uint8Array;
}): Uint8Array {
  if (input.transcriptDigest.length !== 32)
    throw new Error("A transcript digest must be 32 bytes.");
  return concat(
    label(CALL_VIEW_LABEL),
    lengthPrefixed(input.channelId),
    lengthPrefixed(input.leaseId),
    lengthPrefixed(input.epoch),
    keySlot(input.keyIndex),
    input.transcriptDigest,
  );
}
/** A roster statement as it travels in JSON. */
export type CallView = {
  epoch: string;
  keyIndex: number;
  /** Base64 SHA-256 of the transcript, 32 bytes. */
  digest: string;
  /** Base64 Ed25519 signature by the connection's device key, 64 bytes. */
  signature: string;
};
export async function signCallView(
  signKey: string,
  input: {
    channelId: string;
    leaseId: string;
    epoch: string;
    keyIndex: number;
    transcriptDigest: Uint8Array;
  },
): Promise<CallView> {
  const signature = await ed25519Sign(fromBase64(signKey), callViewBody(input));
  return {
    epoch: input.epoch,
    keyIndex: input.keyIndex,
    digest: toBase64(input.transcriptDigest),
    signature: toBase64(signature),
  };
}
/**
 * What a connection's latest roster statement says against this app's own
 * transcript digest for the current epoch and slot: "same", "different"
 * (a valid statement for this epoch over other connections), or "missing"
 * (none, an older epoch, or one that does not verify).
 */
export async function compareCallView(input: {
  channelId: string;
  leaseId: string;
  devicePublicKey: string;
  view: CallView | null | undefined;
  epoch: string;
  keyIndex: number;
  transcriptDigest: Uint8Array;
}): Promise<"same" | "different" | "missing"> {
  const view = input.view;
  if (!view || view.epoch !== input.epoch || view.keyIndex !== input.keyIndex)
    return "missing";
  const digest = exactBase64(view.digest, 32);
  const signature = exactBase64(view.signature, 64);
  const devicePublicKey = exactBase64(input.devicePublicKey, 32);
  if (!digest || !signature || !devicePublicKey) return "missing";
  let body: Uint8Array;
  try {
    body = callViewBody({
      channelId: input.channelId,
      leaseId: input.leaseId,
      epoch: view.epoch,
      keyIndex: view.keyIndex,
      transcriptDigest: digest,
    });
  } catch {
    return "missing";
  }
  if (!(await ed25519Verify(devicePublicKey, body, signature))) return "missing";
  return equalBytes(digest, input.transcriptDigest) ? "same" : "different";
}

/* ---------- Who gets the key ---------- */

/**
 * A connection's state, from this app's point of view:
 * - "you-linked": your own account, bound under your identity key;
 * - "you-unchecked": your own account, bound, but this device has no
 *   identity to compare it with;
 * - "you-unlinked": your own account on a device with no binding, or an
 *   older app, seen from a device that has no identity either (a device
 *   that has one refuses it: "own-unlinked");
 * - "verified": another account, bound under the identity key you pinned
 *   and verified;
 * - "not-verified": another account you have not verified, or one with no
 *   binding (no private conversations, or an older app);
 * - "changed": another account bound under a new identity key (or one whose
 *   change you have not reviewed yet), not verified before;
 * - "held": a contact you verified whose identity key changed, or who
 *   joined unbound; they get no key until you compare Safety codes again
 *   or dismiss the alert;
 * - "refused": a binding that does not verify, an identity key that cannot
 *   be right, a third account in a one-to-one call, your own account on a
 *   device that isn't linked when this one is, or an older app after the
 *   old protocol closed.
 */
export type CallPeerState =
  | "you-linked"
  | "you-unchecked"
  | "you-unlinked"
  | "verified"
  | "not-verified"
  | "changed"
  | "held"
  | "refused";

/** Why a connection was refused. */
export type CallRefusal =
  | "binding"
  | "not-in-conversation"
  | "own-identity"
  | "two-identities"
  | "own-unlinked"
  | "update-required";

export type CallPeerInput = {
  /** This app's account and its identity key (null when this device has no private conversation identity). */
  self: { userId: string; identityPublicKey: string | null };
  /** One-to-one calls: the only other account allowed in. null in group calls. */
  oneToOnePeer: string | null;
  /** The server accepts only protocol 3 (older apps are refused). */
  closed: boolean;
  connection: {
    userId: string;
    /** Missing or anything but 3 counts as 2. */
    v: number;
    /** The binding check, from checkCallBinding. */
    binding: CallBindingCheck["status"];
    /** The identity key of a valid binding. */
    identityPublicKey: string | null;
  };
  /** This device's trust in that account. */
  pin: string | null;
  /** The identity key this device marked verified for that account, if any. */
  verified: string | null;
  /** A Safety code change for that account not reviewed yet. */
  keyChange: { wasVerified: boolean } | null;
};
export type CallPeerDecision = {
  state: CallPeerState;
  /** Wrap the key for this connection, and accept a copy from it. */
  share: boolean;
  /**
   * What this device records: "first" pins the connection's identity key
   * (trust on first use), "changed" pins it and raises a key change alert
   * (clearing the verified mark), "none" changes nothing.
   */
  pin: "none" | "first" | "changed";
  refusal?: CallRefusal;
};

const refuse = (refusal: CallRefusal): CallPeerDecision => ({
  state: "refused",
  share: false,
  pin: "none",
  refusal,
});
const allow = (
  state: CallPeerState,
  pin: CallPeerDecision["pin"] = "none",
): CallPeerDecision => ({ state, share: true, pin });

/**
 * The rule every app applies to each other connection in a call, in order.
 * The app's own connection is skipped before this.
 */
export function callPeerDecision(input: CallPeerInput): CallPeerDecision {
  const { connection, self } = input;
  const older = connection.v !== CALL_PROTOCOL_VERSION;
  // A binding that does not check out (an older app never sends one).
  if (connection.binding === "invalid" || (older && connection.binding !== "none"))
    return refuse("binding");
  // A one-to-one call refuses any third account.
  if (
    input.oneToOnePeer !== null &&
    connection.userId !== self.userId &&
    connection.userId !== input.oneToOnePeer
  )
    return refuse("not-in-conversation");
  // After the old protocol closes, an older app needs an update.
  if (older && input.closed) return refuse("update-required");
  const bound = connection.binding === "valid";
  if (connection.userId === self.userId) {
    // Every device of an account that has an identity can be linked, and
    // the server can claim "you, on a device that isn't linked" at will.
    // A device that has an identity treats its own account as verified and
    // lets in only its linked devices; a device without one cannot tell
    // any of them apart, so it lets them in, shown as not linked.
    if (!bound)
      return self.identityPublicKey
        ? refuse("own-unlinked")
        : allow("you-unlinked");
    if (!self.identityPublicKey) return allow("you-unchecked");
    return connection.identityPublicKey === self.identityPublicKey
      ? allow("you-linked")
      : refuse("own-identity");
  }
  const wasVerified = !!input.verified || !!input.keyChange?.wasVerified;
  if (!bound) return wasVerified ? hold() : allow("not-verified");
  if (!self.identityPublicKey) return allow("not-verified");
  const key = connection.identityPublicKey;
  if (!input.pin) return allow("not-verified", "first");
  if (input.pin !== key)
    return wasVerified
      ? { ...hold(), pin: "changed" }
      : allow("changed", "changed");
  if (input.keyChange) return input.keyChange.wasVerified ? hold() : allow("changed");
  return input.verified === key ? allow("verified") : allow("not-verified");
}
const hold = (): CallPeerDecision => ({ state: "held", share: false, pin: "none" });

/**
 * The rule for every other connection in a call at once. Another account
 * bound under two or more identity keys in the same call cannot all be
 * right (a person has one identity at a time): connections under a key
 * other than the pinned one are refused, every one of them when none
 * matches the pin, and no key change is recorded from them. Otherwise each
 * connection follows callPeerDecision. Inputs are taken in order, so the
 * first connection of an account under a new key records the change and
 * the rest follow from it.
 */
export function callPeerDecisions(
  inputs: readonly CallPeerInput[],
): CallPeerDecision[] {
  const keysByAccount = new Map<string, Set<string>>();
  for (const input of inputs)
    if (
      input.connection.binding === "valid" &&
      input.connection.v === CALL_PROTOCOL_VERSION &&
      input.connection.userId !== input.self.userId &&
      input.connection.identityPublicKey
    ) {
      const keys = keysByAccount.get(input.connection.userId) ?? new Set();
      keys.add(input.connection.identityPublicKey);
      keysByAccount.set(input.connection.userId, keys);
    }
  const pins = new Map<string, string | null>();
  const changes = new Map<string, CallPeerInput["keyChange"]>();
  const verifiedMarks = new Map<string, string | null>();
  return inputs.map((input) => {
    const userId = input.connection.userId;
    const keys = keysByAccount.get(userId);
    if (
      keys &&
      keys.size > 1 &&
      input.connection.binding === "valid" &&
      input.connection.v === CALL_PROTOCOL_VERSION
    ) {
      const pin = pins.has(userId) ? pins.get(userId)! : input.pin;
      if (!pin || input.connection.identityPublicKey !== pin || !keys.has(pin))
        return refuse("two-identities");
    }
    // Earlier connections of the same account in this list may have pinned
    // a key or raised a change; later ones read that.
    const effective: CallPeerInput = {
      ...input,
      pin: pins.has(userId) ? pins.get(userId)! : input.pin,
      keyChange: changes.has(userId) ? changes.get(userId)! : input.keyChange,
      verified: verifiedMarks.has(userId)
        ? verifiedMarks.get(userId)!
        : input.verified,
    };
    const decision = callPeerDecision(effective);
    if (decision.pin !== "none" && input.connection.identityPublicKey) {
      pins.set(userId, input.connection.identityPublicKey);
      if (decision.pin === "changed") {
        changes.set(userId, {
          wasVerified:
            !!effective.verified || !!effective.keyChange?.wasVerified,
        });
        verifiedMarks.set(userId, null);
      }
    }
    return decision;
  });
}

/** The protocol a pair of connections wraps in: the lower of the two. */
export const callPairVersion = (a: number | undefined, b: number | undefined) =>
  a === CALL_PROTOCOL_VERSION && b === CALL_PROTOCOL_VERSION
    ? CALL_PROTOCOL_VERSION
    : 2;
