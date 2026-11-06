/**
 * The private conversation protocol: constants, the exact bytes each
 * signature and commitment covers, the key package lifetime policy, the
 * payload rules and the wire types. The server and every client share them.
 */

/** MLS ciphersuite 1: X25519, AES-128-GCM, SHA-256 and Ed25519. */
export const PRIVATE_DM_CIPHERSUITE =
  "MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519" as const;

/** Disappearing message timers, in seconds. 0 means messages stay. */
export const PRIVATE_DM_TIMERS = [
  { seconds: 300, label: "5 minutes" },
  { seconds: 3600, label: "1 hour" },
  { seconds: 28800, label: "8 hours" },
  { seconds: 86400, label: "1 day" },
  { seconds: 604800, label: "1 week" },
  { seconds: 2419200, label: "4 weeks" },
  { seconds: 0, label: "Off" },
] as const;
/** Messages disappear after a week unless someone picks another timer. */
export const PRIVATE_DM_DEFAULT_TIMER = 604800;
/**
 * The server keeps ciphertext for devices that are offline at most this
 * long, even with the timer off. Devices keep their own copy.
 */
export const PRIVATE_DM_MAX_QUEUE_SECONDS = 30 * 86400;
export const isPrivateDmTimer = (seconds: number) =>
  PRIVATE_DM_TIMERS.some((timer) => timer.seconds === seconds);
export const timerLabel = (seconds: number) =>
  PRIVATE_DM_TIMERS.find((timer) => timer.seconds === seconds)?.label ??
  `${Math.round(seconds / 60)} minutes`;

/** The bytes an account identity key signs to vouch for one device key. */
export function deviceCertificateBody(
  userId: string,
  deviceId: string,
  devicePublicKey: Uint8Array,
): Uint8Array {
  const head = new TextEncoder().encode(
    `hubs private dms device v1\0${userId}\0${deviceId}\0`,
  );
  const out = new Uint8Array(head.length + devicePublicKey.length);
  out.set(head);
  out.set(devicePublicKey, head.length);
  return out;
}

/** How far a self-removal's time may be from the server's clock. */
export const PRIVATE_DM_SELF_REMOVE_WINDOW_MS = 5 * 60 * 1000;

/**
 * The bytes a device signs with its own device key to remove itself without
 * a step-up check, for example when an app signs out. Only the real device
 * holds that key, so a session alone still cannot remove a device.
 */
export function selfRemoveBody(
  userId: string,
  deviceId: string,
  at: number,
): Uint8Array {
  return new TextEncoder().encode(
    `hubs private dms self-remove v1\0${userId}\0${deviceId}\0${at}`,
  );
}

/**
 * The bytes an account identity key signs to remove one of its devices.
 * Other people's devices remove a device from their conversations only
 * with this signature, or with that device's own self-removal proof, so
 * the server alone cannot make anyone drop a person's device. The device
 * public key is the last 32 bytes; `at` is the signer's clock in
 * milliseconds, written in decimal.
 */
export function deviceRemovalBody(
  userId: string,
  deviceId: string,
  devicePublicKey: Uint8Array,
  at: number,
): Uint8Array {
  const head = new TextEncoder().encode(
    `hubs private dms remove device v1\0${userId}\0${deviceId}\0${at}\0`,
  );
  const out = new Uint8Array(head.length + devicePublicKey.length);
  out.set(head);
  out.set(devicePublicKey, head.length);
  return out;
}

/**
 * The bytes an account identity key signs to say that every removal of
 * its devices is signed from now on. A device that has seen this statement
 * for a person's identity key ignores unsigned removals of that person's
 * devices. Until then, unsigned removals still count, because some app
 * builds cannot sign them. The identity public key is the last 32 bytes.
 */
export function signedRemovalsBody(
  userId: string,
  identityPublicKey: Uint8Array,
): Uint8Array {
  const head = new TextEncoder().encode(
    `hubs private dms signed removals v1\0${userId}\0`,
  );
  const out = new Uint8Array(head.length + identityPublicKey.length);
  out.set(head);
  out.set(identityPublicKey, head.length);
  return out;
}

const SIGNED_REMOVALS_NOTE_LABEL = new TextEncoder().encode(
  "hubs private dms signed removals note v1\0",
);

/**
 * What a commit carries as its authenticated data once the sender's account
 * has stated that its removals are signed: this label, then the identity
 * key's 64-byte signature over `signedRemovalsBody`. The commit's signature
 * and encryption cover this data, so the statement reaches contacts inside
 * the group, where the server cannot strip it. Clients that do not know the
 * note ignore it.
 */
export function signedRemovalsNote(signature: Uint8Array): Uint8Array {
  const out = new Uint8Array(
    SIGNED_REMOVALS_NOTE_LABEL.length + signature.length,
  );
  out.set(SIGNED_REMOVALS_NOTE_LABEL);
  out.set(signature, SIGNED_REMOVALS_NOTE_LABEL.length);
  return out;
}

/** The signature in a commit's authenticated data, or null when it holds no note. */
export function readSignedRemovalsNote(data: Uint8Array): Uint8Array | null {
  const label = SIGNED_REMOVALS_NOTE_LABEL;
  if (
    data.length !== label.length + 64 ||
    !label.every((byte, i) => data[i] === byte)
  )
    return null;
  return data.slice(label.length);
}

/** The label the server's franking stamp covers, with its fields in order. */
export function frankingStampBody(input: {
  commitment: string;
  senderUserId: string;
  conversationId: string;
  stampedAt: string;
}): string {
  return JSON.stringify([
    "hubs private dms stamp v1",
    input.commitment,
    input.senderUserId,
    input.conversationId,
    input.stampedAt,
  ]);
}

/** Fresh key packages each device keeps on the server. */
export const PRIVATE_DM_KEY_PACKAGE_TARGET = 20;
/**
 * Active private devices one account may have at a time. Two full accounts
 * must fit in one claim and one commit's welcomes (50 each on the server),
 * or a contact with many devices could stop the other person's sync.
 */
export const PRIVATE_DM_MAX_DEVICES = 20;

/**
 * Key package lifetime policy, the same on the server and in every client:
 * a key package is valid for 90 days, and each device replaces its own
 * every 30 days. One that never expires is refused.
 */
export const PRIVATE_DM_KEY_PACKAGE_LIFETIME_SECONDS = 90 * 86400;
export const PRIVATE_DM_KEY_PACKAGE_REFRESH_SECONDS = 30 * 86400;
/** notBefore is set this far back, and a key package this early still counts as valid. */
export const PRIVATE_DM_KEY_PACKAGE_CLOCK_SKEW_SECONDS = 3600;

export type KeyPackageLifetime = { notBefore: bigint; notAfter: bigint };

/** The lifetime of a key package made at `nowMs`: an hour back to 90 days on. */
export function keyPackageLifetime(nowMs: number): KeyPackageLifetime {
  const now = BigInt(Math.floor(nowMs / 1000));
  return {
    notBefore: now - BigInt(PRIVATE_DM_KEY_PACKAGE_CLOCK_SKEW_SECONDS),
    notAfter: now + BigInt(PRIVATE_DM_KEY_PACKAGE_LIFETIME_SECONDS),
  };
}

/** Why a key package's lifetime is outside the policy at `nowMs`, or null. */
export function keyPackageLifetimeProblem(
  lifetime: KeyPackageLifetime,
  nowMs: number,
): string | null {
  const now = BigInt(Math.floor(nowMs / 1000));
  const skew = BigInt(PRIVATE_DM_KEY_PACKAGE_CLOCK_SKEW_SECONDS);
  if (lifetime.notAfter <= lifetime.notBefore)
    return "This key package's lifetime is empty.";
  if (
    lifetime.notAfter - lifetime.notBefore >
    BigInt(PRIVATE_DM_KEY_PACKAGE_LIFETIME_SECONDS) + skew
  )
    return "This key package is valid for longer than 90 days.";
  if (lifetime.notBefore > now + skew)
    return "This key package is not valid yet.";
  if (lifetime.notAfter <= now) return "This key package has expired.";
  return null;
}

/** What the server also asks of a key package it stores: made recently, with 60 days or more left. */
export function keyPackagePublishProblem(
  lifetime: KeyPackageLifetime,
  nowMs: number,
): string | null {
  const problem = keyPackageLifetimeProblem(lifetime, nowMs);
  if (problem) return problem;
  const now = BigInt(Math.floor(nowMs / 1000));
  return lifetime.notAfter <
    now +
      BigInt(
        PRIVATE_DM_KEY_PACKAGE_LIFETIME_SECONDS -
          PRIVATE_DM_KEY_PACKAGE_REFRESH_SECONDS,
      )
    ? "This key package was made too long ago."
    : null;
}
/** Largest encrypted message the server accepts, in base64 characters. */
export const PRIVATE_DM_MAX_CIPHERTEXT = 64 * 1024;
/**
 * Each device refreshes its own keys in every conversation at least this
 * often with an MLS commit (an update path), so a stolen key stops working
 * even when nobody adds or removes a device: post-compromise security.
 */
export const PRIVATE_DM_KEY_UPDATE_SECONDS = 7 * 86400;
/**
 * A link request stays open this long, on the server and on the new
 * device, which refuses a hand-off that arrives later by its own clock.
 */
export const PRIVATE_DM_LINK_SECONDS = 15 * 60;
/** Link v2: the secret the new device shows in its code, in bytes. */
export const PRIVATE_DM_LINK_SECRET_BYTES = 5;
/** History transfer: every part's plaintext is exactly this many bytes. */
export const PRIVATE_DM_HISTORY_PART_BYTES = 262144;
/** The most JSON one part holds (the part less its 4-byte length). */
export const PRIVATE_DM_HISTORY_JSON_MAX = PRIVATE_DM_HISTORY_PART_BYTES - 4;
/**
 * A sealed history part on the wire is always this many characters:
 * {"v":2,"enc":"<44>","ct":"<349584>"} with standard padded base64.
 */
export const PRIVATE_DM_HISTORY_SEALED_CHARS = 349652;
/** Part counts are padded up to one of these, so the size shows only in four steps. */
export const PRIVATE_DM_HISTORY_PART_COUNTS = [1, 4, 16, 64] as const;
/** The smallest allowed part count that holds `parts`, or null when none does. */
export const paddedHistoryCount = (parts: number): number | null =>
  parts < 1
    ? null
    : (PRIVATE_DM_HISTORY_PART_COUNTS.find((count) => count >= parts) ?? null);

/**
 * What travels inside the encryption. The server never sees it.
 * `frankingKey` lets a reporter prove what was sent.
 */
export type PrivateDmPayload = {
  v: 1;
  id: string;
  kind: "text" | "timer";
  body: string;
  sentAt: number;
  expiresInSeconds: number;
  userId: string;
  deviceId: string;
  frankingKey: string;
};

/** Longest message text, in UTF-16 code units, a device sends or accepts. */
export const PRIVATE_DM_MAX_BODY = 4000;
/**
 * How far a received message's own time may sit before the server's relay
 * time. A message dated earlier shows at the relay time minus this, so a
 * sender cannot slip a message far up into the history.
 */
export const PRIVATE_DM_CLOCK_SKEW_MS = 10 * 60 * 1000;
const PAYLOAD_KEYS = [
  "v",
  "id",
  "kind",
  "body",
  "sentAt",
  "expiresInSeconds",
  "userId",
  "deviceId",
  "frankingKey",
] as const;
/** True when a string has no lone UTF-16 surrogate (every platform can encode it). */
export const isWellFormedText = (text: string) =>
  !/[\uD800-\uDBFF](?![\uDC00-\uDFFF])|(?<![\uD800-\uDBFF])[\uDC00-\uDFFF]/.test(
    text,
  );

/**
 * Why a decrypted payload is not one a device may show, or null. Every
 * client applies the same rules before it trusts a payload: exactly the
 * known fields, an id of letters, digits, "-" and "_" (so it cannot collide
 * with this device's own notices), text or timer only, a timer from the
 * fixed list, safe integers, well-formed text and a 32-byte franking key. A
 * payload that fails is refused like a message that does not open.
 */
export function privateDmPayloadProblem(value: unknown): string | null {
  if (!value || typeof value !== "object" || Array.isArray(value))
    return "The payload is not an object.";
  const payload = value as Record<string, unknown>;
  const keys = Object.keys(payload);
  if (
    keys.length !== PAYLOAD_KEYS.length ||
    !PAYLOAD_KEYS.every((key) => keys.includes(key))
  )
    return "The payload has unknown or missing fields.";
  if (payload.v !== 1) return "Unknown payload version.";
  if (
    typeof payload.id !== "string" ||
    !/^[A-Za-z0-9_-]{1,64}$/.test(payload.id)
  )
    return "The message id is not valid.";
  if (payload.kind !== "text" && payload.kind !== "timer")
    return "Messages are text or timer changes.";
  if (
    typeof payload.body !== "string" ||
    payload.body.length > PRIVATE_DM_MAX_BODY ||
    !isWellFormedText(payload.body)
  )
    return "The message text is not valid.";
  if (payload.kind === "timer" && payload.body !== "")
    return "A timer change carries no text.";
  if (
    typeof payload.sentAt !== "number" ||
    !Number.isSafeInteger(payload.sentAt) ||
    payload.sentAt < 0
  )
    return "The message time is not valid.";
  if (
    typeof payload.expiresInSeconds !== "number" ||
    !isPrivateDmTimer(payload.expiresInSeconds)
  )
    return "The disappearing timer is not one of the choices.";
  for (const [key, max] of [
    ["userId", 128],
    ["deviceId", 64],
  ] as const) {
    const field = payload[key];
    if (
      typeof field !== "string" ||
      !field ||
      field.length > max ||
      !isWellFormedText(field)
    )
      return `The payload's ${key} is not valid.`;
  }
  if (
    typeof payload.frankingKey !== "string" ||
    // 32 bytes leave 2 spare bits in the last character. They must be zero,
    // as every platform's strict base64 requires.
    !/^[A-Za-z0-9+/]{42}[AEIMQUYcgkosw048]=$/.test(payload.frankingKey)
  )
    return "The franking key must be 32 bytes.";
  return null;
}

/** The exact bytes the franking commitment covers (everything but the key). */
export function canonicalPayloadBytes(payload: PrivateDmPayload): Uint8Array {
  return new TextEncoder().encode(
    JSON.stringify([
      "hubs private dms message v1",
      payload.v,
      payload.id,
      payload.kind,
      payload.body,
      payload.sentAt,
      payload.expiresInSeconds,
      payload.userId,
      payload.deviceId,
    ]),
  );
}

export type PrivateDmDevice = {
  id: string;
  userId: string;
  identityKey: string;
  deviceKey: string;
  certificate: string;
  createdAt: string;
  /** The client this device last ran can sign removals (this account's own list only). */
  signsRemovals?: boolean;
};
/**
 * A removed device, as the server lists it for a conversation's members.
 * `signature` proves the removal: by the identity key over
 * `deviceRemovalBody` (kind "identity"), or by the device's own key over
 * `selfRemoveBody` (kind "self"). Other kinds carry no proof: "reset"
 * (the person started over with a new identity), "unsigned" (a client that
 * cannot sign) and "session" (removed with a lost device that shared its
 * sign-in).
 */
export type PrivateDmRevocation = {
  id: string;
  userId: string;
  identityKey: string;
  deviceKey: string;
  revokedAt: string;
  kind: "identity" | "self" | "reset" | "unsigned" | "session";
  /** The signer's time in the signed bytes (milliseconds). */
  at: number | null;
  signature: string | null;
  /** The client that made the removal: "web", or "ios:<build>" and so on. */
  client: string | null;
};
/** An identity key's signed statement that its removals are signed (`signedRemovalsBody`). */
export type PrivateDmRemovalStatement = {
  userId: string;
  identityKey: string;
  signature: string;
};
export type PrivateDmMember = {
  userId: string;
  handle: string;
  displayName: string;
  /** True for accounts the server counts as new. Clients hold their links behind a tap. */
  newAccount: boolean;
  /** True when the person is a friend of the viewer. */
  friend: boolean;
};
export type PrivateDmConversation = {
  id: string;
  /** The ordinary one-to-one conversation this private one was made from. */
  dmChannelId: string | null;
  createdBy: string;
  createdAt: string;
  epoch: number;
  timerSeconds: number;
  members: PrivateDmMember[];
  /** Set while the viewer has not accepted yet. */
  pending: boolean;
};
export type PrivateDmEnvelope = {
  id: string;
  seq: number;
  conversationId: string;
  kind: "message" | "commit" | "welcome";
  senderUserId: string;
  senderDeviceId: string;
  /** For welcomes: the key package the welcome was made for. */
  keyPackageId: string | null;
  epoch: number;
  ciphertext: string;
  /** The server's stamp on the franking commitment (messages only). */
  frankingTag: string | null;
  /** Which of the server's stamp keys made `frankingTag`; a report sends it back. */
  frankingKeyId?: string | null;
  createdAt: string;
  expiresAt: string;
};
export type PrivateDmState = {
  enabled: boolean;
  devices: PrivateDmDevice[];
  hasBackup: boolean;
  /** The identity key whose statement that removals are signed the server holds, if any. */
  signedRemovals?: string | null;
  /** On for this service, but not on this address: only at its main address. */
  onMainAddress?: boolean;
};

/** A message a reporter's device reveals, with what proves it was sent. */
export type PrivateDmReportedMessage = {
  envelopeId: string;
  payload: PrivateDmPayload;
  commitment: string;
  frankingTag: string;
  frankingKeyId?: string;
  senderUserId: string;
  conversationId: string;
  stampedAt: string;
};
