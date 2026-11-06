/**
 * The device-side encryption engine for private conversations.
 *
 * Every primitive comes from ts-mls (MLS, RFC 9420) and the libraries it is
 * built on (@hpke/core, WebCrypto, @noble). Nothing here implements a cipher,
 * a signature or a key agreement. This file composes the library's calls:
 * MLS groups for conversations, the ciphersuite's signature for device
 * certificates, its hash for safety codes, its HMAC for message franking,
 * HPKE for linking a device, and its AEAD for the passkey backup.
 */
import {
  type ClientConfig,
  type ClientState,
  type CiphersuiteImpl,
  type KeyPackage,
  type PrivateKeyPackage,
  type Credential,
  createApplicationMessage,
  createCommit,
  createGroup,
  decodeGroupState,
  decodeMlsMessage,
  defaultCapabilities,
  defaultKeyPackageEqualityConfig,
  defaultKeyRetentionConfig,
  defaultLifetimeConfig,
  defaultPaddingConfig,
  emptyPskIndex,
  encodeGroupState,
  encodeMlsMessage,
  generateKeyPackageWithKey,
  getCiphersuiteFromName,
  getCiphersuiteImpl,
  joinGroup,
  processPrivateMessage,
  zeroOutUint8Array,
} from "ts-mls";
import { decryptSenderData } from "ts-mls/privateMessage.js";
import {
  PRIVATE_DM_CIPHERSUITE,
  PRIVATE_DM_HISTORY_JSON_MAX,
  PRIVATE_DM_HISTORY_PART_BYTES,
  PRIVATE_DM_LINK_SECRET_BYTES,
  type KeyPackageLifetime,
  type PrivateDmPayload,
  canonicalPayloadBytes,
  deviceCertificateBody,
  deviceRemovalBody,
  keyPackageLifetime,
  keyPackageLifetimeProblem,
  privateDmPayloadProblem,
  readSignedRemovalsNote,
  selfRemoveBody,
  signedRemovalsBody,
} from "./protocol.js";

const te = new TextEncoder();
const td = new TextDecoder();
const strictUtf8 = new TextDecoder("utf-8", { fatal: true });

let suite: Promise<CiphersuiteImpl> | undefined;
/** The one ciphersuite private conversations use (X25519, AES-128-GCM, Ed25519). */
export const ciphersuite = () =>
  (suite ??= getCiphersuiteImpl(
    getCiphersuiteFromName(PRIVATE_DM_CIPHERSUITE),
  ));

export function toBase64(bytes: Uint8Array): string {
  let text = "";
  for (let i = 0; i < bytes.length; i += 0x8000)
    text += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  return btoa(text);
}
export function fromBase64(text: string): Uint8Array {
  const raw = atob(text);
  const bytes = new Uint8Array(raw.length);
  for (let i = 0; i < raw.length; i++) bytes[i] = raw.charCodeAt(i);
  return bytes;
}
/**
 * True for exactly the text `toBase64` writes. `atob` also takes spare bits,
 * spaces and missing padding, which other platforms' strict decoders refuse,
 * so a value that opens on one platform must be this form on all of them.
 */
export function isStrictBase64(text: string): boolean {
  try {
    return toBase64(fromBase64(text)) === text;
  } catch {
    return false;
  }
}
const concat = (...parts: Uint8Array[]) => {
  const out = new Uint8Array(parts.reduce((n, p) => n + p.length, 0));
  let at = 0;
  for (const part of parts) {
    out.set(part, at);
    at += part.length;
  }
  return out;
};
const equalBytes = (a: Uint8Array, b: Uint8Array) =>
  a.length === b.length && a.every((value, i) => value === b[i]);

/** The account identity key. It lives only on the person's devices and in their passkey backup. */
export type IdentityKeys = { publicKey: string; signKey: string };
/** One device's keys and its certificate from the account identity key. */
export type DeviceKeys = {
  userId: string;
  deviceId: string;
  identityPublicKey: string;
  publicKey: string;
  signKey: string;
  certificate: string;
};
/** What a device certificate (the MLS credential) says. */
export type DeviceCredential = {
  v: 1;
  userId: string;
  deviceId: string;
  identityPublicKey: string;
  certificate: string;
};

export async function createIdentity(): Promise<IdentityKeys> {
  const cs = await ciphersuite();
  const pair = await cs.signature.keygen();
  return {
    publicKey: toBase64(pair.publicKey),
    signKey: toBase64(pair.signKey),
  };
}

/** Make a new device key and sign it with the account identity key. */
export async function createDevice(
  identity: IdentityKeys,
  userId: string,
  deviceId: string,
): Promise<DeviceKeys> {
  const cs = await ciphersuite();
  const pair = await cs.signature.keygen();
  const certificate = await cs.signature.sign(
    fromBase64(identity.signKey),
    deviceCertificateBody(userId, deviceId, pair.publicKey),
  );
  return {
    userId,
    deviceId,
    identityPublicKey: identity.publicKey,
    publicKey: toBase64(pair.publicKey),
    signKey: toBase64(pair.signKey),
    certificate: toBase64(certificate),
  };
}

const credentialFor = (device: DeviceKeys): Credential => ({
  credentialType: "basic",
  identity: te.encode(
    JSON.stringify({
      v: 1,
      userId: device.userId,
      deviceId: device.deviceId,
      identityPublicKey: device.identityPublicKey,
      certificate: device.certificate,
    } satisfies DeviceCredential),
  ),
});

export function readCredential(
  credential: Credential,
): DeviceCredential | null {
  if (credential.credentialType !== "basic") return null;
  try {
    const value = JSON.parse(td.decode(credential.identity));
    if (
      value?.v === 1 &&
      typeof value.userId === "string" &&
      typeof value.deviceId === "string" &&
      typeof value.identityPublicKey === "string" &&
      typeof value.certificate === "string" &&
      isStrictBase64(value.identityPublicKey) &&
      isStrictBase64(value.certificate)
    )
      return value;
  } catch {
    // Not a credential in this format.
  }
  return null;
}

/** Check that a device key was signed by the identity key its credential names. */
export async function verifyDeviceCertificate(
  credential: DeviceCredential,
  devicePublicKey: Uint8Array,
): Promise<boolean> {
  const cs = await ciphersuite();
  try {
    return await cs.signature.verify(
      fromBase64(credential.identityPublicKey),
      deviceCertificateBody(
        credential.userId,
        credential.deviceId,
        devicePublicKey,
      ),
      fromBase64(credential.certificate),
    );
  } catch {
    return false;
  }
}

/** The identity key's signature removing one of this account's devices. */
export async function signDeviceRemoval(
  identity: IdentityKeys,
  userId: string,
  deviceId: string,
  devicePublicKey: string,
  at: number,
): Promise<string> {
  const cs = await ciphersuite();
  return toBase64(
    await cs.signature.sign(
      fromBase64(identity.signKey),
      deviceRemovalBody(userId, deviceId, fromBase64(devicePublicKey), at),
    ),
  );
}

/** A device's own signature removing itself from its account. */
export async function signSelfRemoval(
  device: DeviceKeys,
  at: number,
): Promise<string> {
  const cs = await ciphersuite();
  return toBase64(
    await cs.signature.sign(
      fromBase64(device.signKey),
      selfRemoveBody(device.userId, device.deviceId, at),
    ),
  );
}

/** The identity key's statement that this account's removals are signed. */
export async function signRemovalStatement(
  identity: IdentityKeys,
  userId: string,
): Promise<string> {
  const cs = await ciphersuite();
  return toBase64(
    await cs.signature.sign(
      fromBase64(identity.signKey),
      signedRemovalsBody(userId, fromBase64(identity.publicKey)),
    ),
  );
}

const verifies = async (
  publicKey: string,
  body: Uint8Array,
  signature: string,
) => {
  const cs = await ciphersuite();
  try {
    return await cs.signature.verify(
      fromBase64(publicKey),
      body,
      fromBase64(signature),
    );
  } catch {
    return false;
  }
};

/**
 * Whether a removal proof covers this exact group member: the identity key
 * in its credential signed `deviceRemovalBody` over its device key, or its
 * own device key signed `selfRemoveBody`.
 */
export function verifyRemoval(
  member: Pick<
    GroupMember,
    "userId" | "deviceId" | "identityPublicKey" | "devicePublicKey"
  >,
  proof: { kind: string; at: number | null; signature: string | null },
): Promise<boolean> {
  if (!proof.signature || proof.at === null || !Number.isSafeInteger(proof.at))
    return Promise.resolve(false);
  if (proof.kind === "identity")
    return verifies(
      member.identityPublicKey,
      deviceRemovalBody(
        member.userId,
        member.deviceId,
        fromBase64(member.devicePublicKey),
        proof.at,
      ),
      proof.signature,
    );
  if (proof.kind === "self")
    return verifies(
      member.devicePublicKey,
      selfRemoveBody(member.userId, member.deviceId, proof.at),
      proof.signature,
    );
  return Promise.resolve(false);
}

/** Whether an identity key signed the statement that its removals are signed. */
export const verifyRemovalStatement = (statement: {
  userId: string;
  identityKey: string;
  signature: string;
}) =>
  verifies(
    statement.identityKey,
    signedRemovalsBody(statement.userId, fromBase64(statement.identityKey)),
    statement.signature,
  );

/** MLS client settings: the library defaults plus our certificate check. */
export function clientConfig(): ClientConfig {
  return {
    keyRetentionConfig: defaultKeyRetentionConfig,
    lifetimeConfig: defaultLifetimeConfig,
    keyPackageEqualityConfig: defaultKeyPackageEqualityConfig,
    paddingConfig: defaultPaddingConfig,
    authService: {
      async validateCredential(credential, signaturePublicKey) {
        const parsed = readCredential(credential);
        return (
          !!parsed &&
          (await verifyDeviceCertificate(parsed, signaturePublicKey))
        );
      },
    },
  };
}

/** A key package ready to upload, and the private half that stays on the device. */
export type DeviceKeyPackage = {
  id: string;
  publicPackage: string;
  privatePackage: string;
  /** When it was made and when it stops being valid (ms). Missing on key packages made before the lifetime policy. */
  createdAt?: number;
  expiresAt?: number;
  /**
   * The device's last-resort key package (RFC 9420 section 16.8): the
   * server hands it out only when the one-time ones run out, and more than
   * one welcome may use it, so its private half is kept after a join.
   */
  lastResort?: boolean;
  /**
   * When a newer last-resort package took this one's place. No new welcome
   * can name it after the server's queue time, so its private half goes then.
   */
  replacedAt?: number;
};
const encodePrivatePackage = (value: PrivateKeyPackage) =>
  JSON.stringify({
    initPrivateKey: toBase64(value.initPrivateKey),
    hpkePrivateKey: toBase64(value.hpkePrivateKey),
    signaturePrivateKey: toBase64(value.signaturePrivateKey),
  });
const decodePrivatePackage = (text: string): PrivateKeyPackage => {
  const value = JSON.parse(text);
  return {
    initPrivateKey: fromBase64(value.initPrivateKey),
    hpkePrivateKey: fromBase64(value.hpkePrivateKey),
    signaturePrivateKey: fromBase64(value.signaturePrivateKey),
  };
};
export const encodeKeyPackageMessage = (keyPackage: KeyPackage) =>
  toBase64(
    encodeMlsMessage({
      keyPackage,
      wireformat: "mls_key_package",
      version: "mls10",
    }),
  );
export function decodeKeyPackageMessage(text: string): KeyPackage {
  const decoded = decodeMlsMessage(fromBase64(text), 0)?.[0];
  if (!decoded || decoded.wireformat !== "mls_key_package")
    throw new Error("That is not a key package.");
  return decoded.keyPackage;
}

/** Who a published key package says it belongs to, or null when it cannot be read. */
export function keyPackageCredential(text: string): DeviceCredential | null {
  try {
    return readCredential(decodeKeyPackageMessage(text).leafNode.credential);
  } catch {
    return null;
  }
}

/** A key package's lifetime (its leaf node's), or null when it has none. */
export function keyPackageLifetimeOf(
  keyPackage: KeyPackage,
): KeyPackageLifetime | null {
  const leaf = keyPackage.leafNode;
  return leaf.leafNodeSource === "key_package" ? leaf.lifetime : null;
}

/**
 * Why a key package another device published may not be added at `nowMs`
 * (the lifetime policy in protocol.ts), or null. ts-mls checks only that it
 * is valid now; this also refuses one that is valid for too long.
 */
export function keyPackageProblem(text: string, nowMs: number): string | null {
  try {
    const lifetime = keyPackageLifetimeOf(decodeKeyPackageMessage(text));
    return lifetime
      ? keyPackageLifetimeProblem(lifetime, nowMs)
      : "That is not a key package.";
  } catch {
    return "That is not a key package.";
  }
}

/** One-time key packages other people's devices use to add this device, valid for 90 days. */
export async function createKeyPackages(
  device: DeviceKeys,
  count: number,
  nowMs = Date.now(),
): Promise<DeviceKeyPackage[]> {
  const cs = await ciphersuite();
  const lifetime = keyPackageLifetime(nowMs);
  const packages: DeviceKeyPackage[] = [];
  for (let i = 0; i < count; i++) {
    const made = await generateKeyPackageWithKey(
      credentialFor(device),
      defaultCapabilities(),
      lifetime,
      [],
      {
        publicKey: fromBase64(device.publicKey),
        signKey: fromBase64(device.signKey),
      },
      cs,
    );
    packages.push({
      id: toBase64(cs.rng.randomBytes(12))
        .replace(/\+/g, "-")
        .replace(/\//g, "_"),
      publicPackage: encodeKeyPackageMessage(made.publicPackage),
      privatePackage: encodePrivatePackage(made.privatePackage),
      createdAt: nowMs,
      expiresAt: Number(lifetime.notAfter) * 1000,
    });
  }
  return packages;
}

/** What a device keeps for each conversation: the MLS group state. */
export const saveGroup = (state: ClientState) =>
  toBase64(encodeGroupState(state));
export function loadGroup(saved: string): ClientState {
  const decoded = decodeGroupState(fromBase64(saved), 0)?.[0];
  if (!decoded) throw new Error("This conversation's keys could not be read.");
  // Commits carry their proposals by value, so a stored pending proposal can
  // only be one another member slipped in. It would block sending for good.
  return { ...decoded, unappliedProposals: {}, clientConfig: clientConfig() };
}

/** The people and devices in a conversation, as their certificates say. */
export type GroupMember = DeviceCredential & {
  leafIndex: number;
  devicePublicKey: string;
};
export function groupMembers(state: ClientState): GroupMember[] {
  const members: GroupMember[] = [];
  state.ratchetTree.forEach((node, nodeIndex) => {
    if (node?.nodeType !== "leaf") return;
    const credential = readCredential(node.leaf.credential);
    if (credential)
      members.push({
        ...credential,
        leafIndex: nodeIndex / 2,
        devicePublicKey: toBase64(node.leaf.signaturePublicKey),
      });
  });
  return members;
}

const wire = {
  welcome: (
    welcome: NonNullable<Awaited<ReturnType<typeof createCommit>>["welcome"]>,
  ) =>
    toBase64(
      encodeMlsMessage({
        welcome,
        wireformat: "mls_welcome",
        version: "mls10",
      }),
    ),
  privateMessage: (
    privateMessage: Awaited<
      ReturnType<typeof createApplicationMessage>
    >["privateMessage"],
  ) =>
    toBase64(
      encodeMlsMessage({
        privateMessage,
        wireformat: "mls_private_message",
        version: "mls10",
      }),
    ),
};

/** Start a conversation as its only member. */
export async function startGroup(
  device: DeviceKeys,
  conversationId: string,
  nowMs = Date.now(),
): Promise<ClientState> {
  const cs = await ciphersuite();
  const own = await generateKeyPackageWithKey(
    credentialFor(device),
    defaultCapabilities(),
    keyPackageLifetime(nowMs),
    [],
    {
      publicKey: fromBase64(device.publicKey),
      signKey: fromBase64(device.signKey),
    },
    cs,
  );
  return createGroup(
    te.encode(conversationId),
    own.publicPackage,
    own.privatePackage,
    [],
    cs,
    clientConfig(),
  );
}

/**
 * Add and remove devices in one commit. The commit goes to the devices
 * already in the conversation; the welcome goes to the new ones. `note` is
 * the commit's authenticated data (see `signedRemovalsNote`).
 */
export async function changeDevices(
  state: ClientState,
  add: string[],
  removeLeaves: number[] = [],
  note?: Uint8Array,
): Promise<{
  state: ClientState;
  commit: string;
  welcome: string | null;
  epoch: number;
}> {
  const cs = await ciphersuite();
  const result = await createCommit(
    { state, cipherSuite: cs },
    {
      ratchetTreeExtension: true,
      ...(note ? { authenticatedData: note } : {}),
      extraProposals: [
        ...add.map((text) => ({
          proposalType: "add" as const,
          add: { keyPackage: decodeKeyPackageMessage(text) },
        })),
        ...removeLeaves.map((removed) => ({
          proposalType: "remove" as const,
          remove: { removed: removed as never },
        })),
      ],
    },
  );
  result.consumed.forEach(zeroOutUint8Array);
  const commit = toBase64(encodeMlsMessage(result.commit));
  return {
    state: result.newState,
    commit,
    welcome: result.welcome ? wire.welcome(result.welcome) : null,
    epoch: Number(state.groupContext.epoch),
  };
}

/** The conversation a group belongs to (its MLS group id). */
export const groupConversationId = (state: ClientState) =>
  td.decode(state.groupContext.groupId);

/** Join a conversation from a welcome addressed to one of this device's key packages. */
export async function joinFromWelcome(
  welcome: string,
  keyPackage: DeviceKeyPackage,
): Promise<ClientState> {
  const cs = await ciphersuite();
  const decoded = decodeMlsMessage(fromBase64(welcome), 0)?.[0];
  if (!decoded || decoded.wireformat !== "mls_welcome")
    throw new Error("That is not a welcome.");
  return joinGroup(
    decoded.welcome,
    decodeKeyPackageMessage(keyPackage.publicPackage),
    decodePrivatePackage(keyPackage.privatePackage),
    emptyPskIndex,
    cs,
    undefined,
    undefined,
    clientConfig(),
  );
}

/**
 * Message franking: the sender commits to the message with a fresh key that
 * travels inside the ciphertext. The commitment rides in the clear (as MLS
 * authenticated data) so the server can stamp it; a reporter later reveals
 * the key and the message, and anyone can check the commitment and the
 * server's stamp.
 */
export async function frankingCommitment(
  frankingKey: Uint8Array,
  payload: PrivateDmPayload,
): Promise<Uint8Array> {
  const cs = await ciphersuite();
  return cs.hash.mac(frankingKey, canonicalPayloadBytes(payload));
}

/** Encrypt one message for everyone in the conversation. */
export async function encryptMessage(
  state: ClientState,
  payload: Omit<PrivateDmPayload, "frankingKey">,
): Promise<{
  state: ClientState;
  ciphertext: string;
  commitment: string;
  payload: PrivateDmPayload;
}> {
  const cs = await ciphersuite();
  const full: PrivateDmPayload = {
    ...payload,
    frankingKey: toBase64(cs.rng.randomBytes(32)),
  };
  const commitment = await frankingCommitment(
    fromBase64(full.frankingKey),
    full,
  );
  const result = await createApplicationMessage(
    state,
    te.encode(JSON.stringify(full)),
    cs,
    commitment,
  );
  result.consumed.forEach(zeroOutUint8Array);
  return {
    state: result.newState,
    ciphertext: wire.privateMessage(result.privateMessage),
    commitment: toBase64(commitment),
    payload: full,
  };
}

/** Read the franking commitment from an encrypted message without decrypting it. */
export function readCommitment(ciphertext: string): string | null {
  try {
    const decoded = decodeMlsMessage(fromBase64(ciphertext), 0)?.[0];
    if (decoded?.wireformat !== "mls_private_message") return null;
    return toBase64(decoded.privateMessage.authenticatedData);
  } catch {
    return null;
  }
}

export type Incoming =
  | {
      kind: "message";
      state: ClientState;
      payload: PrivateDmPayload;
      commitment: string;
      sender: GroupMember;
    }
  | {
      kind: "change";
      state: ClientState;
      /** Wipe the old epoch's secrets; call once the change is accepted. */
      release(): void;
      /** The member who made the change, as the tree before it says. */
      sender: GroupMember | null;
      /** The signature in the commit's note (`signedRemovalsNote`), if any. */
      removalStatement: Uint8Array | null;
    };

/**
 * Decrypt a message or apply a membership change. A message whose franking
 * commitment does not match its contents is refused, so a reporter can only
 * ever reveal what the sender really sent.
 */
export async function receive(
  state: ClientState,
  ciphertext: string,
  /**
   * The server's sender label on the envelope. A message must name the same
   * account and device. This is checked before any secret is released, so a
   * mislabeled envelope leaves `state` whole.
   */
  label?: { userId: string; deviceId: string },
): Promise<Incoming> {
  const cs = await ciphersuite();
  const decoded = decodeMlsMessage(fromBase64(ciphertext), 0)?.[0];
  if (!decoded) throw new Error("That message could not be read.");
  if (decoded.wireformat !== "mls_private_message")
    throw new Error("Private conversations only accept encrypted messages.");
  // Every change here is a commit carrying its proposals by value. A
  // standalone proposal could only pile up and block this device's commits.
  if (decoded.privateMessage.contentType === "proposal")
    throw new Error("Private conversations do not use standalone proposals.");
  const before = groupMembers(state);
  const senderLeaf = await senderLeafIndex(state, decoded.privateMessage);
  const processed = await processPrivateMessage(
    state,
    decoded.privateMessage,
    emptyPskIndex,
    cs,
  );
  // Secrets the new state no longer needs are still shared with `state`.
  // They are wiped only once the result is accepted: a refused message or
  // commit leaves `state` whole, so the device can keep using it.
  const release = () => processed.consumed.forEach(zeroOutUint8Array);
  if (processed.kind === "newState")
    return {
      kind: "change",
      state: processed.newState,
      release,
      sender: before.find((m) => m.leafIndex === senderLeaf) ?? null,
      removalStatement: readSignedRemovalsNote(
        decoded.privateMessage.authenticatedData,
      ),
    };
  let parsed: unknown;
  try {
    // Strict UTF-8, the same decoding every other client uses.
    parsed = JSON.parse(strictUtf8.decode(processed.message));
  } catch {
    throw new Error("This message could not be read.");
  }
  // The same payload rules on every platform, before anything is trusted.
  const problem = privateDmPayloadProblem(parsed);
  if (problem) throw new Error(problem);
  const payload = parsed as PrivateDmPayload;
  const commitment = decoded.privateMessage.authenticatedData;
  const expected = await frankingCommitment(
    fromBase64(payload.frankingKey),
    payload,
  );
  if (!equalBytes(expected, commitment))
    throw new Error("This message did not match its commitment.");
  const sender = before.find((m) => m.leafIndex === senderLeaf) ?? null;
  if (
    !sender ||
    sender.userId !== payload.userId ||
    sender.deviceId !== payload.deviceId
  )
    throw new Error("This message did not come from the device it names.");
  if (
    label &&
    (label.userId !== payload.userId || label.deviceId !== payload.deviceId)
  )
    throw new Error("The server named a different sender.");
  release();
  return {
    kind: "message",
    state: processed.newState,
    payload,
    commitment: toBase64(commitment),
    sender,
  };
}

/**
 * The sender's leaf, read with the library's own sender-data decryption. MLS
 * has already checked the sender's signature by the time the message opens.
 */
async function senderLeafIndex(
  state: ClientState,
  message: Parameters<typeof decryptSenderData>[0],
): Promise<number | null> {
  return (await senderData(state, message))?.leafIndex ?? null;
}
async function senderData(
  state: ClientState,
  message: Parameters<typeof decryptSenderData>[0],
) {
  const cs = await ciphersuite();
  const secret =
    message.epoch === state.groupContext.epoch
      ? state.keySchedule.senderDataSecret
      : state.historicalReceiverData.get(message.epoch)?.senderDataSecret;
  if (!secret) return null;
  return (await decryptSenderData(message, secret, cs)) ?? null;
}

/**
 * Who sent an encrypted message, in which epoch, and its generation: the
 * position in the sender's chain of message keys for that epoch (RFC 9420
 * section 9.1), read from the sender data without opening the content.
 * Each sender's messages in an epoch count 0, 1, 2, and so on, so a gap
 * means one did not arrive. Null when this group cannot read it, or when
 * it is not an application message.
 */
export async function messageHeader(
  state: ClientState,
  ciphertext: string,
): Promise<{ epoch: number; leafIndex: number; generation: number } | null> {
  try {
    const decoded = decodeMlsMessage(fromBase64(ciphertext), 0)?.[0];
    if (
      decoded?.wireformat !== "mls_private_message" ||
      decoded.privateMessage.contentType !== "application"
    )
      return null;
    const data = await senderData(state, decoded.privateMessage);
    return data
      ? {
          epoch: Number(decoded.privateMessage.epoch),
          leafIndex: data.leafIndex,
          generation: data.generation,
        }
      : null;
  } catch {
    return null;
  }
}

/** Safety code: 60 digits from both people's identity keys, the same on both sides. */
export async function safetyCode(
  a: { userId: string; identityPublicKey: string },
  b: { userId: string; identityPublicKey: string },
): Promise<string> {
  const cs = await ciphersuite();
  const half = async (person: typeof a) => {
    const digest = await cs.hash.digest(
      concat(
        te.encode(`hubs safety code v1\0${person.userId}\0`),
        fromBase64(person.identityPublicKey),
      ),
    );
    const groups: string[] = [];
    for (let i = 0; i < 6; i++) {
      let value = 0;
      for (let j = 0; j < 5; j++) value = value * 256 + digest[i * 5 + j];
      groups.push(String(value % 100000).padStart(5, "0"));
    }
    return groups.join(" ");
  };
  const [first, second] = [a, b].sort((x, y) =>
    x.userId < y.userId ? -1 : x.userId > y.userId ? 1 : 0,
  );
  return `${await half(first)} ${await half(second)}`;
}

/** What one device hands another when linking, or keeps in the passkey backup. */
export type IdentityBundle = {
  v: 1;
  userId: string;
  identity: IdentityKeys;
  /** Contacts' identity keys this person already trusts. */
  trusted: Record<string, string>;
  /**
   * In a passkey backup: its counter, one more than any backup the saving
   * device knew of. Sealed with the rest, so the server cannot change it;
   * a device that has seen a higher counter refuses the backup. Backups
   * made before counters read as 0. Clients that do not know the field
   * ignore it, so the format stays version 1.
   */
  counter?: number;
  /** In a link hand-off: the highest backup counter the old device has seen. */
  backupCounter?: number;
  /**
   * What this person already decided about contacts, so a new device starts
   * from the same place: identity keys they compared (user id to key), safety
   * code changes not reviewed yet, and contacts' statements that their
   * removals are signed (user id to key). Older clients ignore these fields.
   */
  verified?: Record<string, string>;
  keyChanges?: Record<string, { at: number; wasVerified: boolean }>;
  signedRemovals?: Record<string, string>;
};

const LINK_INFO = te.encode("hubs private dms link v1");

/** The new device's half of linking: a fresh HPKE key pair. */
export async function createLinkKeys(): Promise<{
  publicKey: string;
  privateKey: string;
}> {
  const cs = await ciphersuite();
  const pair = await cs.hpke.generateKeyPair();
  return {
    publicKey: toBase64(await cs.hpke.exportPublicKey(pair.publicKey)),
    privateKey: toBase64(await cs.hpke.exportPrivateKey(pair.privateKey)),
  };
}

/**
 * The link code is derived from the new device's link key, so the code a
 * person types on the old device names that exact key. A server that swaps
 * in its own key would have to match these 48 bits and the 6-digit check
 * together (about 2^68 tries) inside the 10-minute window.
 */
export async function linkCode(publicKey: string): Promise<string> {
  const cs = await ciphersuite();
  const digest = await cs.hash.digest(
    concat(te.encode("hubs private dms link id v1\0"), fromBase64(publicKey)),
  );
  return [...digest.subarray(0, 6)]
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

/** A short check of the new device's link key, shown on both screens. */
export async function linkCheck(publicKey: string): Promise<string> {
  const cs = await ciphersuite();
  const digest = await cs.hash.digest(
    concat(te.encode("hubs link check\0"), fromBase64(publicKey)),
  );
  let value = 0;
  for (let i = 0; i < 4; i++) value = value * 256 + digest[i];
  return String(value % 1_000_000).padStart(6, "0");
}

/** The existing device seals the identity for the new device's link key. */
export async function sealForLink(
  linkPublicKey: string,
  bundle: IdentityBundle,
): Promise<string> {
  const cs = await ciphersuite();
  const sealed = await cs.hpke.seal(
    await cs.hpke.importPublicKey(fromBase64(linkPublicKey)),
    te.encode(JSON.stringify(bundle)),
    LINK_INFO,
  );
  return JSON.stringify({ enc: toBase64(sealed.enc), ct: toBase64(sealed.ct) });
}

export async function openLink(
  linkPrivateKey: string,
  sealed: string,
): Promise<IdentityBundle> {
  const cs = await ciphersuite();
  const value = JSON.parse(sealed);
  const opened = await cs.hpke.open(
    await cs.hpke.importPrivateKey(fromBase64(linkPrivateKey)),
    fromBase64(value.enc),
    fromBase64(value.ct),
    LINK_INFO,
  );
  return JSON.parse(td.decode(opened));
}

// Link v2 (the fix for LK-1; see the link v2 spec). The new device's code
// adds a 5-byte secret that never leaves it; the old device seals with a key
// from that secret inside the HPKE layer, so a server that seals its own
// bundle cannot make the new device take it. The byte formats are fixed by
// the link v2 reference implementation (reference.mjs) and its vectors.

/** The outer HPKE layer's info for link v2. */
const LINK_V2_INFO = te.encode("hubs private dms link v2");

/** Crockford base32, upper case, no check symbol. */
const LINK_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ";

/** A fresh link secret from the platform's secure random source. */
export function createLinkSecret(): Uint8Array {
  return crypto.getRandomValues(new Uint8Array(PRIVATE_DM_LINK_SECRET_BYTES));
}

/**
 * What a person typed, cleaned: ASCII space, tab and hyphen-minus removed,
 * then ASCII upper case. Any other character, ASCII or not, refuses the
 * whole input (null). No locale rules and no Unicode case folding.
 */
export function normalizeLinkCode(text: string): string | null {
  let out = "";
  for (const char of text) {
    const code = char.codePointAt(0)!;
    if (code === 0x20 || code === 0x09 || code === 0x2d) continue;
    if (code >= 0x30 && code <= 0x39) out += char;
    else if (code >= 0x41 && code <= 0x5a) out += char;
    else if (code >= 0x61 && code <= 0x7a)
      out += String.fromCharCode(code - 32);
    else return null;
  }
  return out;
}

/** The link secret as 8 Crockford base32 characters. */
export function encodeLinkSecret(bytes: Uint8Array): string {
  if (bytes.length !== PRIVATE_DM_LINK_SECRET_BYTES)
    throw new Error("The link secret is 5 bytes.");
  let value = 0n;
  for (const byte of bytes) value = (value << 8n) | BigInt(byte);
  let out = "";
  for (let i = 7; i >= 0; i--)
    out += LINK_ALPHABET[Number((value >> BigInt(i * 5)) & 31n)];
  return out;
}

/** 8 normalized characters to the 5 secret bytes, or null. O reads as 0, I and L as 1. */
export function decodeLinkSecret(normalized: string | null): Uint8Array | null {
  if (normalized === null || normalized.length !== 8) return null;
  const mapped = normalized.replace(/O/g, "0").replace(/[IL]/g, "1");
  let value = 0n;
  for (const char of mapped) {
    const index = LINK_ALPHABET.indexOf(char);
    if (index < 0) return null;
    value = (value << 5n) | BigInt(index);
  }
  const out = new Uint8Array(PRIVATE_DM_LINK_SECRET_BYTES);
  for (let i = 4; i >= 0; i--) {
    out[i] = Number(value & 255n);
    value >>= 8n;
  }
  return out;
}

/**
 * The full code the old device takes: 12 hex characters (the link id, sent
 * to the server in lower case), then the 8-character secret. Null for
 * anything else, including an older app's 12-character code.
 */
export function parseLinkCode(
  text: string,
): { id: string; secret: Uint8Array } | null {
  const normalized = normalizeLinkCode(text);
  if (normalized === null || normalized.length !== 20) return null;
  const id = normalized.slice(0, 12).toLowerCase();
  if (!/^[0-9a-f]{12}$/.test(id)) return null;
  const secret = decodeLinkSecret(normalized.slice(12));
  return secret ? { id, secret } : null;
}

/** True when what was typed is an older app's code: the 12-character link id alone. */
export function isOldLinkCode(text: string): boolean {
  const normalized = normalizeLinkCode(text);
  return normalized !== null && /^[0-9A-F]{12}$/.test(normalized);
}

/** The full code as the new device shows it, in groups of four: `a1b2 c3d4 e5f6 04HM ASW9`. */
export function showLinkCode(id: string, secret: Uint8Array): string {
  const text = `${id}${encodeLinkSecret(secret)}`;
  return (text.match(/.{1,4}/g) ?? []).join(" ");
}

const sha256 = async (bytes: Uint8Array) =>
  new Uint8Array(
    await crypto.subtle.digest("SHA-256", bytes as Uint8Array<ArrayBuffer>),
  );
const hexOf = (bytes: Uint8Array) =>
  [...bytes].map((byte) => byte.toString(16).padStart(2, "0")).join("");

/**
 * The v2 check number. It covers the link key and the secret, so a typo in
 * the secret shows as numbers that do not match, before anything is sealed.
 */
export async function linkCheckV2(
  linkPublicKey: string,
  secret: Uint8Array,
): Promise<string> {
  const digest = await sha256(
    concat(
      te.encode("hubs link check v2\0"),
      fromBase64(linkPublicKey),
      secret,
    ),
  );
  const value =
    new DataView(digest.buffer, digest.byteOffset).getUint32(0) % 1_000_000;
  return String(value).padStart(6, "0");
}

/** K: HKDF-SHA256 with the link public key as salt and the secret as input. */
export async function linkKeyV2(
  linkPublicKey: string,
  secret: Uint8Array,
): Promise<Uint8Array> {
  const ikm = await crypto.subtle.importKey(
    "raw",
    secret as Uint8Array<ArrayBuffer>,
    "HKDF",
    false,
    ["deriveBits"],
  );
  return new Uint8Array(
    await crypto.subtle.deriveBits(
      {
        name: "HKDF",
        hash: "SHA-256",
        salt: fromBase64(linkPublicKey) as Uint8Array<ArrayBuffer>,
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
export function linkInnerAad(
  kind: "bundle" | "history",
  index: number,
  count: number,
  userId: string,
  linkPublicKey: string,
): Uint8Array {
  return concat(
    te.encode(`hubs link v2\n${kind}\n${index}\n${count}\n${userId}\n`),
    fromBase64(linkPublicKey),
  );
}

const aesKey = (key: Uint8Array, use: "encrypt" | "decrypt") =>
  crypto.subtle.importKey(
    "raw",
    key as Uint8Array<ArrayBuffer>,
    "AES-GCM",
    false,
    [use],
  );

/** Inner layer: nonce (12 bytes) || AES-256-GCM ciphertext with its 16-byte tag. */
export async function sealLinkInner(
  key: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
  nonce: Uint8Array = crypto.getRandomValues(new Uint8Array(12)),
): Promise<Uint8Array> {
  const ct = new Uint8Array(
    await crypto.subtle.encrypt(
      {
        name: "AES-GCM",
        iv: nonce as Uint8Array<ArrayBuffer>,
        additionalData: aad as Uint8Array<ArrayBuffer>,
        tagLength: 128,
      },
      await aesKey(key, "encrypt"),
      plaintext as Uint8Array<ArrayBuffer>,
    ),
  );
  return concat(nonce, ct);
}
/** Opens the inner layer; throws on any failure. */
export async function openLinkInner(
  key: Uint8Array,
  sealed: Uint8Array,
  aad: Uint8Array,
): Promise<Uint8Array> {
  if (sealed.length < 12 + 16) throw new Error("This link part is too short.");
  return new Uint8Array(
    await crypto.subtle.decrypt(
      {
        name: "AES-GCM",
        iv: sealed.slice(0, 12),
        additionalData: aad as Uint8Array<ArrayBuffer>,
        tagLength: 128,
      },
      await aesKey(key, "decrypt"),
      sealed.slice(12),
    ),
  );
}

/** Outer layer: HPKE base mode to the link key with the v2 info, as the wire value. */
export async function sealLinkOuter(
  linkPublicKey: string,
  inner: Uint8Array,
): Promise<string> {
  const cs = await ciphersuite();
  const sealed = await cs.hpke.seal(
    await cs.hpke.importPublicKey(fromBase64(linkPublicKey)),
    inner,
    LINK_V2_INFO,
  );
  // Keys in this order: v, enc, ct.
  return JSON.stringify({
    v: 2,
    enc: toBase64(sealed.enc),
    ct: toBase64(sealed.ct),
  });
}

/**
 * Reads a link wire value: "v2" with its parts when it is a v2 seal, or
 * "other" when it does not parse or its v is not the number 2 (an older
 * app's seal, which a v2 device never opens).
 */
export function readLinkWire(
  wire: string,
): { kind: "v2"; enc: string; ct: string } | { kind: "other" } {
  let value: unknown;
  try {
    value = JSON.parse(wire);
  } catch {
    return { kind: "other" };
  }
  if (!value || typeof value !== "object" || Array.isArray(value))
    return { kind: "other" };
  const fields = value as Record<string, unknown>;
  // "The number 2" as written, never 2.0 or 2e0 (spec clarification 5; LW-9).
  if (fields.v !== 2 || !wire.startsWith('{"v":2,')) return { kind: "other" };
  return {
    kind: "v2",
    enc: typeof fields.enc === "string" ? fields.enc : "",
    ct: typeof fields.ct === "string" ? fields.ct : "",
  };
}

/** Opens the outer layer of a v2 wire value; throws on any failure. */
export async function openLinkOuter(
  linkPrivateKey: string,
  wire: string,
): Promise<Uint8Array> {
  const read = readLinkWire(wire);
  if (read.kind !== "v2") throw new Error("This is not a link v2 seal.");
  const keys = Object.keys(JSON.parse(wire));
  if (
    keys.length !== 3 ||
    !isStrictBase64(read.enc) ||
    !isStrictBase64(read.ct)
  )
    throw new Error("This link seal is not valid.");
  const cs = await ciphersuite();
  return new Uint8Array(
    await cs.hpke.open(
      await cs.hpke.importPrivateKey(fromBase64(linkPrivateKey)),
      fromBase64(read.enc),
      fromBase64(read.ct),
      LINK_V2_INFO,
    ),
  );
}

/** Both layers: the inner AES-256-GCM under K, then the outer HPKE seal. */
export async function sealLinkV2(
  linkPublicKey: string,
  key: Uint8Array,
  plaintext: Uint8Array,
  aad: Uint8Array,
): Promise<string> {
  return sealLinkOuter(linkPublicKey, await sealLinkInner(key, plaintext, aad));
}
/** Opens both layers; throws on any failure. */
export async function openLinkV2(
  linkPrivateKey: string,
  key: Uint8Array,
  wire: string,
  aad: Uint8Array,
): Promise<Uint8Array> {
  return openLinkInner(key, await openLinkOuter(linkPrivateKey, wire), aad);
}

/** A history part's plaintext: 4-byte big-endian length, the JSON, then zeros. */
export function padHistoryPart(json: string): Uint8Array {
  const body = te.encode(json);
  if (body.length > PRIVATE_DM_HISTORY_JSON_MAX)
    throw new Error("This history part is too large.");
  const out = new Uint8Array(PRIVATE_DM_HISTORY_PART_BYTES);
  new DataView(out.buffer).setUint32(0, body.length);
  out.set(body, 4);
  return out;
}
/** The JSON of a padded part, or null if its size, length, padding or UTF-8 is wrong. */
export function unpadHistoryPart(part: Uint8Array): string | null {
  if (part.length !== PRIVATE_DM_HISTORY_PART_BYTES) return null;
  const length = new DataView(part.buffer, part.byteOffset).getUint32(0);
  if (length > PRIVATE_DM_HISTORY_JSON_MAX) return null;
  for (let i = 4 + length; i < part.length; i++) if (part[i] !== 0) return null;
  const body = part.subarray(4, 4 + length);
  // A byte order mark is refused.
  if (body[0] === 0xef && body[1] === 0xbb && body[2] === 0xbf) return null;
  try {
    return new TextDecoder("utf-8", { fatal: true, ignoreBOM: true }).decode(
      body,
    );
  } catch {
    return null;
  }
}
/** The bundle's history digest: hex SHA-256 over every padded part, in order. */
export async function historyDigest(parts: Uint8Array[]): Promise<string> {
  return hexOf(await sha256(concat(...parts)));
}

/** Strict UTF-8 text with no byte order mark, or null. */
export function strictText(bytes: Uint8Array): string | null {
  if (bytes[0] === 0xef && bytes[1] === 0xbb && bytes[2] === 0xbf) return null;
  try {
    return strictUtf8.decode(bytes);
  } catch {
    return null;
  }
}

/** The passkey backup: a key from the passkey's PRF output seals the identity. */
export type SealedBackup = { salt: string; nonce: string; ciphertext: string };
const BACKUP_INFO = te.encode("hubs private dms backup v1");
async function backupKey(prfOutput: Uint8Array, salt: Uint8Array) {
  const cs = await ciphersuite();
  return cs.kdf.expand(
    await cs.kdf.extract(salt, prfOutput),
    BACKUP_INFO,
    cs.hpke.keyLength,
  );
}
export async function sealBackup(
  prfOutput: Uint8Array,
  bundle: IdentityBundle,
): Promise<SealedBackup> {
  const cs = await ciphersuite();
  const salt = cs.rng.randomBytes(32);
  const nonce = cs.rng.randomBytes(cs.hpke.nonceLength);
  const ciphertext = await cs.hpke.encryptAead(
    await backupKey(prfOutput, salt),
    nonce,
    concat(BACKUP_INFO, te.encode(bundle.userId)),
    te.encode(JSON.stringify(bundle)),
  );
  return {
    salt: toBase64(salt),
    nonce: toBase64(nonce),
    ciphertext: toBase64(ciphertext),
  };
}
export async function openBackup(
  prfOutput: Uint8Array,
  userId: string,
  sealed: SealedBackup,
): Promise<IdentityBundle> {
  const cs = await ciphersuite();
  const opened = await cs.hpke.decryptAead(
    await backupKey(prfOutput, fromBase64(sealed.salt)),
    fromBase64(sealed.nonce),
    concat(BACKUP_INFO, te.encode(userId)),
    fromBase64(sealed.ciphertext),
  );
  const bundle = JSON.parse(td.decode(opened)) as IdentityBundle;
  if (bundle.userId !== userId)
    throw new Error("This backup belongs to a different account.");
  return bundle;
}
