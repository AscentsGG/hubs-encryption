/**
 * What one device does in private conversations. It keeps its keys, group
 * states and decrypted messages in a local store, talks to the server only
 * in ciphertext, adds and removes devices as people link or retire them, and
 * pins each contact's identity key so a change shows as a notice.
 *
 * The store is passed in: IndexedDB in a browser (idb-store.ts), memory in
 * tests.
 */
import type { ClientState } from "ts-mls";
import {
  PRIVATE_DM_CLOCK_SKEW_MS,
  PRIVATE_DM_DEFAULT_TIMER,
  PRIVATE_DM_HISTORY_JSON_MAX,
  PRIVATE_DM_HISTORY_PART_COUNTS,
  PRIVATE_DM_HISTORY_SEALED_CHARS,
  PRIVATE_DM_LINK_SECONDS,
  PRIVATE_DM_TIMERS,
  isPrivateDmTimer,
  isWellFormedText,
  paddedHistoryCount,
  privateDmPayloadProblem,
  PRIVATE_DM_KEY_PACKAGE_LIFETIME_SECONDS,
  PRIVATE_DM_KEY_PACKAGE_REFRESH_SECONDS,
  PRIVATE_DM_KEY_PACKAGE_TARGET,
  PRIVATE_DM_KEY_UPDATE_SECONDS,
  PRIVATE_DM_MAX_BODY,
  PRIVATE_DM_MAX_QUEUE_SECONDS,
  signedRemovalsNote,
  type PrivateDmConversation,
  type PrivateDmDevice,
  type PrivateDmEnvelope,
  type PrivateDmPayload,
  type PrivateDmRemovalStatement,
  type PrivateDmReportedMessage,
  type PrivateDmRevocation,
  type PrivateDmState,
  timerLabel,
} from "./protocol.js";
import {
  type DeviceKeyPackage,
  type DeviceKeys,
  type GroupMember,
  type IdentityBundle,
  type IdentityKeys,
  type SealedBackup,
  changeDevices,
  createDevice,
  createIdentity,
  createKeyPackages,
  createLinkKeys,
  createLinkSecret,
  encryptMessage,
  fromBase64,
  groupConversationId,
  groupMembers,
  historyDigest,
  isOldLinkCode,
  isStrictBase64,
  joinFromWelcome,
  keyPackageCredential,
  keyPackageProblem,
  messageHeader,
  linkCheckV2,
  linkCode,
  linkInnerAad,
  linkKeyV2,
  loadGroup,
  openBackup,
  openLinkV2,
  padHistoryPart,
  parseLinkCode,
  readLinkWire,
  receive,
  safetyCode,
  saveGroup,
  sealBackup,
  sealLinkV2,
  showLinkCode,
  signDeviceRemoval,
  signRemovalStatement,
  signSelfRemoval,
  startGroup,
  strictText,
  toBase64,
  unpadHistoryPart,
  verifyDeviceCertificate,
  verifyRemoval,
  verifyRemovalStatement,
} from "./engine.js";
import { sweepDisappeared } from "./disappearing.js";
import {
  type CallBinding,
  type CallBindingCheck,
  type CallConnection,
  type CallPeerDecision,
  type CallPeerInput,
  type CallView,
  callPeerDecisions,
  callSignaturesSupported,
  checkCallBinding,
  signCallBinding,
  signCallView,
} from "./calls.js";

/** A small key-value store on this device. */
export interface DeviceStore {
  get<T>(key: string): Promise<T | undefined>;
  set(key: string, value: unknown): Promise<void>;
  delete(key: string): Promise<void>;
  keys(prefix: string): Promise<string[]>;
  /**
   * Read one value and write its replacement as one step that no other
   * write (from this tab or another) can land in between. `change` runs
   * synchronously; returning undefined writes nothing, and throwing writes
   * nothing and rejects with that error.
   */
  update<T>(
    key: string,
    change: (current: T | undefined) => T | undefined,
  ): Promise<void>;
}
/** A DeviceStore in memory. Values are copied in and out, as IndexedDB does. */
export function memoryStore(): DeviceStore & { dump(): Map<string, unknown> } {
  const map = new Map<string, unknown>();
  return {
    async get<T>(key: string) {
      return structuredClone(map.get(key)) as T | undefined;
    },
    async set(key, value) {
      map.set(key, structuredClone(value));
    },
    async update<T>(
      key: string,
      change: (current: T | undefined) => T | undefined,
    ) {
      const next = change(structuredClone(map.get(key)) as T | undefined);
      if (next !== undefined) map.set(key, structuredClone(next));
    },
    async delete(key) {
      map.delete(key);
    },
    async keys(prefix) {
      return [...map.keys()].filter((key) => key.startsWith(prefix));
    },
    dump: () => map,
  };
}

/** Sends one request to the server's API and returns the parsed answer. Throws an error with `status` and `code` on failure. */
export type PrivateDmApi = <T = any>(
  method: "GET" | "POST" | "PUT" | "PATCH",
  path: string,
  body?: unknown,
) => Promise<T>;
export type ApiError = Error & { status?: number; code?: string };

/** One line in a conversation, as this device keeps it. */
export type StoredMessage = {
  id: string;
  kind: "text" | "timer" | "notice";
  body: string;
  sentAt: number;
  expiresAt: number | null;
  senderUserId: string;
  /**
   * On a notice that messages did not arrive: how many. The other person's
   * device numbered them, but they never reached this one.
   */
  missing?: number;
  /** On a timer line: the timer it announced, in seconds. */
  seconds?: number;
  /** Brought from another device when this one was linked (history transfer). */
  imported?: true;
  /** What reporting needs (text messages from others only). */
  proof?: {
    envelopeId: string;
    payload: PrivateDmPayload;
    commitment: string;
    frankingTag: string;
    /** The server's stamp key id, when it sent one. */
    frankingKeyId?: string;
    stampedAt: string;
  };
};
type LocalConversation = {
  group: string | null;
  cursor: number;
  /** The group was made here and no commit has been accepted yet. */
  createdHere: boolean;
  /**
   * The other person, pinned the first time this device sees them. A
   * private conversation is one-to-one, so no other account may join.
   */
  peer?: string;
  /**
   * The disappearing timer as last announced inside the encryption. The
   * server's copy is only a hint: it cannot turn the timer off on its own.
   */
  timerSeconds?: number;
  /** The announcement `timerSeconds` came from (its sentAt and payload
   * id), so one delivered late never replaces a newer one. */
  timerSentAt?: number;
  timerId?: string;
  /** When this device last refreshed its own keys here with a commit. */
  updatedAt?: number;
  /** The MLS epoch of `group` (or of the last group, once it is cleared). */
  epoch?: number;
  /**
   * Counts every write of `group`: each message sent or opened and each
   * commit stores the next one. The write guard (`groupWriteProblem`) uses
   * it to refuse a writer that started from an older state.
   */
  generation?: number;
  /**
   * Fingerprints of envelopes already handled here (newest last), so an
   * envelope the server sends again is skipped quietly instead of showing
   * "could not be opened".
   */
  seen?: string[];
  /**
   * The first epoch this device has followed from its start, so it counts
   * that epoch's messages from generation 0. Unset until this device joins
   * or accepts a commit.
   */
  trackedFrom?: number;
  /** Each other sender's message generations, by "epoch:leaf". */
  generations?: Record<string, GenerationTrack>;
  /** The identity key whose signed-removals statement this conversation has seen. */
  removalsNoted?: string;
  /** A welcome waiting for the person to review a safety code change. */
  heldWelcome?: HeldWelcome;
};

/**
 * A welcome under an identity key this device had not pinned. It is not
 * opened for use until the person reviews the change, and a welcome under
 * `previousKey`, the key this device trusted before, replaces it.
 */
type HeldWelcome = {
  envelopeId: string;
  /** Where it came, so what arrives during the review is read after it joins. */
  seq?: number;
  keyPackageId: string;
  ciphertext: string;
  userId: string;
  previousKey: string;
};

/**
 * One sender's messages in one epoch, as this device saw them: the next
 * generation it expects, gaps not yet called missing (with when they were
 * noticed and where the line would go), and gaps it already told the
 * person about, with that notice's id.
 */
export type GenerationTrack = {
  userId: string;
  next: number;
  gaps: { generation: number; at: number; before: number }[];
  told: { generation: number; notice: string }[];
};
/**
 * How long a gap in a sender's generations may stay open before the
 * person sees that a message did not arrive. Messages from one device
 * reach the server in order, so a gap that lasts this long is not
 * reordering on the way.
 */
export const PRIVATE_DM_MISSING_GRACE_MS = 2 * 60 * 1000;
/** MLS opens a message at most this many generations ahead (the library's forward limit). */
const MAX_GAP = 200;

/**
 * Note that a sender's message with `generation` arrived at `now`, shown
 * at `shownAt`. A jump ahead opens gaps for the generations skipped; an
 * earlier generation closes its gap, quietly when it was not told yet,
 * or settling the notice that told it (returned as `settled`). The native
 * clients apply the same rule.
 */
export function trackGeneration(
  track: GenerationTrack,
  generation: number,
  now: number,
  shownAt: number,
): { track: GenerationTrack; settled: string | null } {
  const next = {
    ...track,
    gaps: [...track.gaps],
    told: [...track.told],
  };
  if (generation >= next.next) {
    for (
      let skipped = Math.max(next.next, generation - MAX_GAP);
      skipped < generation;
      skipped++
    )
      next.gaps.push({ generation: skipped, at: now, before: shownAt - 1 });
    next.next = generation + 1;
    return { track: next, settled: null };
  }
  const gap = next.gaps.findIndex((g) => g.generation === generation);
  if (gap >= 0) {
    next.gaps.splice(gap, 1);
    return { track: next, settled: null };
  }
  const told = next.told.findIndex((g) => g.generation === generation);
  if (told >= 0) {
    const [entry] = next.told.splice(told, 1);
    return { track: next, settled: entry.notice };
  }
  return { track: next, settled: null };
}

/**
 * The gaps open for at least PRIVATE_DM_MISSING_GRACE_MS at `now`: they
 * become one notice, `notice`, and move to `told`.
 */
export function dueGenerations(
  track: GenerationTrack,
  now: number,
  notice: string,
): { track: GenerationTrack; due: GenerationTrack["gaps"] } {
  const due = track.gaps.filter(
    (g) => now - g.at >= PRIVATE_DM_MISSING_GRACE_MS,
  );
  if (!due.length) return { track, due };
  return {
    track: {
      ...track,
      gaps: track.gaps.filter((g) => !due.includes(g)),
      told: [
        ...track.told,
        ...due.map((g) => ({ generation: g.generation, notice })),
      ],
    },
    due,
  };
}
const missingBody = (count: number) =>
  count === 1 ? "A message didn't arrive." : `${count} messages didn't arrive.`;
/** How many handled envelopes each conversation remembers. */
const SEEN_LIMIT = 1000;
/** An envelope's fingerprint: SHA-256 of its ciphertext, first 16 bytes. */
async function envelopeFingerprint(ciphertext: string) {
  const digest = new Uint8Array(
    await crypto.subtle.digest(
      "SHA-256",
      fromBase64(ciphertext) as Uint8Array<ArrayBuffer>,
    ),
  );
  return toBase64(digest.subarray(0, 16));
}

/**
 * The membership rule every device applies to a group before it accepts
 * it (a welcome, a commit from someone else, or its own commit), or null
 * when the group is acceptable. A private conversation is one-to-one:
 *
 * - every device of this account carries this device's identity key;
 * - there is at most one other account, and it is the pinned peer once
 *   one is pinned;
 * - the other account's devices all carry one identity key. A person has
 *   one identity at a time, and starting over revokes the old devices, so
 *   two keys at once means a device the safety code would not show.
 *
 * The native clients apply the same rule.
 */
export function membershipProblem(
  members: Pick<GroupMember, "userId" | "identityPublicKey">[],
  self: { userId: string; identityPublicKey: string; peer: string | null },
): string | null {
  const others = new Set<string>();
  const otherKeys = new Set<string>();
  for (const member of members) {
    if (member.userId === self.userId) {
      if (member.identityPublicKey !== self.identityPublicKey)
        return "A device of this account carries a different identity key.";
    } else {
      others.add(member.userId);
      otherKeys.add(member.identityPublicKey);
    }
  }
  if (others.size > 1) return "A third account would join.";
  const [other] = others;
  if (other && self.peer && other !== self.peer)
    return "Someone other than the pinned person would join.";
  if (otherKeys.size > 1)
    return "The other person's devices carry two identity keys.";
  return null;
}

/**
 * Whether a device the server no longer lists may be removed from a
 * conversation. The server alone must not be able to make devices drop a
 * person's device, so a removal counts when:
 *
 * - its proof verifies (the identity key signed `deviceRemovalBody`, or
 *   the device signed `selfRemoveBody`); a proof that does not verify never
 *   counts;
 * - or the person started over: a device under another identity key, with a
 *   valid certificate, joins in the same commit, which every device shows
 *   as a safety code change. A device only listed under another key is not
 *   enough, since the server writes that list;
 * - or it carries no proof and this device has not seen the person's
 *   statement that their removals are signed (`signedRemovalsBody`). Some
 *   app builds cannot sign removals yet; once a person's identity key has
 *   made that statement, unsigned removals of their devices are ignored.
 *
 * The native clients apply the same rule.
 */
export function removalCounts(input: {
  proof: "valid" | "invalid" | "none";
  startedOver: boolean;
  signedRemovals: boolean;
}): boolean {
  if (input.proof === "valid") return true;
  if (input.proof === "invalid") return false;
  return input.startedOver || !input.signedRemovals;
}

/**
 * Why a passkey backup with `counter` may not be restored on a device that
 * has seen backups up to `seen`, or null. A backup made before counters
 * counts as 0. A server that serves an older backup (an older identity or
 * fewer pinned contacts) is refused by every device that saw a newer one.
 * The native clients apply the same rule.
 */
export function backupRollbackProblem(
  counter: number | undefined,
  seen: number,
): string | null {
  const value = counter ?? 0;
  if (!Number.isSafeInteger(value) || value < 0)
    return "This backup's counter is not valid.";
  return value < seen
    ? "This backup is older than one this device has already seen, so it was not used."
    : null;
}

/** A write that would move a conversation's keys backwards; nothing was stored. */
export class StaleGroupError extends Error {
  readonly code = "STALE_GROUP";
}

/**
 * The write guard for a conversation's group state (compare and set), or
 * null when `next` may replace `stored`:
 *
 * - an older epoch never replaces a newer one;
 * - a newer epoch replaces an older one (every key in it is new, so no
 *   message key of the older epoch can come back);
 * - within one epoch, only a writer that started from the stored
 *   generation may write. A writer that read the state, waited on the
 *   network or on crypto, and finds that someone else stored a newer
 *   generation meanwhile is refused, so the ratchet never goes backwards
 *   and a message key is never used twice.
 *
 * `next.epoch` is null when the group is being cleared (the device left,
 * or a group made here gave way); the stored epoch stays as a floor.
 * The native clients apply the same rule.
 */
export function groupWriteProblem(
  stored: Pick<LocalConversation, "epoch" | "generation"> | undefined,
  next: { epoch: number | null; baseGeneration: number },
): string | null {
  const storedEpoch = stored?.epoch;
  if (next.epoch !== null && storedEpoch !== undefined) {
    if (next.epoch < storedEpoch)
      return `This conversation is already at epoch ${storedEpoch}; epoch ${next.epoch} is older.`;
    if (next.epoch > storedEpoch) return null;
  }
  const storedGeneration = stored?.generation ?? 0;
  if (next.baseGeneration !== storedGeneration)
    return `This conversation's keys moved on (generation ${storedGeneration}) since this change started from generation ${next.baseGeneration}.`;
  return null;
}

/** Web Locks (navigator.locks), or the part of it the client uses. */
export type ConversationLocks = {
  request<T>(name: string, callback: () => Promise<T>): Promise<T>;
};
const browserLocks = (): ConversationLocks | null =>
  (globalThis.navigator as { locks?: ConversationLocks } | undefined)?.locks ??
  null;

/**
 * An app's own rule for outgoing text, run on the trimmed text before
 * anything is encrypted: a reason to refuse the message, or null to send it.
 */
export type SendCheck = (text: string) => string | null;

export type PrivateDmClientOptions = {
  /** Web Locks by default; null runs with this tab's queue and the write guard alone. */
  locks?: ConversationLocks | null;
  sendCheck?: SendCheck;
};

/**
 * A contact's safety code changed; see PrivateDmClient.keyChanges. `held`:
 * this device has not joined the conversation yet, and joins after the review.
 */
export type KeyChange = { at: number; wasVerified: boolean; held?: boolean };

/** Shown when this device refuses a membership change it cannot accept. */
export const REFUSED_MEMBER_NOTICE =
  "A device that does not belong here tried to join this conversation, so this device refused it. Compare safety codes before you keep talking.";
/** Shown when a commit removes this device from a conversation. */
export const DEVICE_REMOVED_NOTICE =
  "This device was removed from this conversation. It rejoins once another device adds it back.";
/** Shown when a change leaves no device of the other person in a conversation. */
export const NO_PEER_DEVICE_NOTICE =
  "The other person has no devices in this conversation right now. Sending is paused until one is back.";

// Link v2 and history transfer (the link v2 spec, docs/link-v2.md in the public repository).

/** On the old device: the new device runs an older app (its code has no secret). */
export const LINK_UPDATE_NEW_DEVICE =
  "The new device needs the latest version of Hubs. Update it, then start linking again.";
/** On the old device: what was typed is not a full code. */
export const LINK_CODE_WRONG =
  "That code isn't complete. Type all 20 letters and numbers the new device shows.";
/** On the old device: /seal answered 409, another seal was there first. */
export const LINK_ANSWERED_FIRST =
  "Another device answered this link first. Don't use the new device. Start linking again.";
/** On the new device: the hand-off is not a v2 seal. */
export const LINK_UPDATE_OTHER_DEVICE =
  "Update Hubs on your other device, then start linking again.";
/** On the new device: the hand-off came after the link's 15 minutes. */
export const LINK_TOO_LONG = "That link took too long. Start again.";
/** On the new device: the hand-off did not open or was not this account's. */
export const LINK_NOT_YOURS =
  "This link didn't come from your other device, so nothing was set up. Start again from your other device.";
/** On the new device: the device is set up, but the history did not come. */
export const HISTORY_NOT_BROUGHT =
  "Your messages couldn't be brought over. New messages will still arrive here.";
/** The quiet line above messages brought from the other device. */
export const HISTORY_LINE = "Earlier messages, from your other device.";

/** A link ended without setting this device up; `message` is the sentence to show. */
export class LinkFailedError extends Error {
  readonly code = "LINK_FAILED";
}
/** Another device answered this link first; the new device must not be used. */
export class LinkAnsweredError extends Error {
  readonly code = "LINK_ANSWERED";
}
/** What the old device typed is not a code it may use. */
export class LinkCodeError extends Error {
  readonly code = "LINK_CODE";
}

/** The history a link bundle names. The part count always comes from here. */
export type LinkHistory = {
  parts: 1 | 4 | 16 | 64;
  digest: string;
  truncated: boolean;
};
/** The link v2 bundle: the identity hand-off and the history it brings. */
export type LinkBundle = Omit<IdentityBundle, "v" | "counter"> & {
  v: 2;
  history: LinkHistory | null;
};
const LINK_KEY = "linkV2";
/** The pre-release client's key: cleared whenever a v2 link starts or ends. */
const LEGACY_LINK_KEY = "link";
/**
 * What the new device keeps of a link, in its store under LINK_KEY. Not
 * "link": a tab still running the pre-release client reads a record under
 * "link" as its own and would open a v1 seal with this link's private key
 * (link v2 audit LW-1), so v2 never writes there and clears any it finds.
 */
type LinkRecord = {
  id: string;
  state: "waiting" | "spent" | "registered" | "imported" | "failed";
  /** When beginLink ran, by this device's clock. */
  startedAt: number;
  publicKey?: string;
  privateKey?: string;
  /** The link secret, base64. It never leaves this device. */
  secret?: string;
  check?: string;
  spentAt?: number;
  /** Which call spent it, so only that call opens the seal. */
  spentBy?: string;
  bundle?: LinkBundle;
  outcome?: LinkOutcome;
  failure?: string;
};
/** What a finished link brought: "failed" shows HISTORY_NOT_BROUGHT. */
export type LinkOutcome = {
  history: "none" | "imported" | "failed";
  truncated?: boolean;
};
/** One message in the history, as it travels. */
type HistoryMessage = {
  id: string;
  kind: "text" | "timer";
  body: string;
  seconds?: number;
  sentAt: number;
  expiresAt: number | null;
  senderUserId: string;
  proof?: StoredMessage["proof"];
};
type HistoryConversation = {
  conversationId: string;
  peer: string;
  timer: { seconds: number; sentAt: number; id: string } | null;
  messages: HistoryMessage[];
};
/** A spent link with no bundle yet is being opened elsewhere for at most this long. */
const LINK_OPEN_GRACE_MS = 60_000;
const te = new TextEncoder();
const MESSAGE_ID = /^[A-Za-z0-9_-]{1,64}$/;
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const isRecord = (value: unknown): value is Record<string, unknown> =>
  !!value && typeof value === "object" && !Array.isArray(value);
const isSafeTime = (value: unknown): value is number =>
  typeof value === "number" && Number.isSafeInteger(value);
const isAccountId = (value: unknown): value is string =>
  typeof value === "string" &&
  value.length > 0 &&
  value.length <= 128 &&
  isWellFormedText(value);
const isStringMap = (value: unknown) =>
  isRecord(value) && Object.values(value).every((v) => typeof v === "string");
/** The words a timer line shows, as this device writes them. */
const timerWords = (seconds: number) =>
  seconds
    ? `Messages now disappear after ${timerLabel(seconds).toLowerCase()}.`
    : "Disappearing messages are off.";
/** A timer line stored before lines kept their seconds: read back from its words. */
const timerFromWords = (words: string) =>
  PRIVATE_DM_TIMERS.find((timer) => timerWords(timer.seconds) === words)
    ?.seconds;

/**
 * A link bundle read strictly, or null: v is the number 2, the account is
 * this one, the identity is two strict base64 keys, the pins are maps of
 * strings and the history is null or names 1, 4, 16 or 64 parts with a
 * hex SHA-256 digest.
 */
function linkBundleOf(value: unknown, userId: string): LinkBundle | null {
  if (!isRecord(value) || value.v !== 2 || value.userId !== userId) return null;
  const identity = value.identity;
  if (
    !isRecord(identity) ||
    typeof identity.publicKey !== "string" ||
    typeof identity.signKey !== "string" ||
    !isStrictBase64(identity.publicKey) ||
    !isStrictBase64(identity.signKey)
  )
    return null;
  if (!isStringMap(value.trusted)) return null;
  for (const field of ["verified", "signedRemovals"])
    if (value[field] !== undefined && !isStringMap(value[field])) return null;
  if (
    value.keyChanges !== undefined &&
    !(
      isRecord(value.keyChanges) &&
      Object.values(value.keyChanges).every(
        (change) =>
          isRecord(change) &&
          isSafeTime(change.at) &&
          typeof change.wasVerified === "boolean",
      )
    )
  )
    return null;
  if (
    value.backupCounter !== undefined &&
    !(isSafeTime(value.backupCounter) && value.backupCounter >= 0)
  )
    return null;
  const history = value.history;
  if (
    history !== null &&
    !(
      isRecord(history) &&
      (PRIVATE_DM_HISTORY_PART_COUNTS as readonly unknown[]).includes(
        history.parts,
      ) &&
      typeof history.digest === "string" &&
      /^[0-9a-f]{64}$/.test(history.digest) &&
      typeof history.truncated === "boolean"
    )
  )
    return null;
  return value as unknown as LinkBundle;
}

/**
 * One conversation from a history part with every field checked, or null
 * when the conversation itself is not valid (it is then skipped). A message
 * that fails a rule, or has expired by `now`, is dropped alone. A proof is
 * kept only when its payload passes privateDmPayloadProblem and names the
 * same id, text and sender as the message.
 */
function historyConversationOf(
  value: unknown,
  userId: string,
  now: number,
): HistoryConversation | null {
  if (
    !isRecord(value) ||
    typeof value.conversationId !== "string" ||
    !UUID.test(value.conversationId) ||
    !isAccountId(value.peer) ||
    value.peer === userId ||
    !Array.isArray(value.messages)
  )
    return null;
  const peer = value.peer;
  let timer: HistoryConversation["timer"] = null;
  const carried = value.timer;
  if (
    isRecord(carried) &&
    typeof carried.seconds === "number" &&
    isPrivateDmTimer(carried.seconds) &&
    isSafeTime(carried.sentAt) &&
    carried.sentAt >= 0 &&
    typeof carried.id === "string" &&
    MESSAGE_ID.test(carried.id)
  )
    timer = {
      seconds: carried.seconds,
      sentAt: carried.sentAt,
      id: carried.id,
    };
  const messages: HistoryMessage[] = [];
  const seen = new Set<string>();
  for (const m of value.messages) {
    if (!isRecord(m)) continue;
    if (typeof m.id !== "string" || !MESSAGE_ID.test(m.id) || seen.has(m.id))
      continue;
    if (
      !isSafeTime(m.sentAt) ||
      m.sentAt < 0 ||
      m.sentAt > now + PRIVATE_DM_CLOCK_SKEW_MS
    )
      continue;
    if (m.expiresAt !== null && !isSafeTime(m.expiresAt)) continue;
    if (m.expiresAt !== null && m.expiresAt <= now) continue;
    if (m.senderUserId !== userId && m.senderUserId !== peer) continue;
    if (typeof m.body !== "string") continue;
    const base = {
      id: m.id,
      sentAt: m.sentAt,
      expiresAt: m.expiresAt as number | null,
      senderUserId: m.senderUserId as string,
    };
    if (m.kind === "timer") {
      // A timer line never expires on its own (spec clarification 6; LW-10).
      if (
        m.expiresAt !== null ||
        m.body !== "" ||
        typeof m.seconds !== "number" ||
        !isPrivateDmTimer(m.seconds)
      )
        continue;
      messages.push({ ...base, kind: "timer", body: "", seconds: m.seconds });
    } else if (m.kind === "text") {
      if (m.body.length > PRIVATE_DM_MAX_BODY || !isWellFormedText(m.body))
        continue;
      const proof = m.proof;
      const keep =
        isRecord(proof) &&
        privateDmPayloadProblem(proof.payload) === null &&
        isRecord(proof.payload) &&
        proof.payload.id === m.id &&
        proof.payload.body === m.body &&
        proof.payload.userId === m.senderUserId &&
        typeof proof.envelopeId === "string" &&
        typeof proof.commitment === "string" &&
        typeof proof.frankingTag === "string" &&
        typeof proof.stampedAt === "string" &&
        (proof.frankingKeyId === undefined ||
          typeof proof.frankingKeyId === "string");
      messages.push({
        ...base,
        kind: "text",
        body: m.body,
        ...(keep
          ? {
              proof: {
                envelopeId: proof.envelopeId as string,
                payload: proof.payload as unknown as PrivateDmPayload,
                commitment: proof.commitment as string,
                frankingTag: proof.frankingTag as string,
                ...(proof.frankingKeyId !== undefined
                  ? { frankingKeyId: proof.frankingKeyId as string }
                  : {}),
                stampedAt: proof.stampedAt as string,
              },
            }
          : {}),
      });
    } else continue;
    seen.add(m.id);
  }
  return { conversationId: value.conversationId, peer, timer, messages };
}

const randomId = (bytes = 16) =>
  toBase64(crypto.getRandomValues(new Uint8Array(bytes)))
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
const conversationKey = (id: string) => `conversation:${id}`;
/** Whether a timer announcement is newer than the one a device follows:
 * by sentAt, then by payload id, so every device picks the same one. */
const newerTimer = (local: LocalConversation, sentAt: number, id: string) =>
  local.timerSentAt === undefined ||
  sentAt > local.timerSentAt ||
  (sentAt === local.timerSentAt && id > (local.timerId ?? ""));
const emptyLocal = (): LocalConversation => ({
  group: null,
  cursor: 0,
  createdHere: false,
});
const messagesKey = (id: string) => `messages:${id}`;

/** How often a syncing device looks for disappeared messages everywhere. */
const SWEEP_MS = 60_000;

export class PrivateDmClient {
  private readonly locks: ConversationLocks | null;
  private readonly sendCheck: SendCheck | null;
  /** The tail of each conversation's queue in this tab. */
  private readonly queues = new Map<string, Promise<unknown>>();
  private sweptAt = 0;
  /** The finishLink running in this client, if any. */
  private finishing: Promise<boolean> | null = null;
  /** On an old device: each approval's sealed history, kept for a retry. */
  private readonly approvals = new Map<
    string,
    {
      publicKey: string;
      sealed: string[];
      sent: Set<number>;
      /** Null when there was nothing to send (spec clarification 2). */
      history: LinkHistory | null;
    }
  >();

  constructor(
    private readonly api: PrivateDmApi,
    private readonly store: DeviceStore,
    readonly userId: string,
    private readonly now: () => number = Date.now,
    options: PrivateDmClientOptions = {},
  ) {
    this.locks = options.locks === undefined ? browserLocks() : options.locks;
    this.sendCheck = options.sendCheck ?? null;
  }

  /**
   * Run one state-changing call alone for its conversation: after this
   * tab's earlier calls, and with Web Locks after every other tab's and
   * window's too (they share this account's store). Every call that reads
   * the group state, waits, and writes it back runs through here, so a
   * slow sync can never land its older state over a newer send.
   * Without Web Locks the write guard still refuses a stale writer, and
   * the call starts again from the stored state.
   */
  private exclusive<T>(conversationId: string, work: () => Promise<T>) {
    const run = () =>
      this.locks
        ? this.locks.request(
            `hubs-private-dm:${this.userId}:${conversationId}`,
            work,
          )
        : work();
    const previous = this.queues.get(conversationId) ?? Promise.resolve();
    const result = previous.then(run, run);
    const tail = result.catch(() => undefined);
    this.queues.set(conversationId, tail);
    void tail.then(() => {
      if (this.queues.get(conversationId) === tail)
        this.queues.delete(conversationId);
    });
    return result;
  }

  // Setup
  async device() {
    return this.store.get<DeviceKeys>("device");
  }
  async identity() {
    return this.store.get<IdentityKeys>("identity");
  }
  /** Contacts' identity keys this device trusts (pinned the first time they are seen). */
  async trusted() {
    return (await this.store.get<Record<string, string>>("trusted")) ?? {};
  }
  async verified() {
    return (await this.store.get<Record<string, string>>("verified")) ?? {};
  }
  /**
   * Contacts whose safety code changed and who have not been reviewed
   * since. The conversation keeps an alert up until the person compares
   * codes again or dismisses it; when the contact had been verified,
   * sending waits for that review.
   */
  async keyChanges() {
    return (
      (await this.store.get<Record<string, KeyChange>>("keyChanges")) ?? {}
    );
  }
  async keyChangeWith(otherUserId: string): Promise<KeyChange | null> {
    return (await this.keyChanges())[otherUserId] ?? null;
  }
  /**
   * The person saw the alert and chose to keep talking without comparing.
   * With `shownAt`, only the change the screen showed is cleared: a newer
   * one that arrived while the alert was up stays. One atomic update, so a
   * change that a sync stores meanwhile is never overwritten.
   */
  async acknowledgeKeyChange(otherUserId: string, shownAt?: number) {
    let cleared = true;
    await this.store.update<Record<string, KeyChange>>(
      "keyChanges",
      (changes) => {
        const change = changes?.[otherUserId];
        if (!changes || !change) return undefined;
        if (shownAt !== undefined && change.at !== shownAt) {
          cleared = false;
          return undefined;
        }
        const { [otherUserId]: _, ...rest } = changes;
        return rest;
      },
    );
    return cleared;
  }

  /**
   * First device on this account: a new identity. With `resetIdentity`
   * ("Start over on this device" on a device with no identity yet), it is
   * starting over, and keeps each contact's pinned key, removals statement
   * and open alerts exactly like `startOver` (AE-3).
   */
  async setUp(options: { resetIdentity?: boolean } = {}) {
    if (options.resetIdentity) return this.startOver();
    const identity = await createIdentity();
    await this.register(identity, {});
  }

  /**
   * Make this store a new device: a new device id can never continue a group
   * or open a welcome of the device it replaces, so those go, and each
   * conversation waits for a device to add this one. Messages stay.
   */
  private async register(
    identity: IdentityKeys,
    carried: Partial<IdentityBundle>,
    resetIdentity = false,
  ) {
    const device = await createDevice(identity, this.userId, randomId());
    const oldPackages = await this.store.keys("keyPackage:");
    await this.api("POST", "/private-dms/devices", {
      id: device.deviceId,
      identityKey: identity.publicKey,
      deviceKey: device.publicKey,
      certificate: device.certificate,
      ...(resetIdentity ? { resetIdentity: true } : {}),
    });
    await this.store.set("identity", identity);
    await this.store.set("device", device);
    const trusted = {
      ...carried.trusted,
      [this.userId]: identity.publicKey,
    };
    // Only what still applies to the keys the new device pins.
    const samePin = (marks: Record<string, string> | undefined) =>
      Object.fromEntries(
        Object.entries(marks ?? {}).filter(([id, key]) => trusted[id] === key),
      );
    await this.store.set("trusted", trusted);
    await this.store.set("verified", samePin(carried.verified));
    await this.store.set("signedRemovals", samePin(carried.signedRemovals));
    await this.store.set(
      "keyChanges",
      Object.fromEntries(
        Object.entries(carried.keyChanges ?? {}).map(([id, change]) => [
          id,
          { at: change.at, wasVerified: change.wasVerified },
        ]),
      ),
    );
    for (const key of oldPackages) await this.store.delete(key);
    await this.leaveGroups();
    await this.refreshKeyPackages();
  }

  /** Drop every conversation's group state, keeping its messages. */
  private async leaveGroups() {
    for (const key of await this.store.keys("conversation:")) {
      const id = key.slice("conversation:".length);
      await this.exclusive(id, async () => {
        const local = await this.local(id);
        if (local.group || local.heldWelcome)
          await this.storeGroup(id, null, local.generation ?? 0, () => ({
            createdHere: false,
            heldWelcome: undefined,
          }));
      });
    }
  }

  /**
   * Keep a fresh supply of one-time key packages on the server, plus one
   * last-resort package for when they run out. Each is valid for 90 days;
   * ones 30 days old are replaced, the rest topped up to the target.
   * Private halves are kept until a welcome could no longer name them
   * (expiry plus the server's queue time).
   */
  async refreshKeyPackages() {
    const device = await this.device();
    if (!device) return;
    const now = this.now();
    const path = `/private-dms/devices/${device.deviceId}/key-packages`;
    const { packages: held } = await this.api<{
      packages: { id: string; createdAt: string; lastResort?: boolean }[];
    }>("GET", path);
    const due = (p: { createdAt: string }) =>
      now - Date.parse(p.createdAt) >=
      PRIVATE_DM_KEY_PACKAGE_REFRESH_SECONDS * 1000;
    // One with no private half here is not this device's: it can never
    // open a welcome, so it is replaced like one that came due.
    const foreign = new Set<string>();
    for (const p of held)
      if (!(await this.store.get(`keyPackage:${p.id}`))) foreign.add(p.id);
    const replaced = (p: { id: string; createdAt: string }) =>
      due(p) || foreign.has(p.id);
    const oneTime = held.filter((p) => !p.lastResort);
    const stale = oneTime.filter(replaced).map((p) => p.id);
    const need = Math.max(
      0,
      PRIVATE_DM_KEY_PACKAGE_TARGET - oneTime.length + stale.length,
    );
    const lastResort = held.find((p) => p.lastResort);
    const newLastResort = !lastResort || replaced(lastResort);
    if (need > 0 || newLastResort) {
      const packages = await createKeyPackages(
        device,
        need + (newLastResort ? 1 : 0),
        now,
      );
      const spare = newLastResort
        ? { ...packages.pop()!, lastResort: true }
        : null;
      // Kept before the upload, so a welcome never names a package this device lost.
      for (const item of [...packages, ...(spare ? [spare] : [])])
        await this.store.set(`keyPackage:${item.id}`, item);
      const result = await this.api<{
        stored: number;
        removed?: string[];
        lastResort?: boolean;
      }>("POST", path, {
        packages: packages.map((p) => ({
          id: p.id,
          keyPackage: p.publicPackage,
        })),
        ...(stale.length ? { replace: stale } : {}),
        // The one it replaces may already be in a welcome, so its private
        // half stays until it expires like the others.
        ...(spare
          ? { lastResort: { id: spare.id, keyPackage: spare.publicPackage } }
          : {}),
      });
      for (const item of packages.slice(result.stored))
        await this.store.delete(`keyPackage:${item.id}`);
      if (spare && !result.lastResort)
        await this.store.delete(`keyPackage:${spare.id}`);
      // The old last-resort half stays only as long as a queued welcome
      // could name it.
      if (spare && result.lastResort)
        for (const key of await this.store.keys("keyPackage:"))
          await this.store.update<DeviceKeyPackage>(key, (current) =>
            current?.lastResort &&
            current.id !== spare.id &&
            current.replacedAt === undefined
              ? { ...current, replacedAt: now }
              : undefined,
          );
      // Replaced before anyone claimed them: no welcome can name them.
      for (const id of result.removed ?? [])
        await this.store.delete(`keyPackage:${id}`);
    }
    for (const key of await this.store.keys("keyPackage:")) {
      const item = await this.store.get<DeviceKeyPackage>(key);
      if (!item) continue;
      // Made before the lifetime policy: count from now.
      const expiresAt =
        item.expiresAt ??
        (item.createdAt ?? now) +
          PRIVATE_DM_KEY_PACKAGE_LIFETIME_SECONDS * 1000;
      if (item.expiresAt === undefined)
        // Only while it is still there: a welcome may have used it meanwhile.
        await this.store.update<DeviceKeyPackage>(key, (current) =>
          current && current.expiresAt === undefined
            ? { ...current, createdAt: current.createdAt ?? now, expiresAt }
            : undefined,
        );
      else if (
        now >
        Math.min(expiresAt, item.replacedAt ?? expiresAt) +
          PRIVATE_DM_MAX_QUEUE_SECONDS * 1000
      )
        await this.store.delete(key);
    }
  }

  private async bundle(): Promise<IdentityBundle> {
    const identity = await this.identity();
    if (!identity) throw new Error("This device has no private keys yet.");
    return {
      v: 1,
      userId: this.userId,
      identity,
      trusted: await this.trusted(),
      verified: await this.verified(),
      keyChanges: await this.keyChanges(),
      signedRemovals: await this.removalStatements(),
    };
  }
  /** The highest passkey backup counter this device has seen. */
  private async backupCounter() {
    return (await this.store.get<number>("backupCounter")) ?? 0;
  }
  private async sawBackupCounter(counter: number | undefined) {
    if (!counter || !Number.isSafeInteger(counter)) return;
    await this.store.update<number>("backupCounter", (seen) =>
      (seen ?? 0) >= counter ? undefined : counter,
    );
  }

  // Adding a device (link v2; see the link v2 spec)
  /**
   * On the new device: open a link request. Show the full code (the link id
   * and the secret, in groups of four) and the v2 check number. The secret
   * stays in this device's store with the link private key and is never
   * sent anywhere.
   */
  async beginLink(): Promise<{ id: string; code: string; check: string }> {
    const keys = await createLinkKeys();
    const secret = createLinkSecret();
    const startedAt = this.now();
    // Only the public key goes to the server, as before.
    const link = await this.api<{ id: string; expiresAt: string }>(
      "POST",
      "/private-dms/links",
      { publicKey: keys.publicKey },
    );
    if (link.id !== (await linkCode(keys.publicKey)))
      throw new Error("The link code did not match this device's key.");
    const check = await linkCheckV2(keys.publicKey, secret);
    const record: LinkRecord = {
      id: link.id,
      state: "waiting",
      startedAt,
      publicKey: keys.publicKey,
      privateKey: keys.privateKey,
      secret: toBase64(secret),
      check,
    };
    await this.store.delete(LEGACY_LINK_KEY);
    await this.store.set(LINK_KEY, record);
    await this.store.delete("linkOutcome");
    return { id: link.id, code: showLinkCode(link.id, secret), check };
  }
  /** On the new device: the link request still in progress, if any. */
  async pendingLink(): Promise<{
    id: string;
    code: string;
    check: string;
  } | null> {
    const link = await this.store.get<LinkRecord>(LINK_KEY);
    if (!link || link.state === "failed" || !link.secret || !link.check)
      return null;
    return {
      id: link.id,
      code: showLinkCode(link.id, fromBase64(link.secret)),
      check: link.check,
    };
  }
  /** On the new device: why the last link ended without setting up, if it did. */
  async linkFailure(): Promise<string | null> {
    const link = await this.store.get<LinkRecord>(LINK_KEY);
    return link?.state === "failed" ? (link.failure ?? LINK_NOT_YOURS) : null;
  }
  /**
   * On the new device: give up on the link. Its keys and secret go, and the
   * server forgets the request, so nothing can be sealed to it any more.
   */
  async cancelLink() {
    const link = await this.store.get<LinkRecord>(LINK_KEY);
    await this.store.delete(LINK_KEY);
    if (link)
      await this.api("POST", `/private-dms/links/${link.id}/finish`, {}).catch(
        () => undefined,
      );
  }
  /**
   * On the new device, once finishLink returned true: what happened to the
   * history, read once. "failed" shows HISTORY_NOT_BROUGHT.
   */
  async takeLinkOutcome(): Promise<LinkOutcome | null> {
    const outcome = (await this.store.get<LinkOutcome>("linkOutcome")) ?? null;
    if (outcome) await this.store.delete("linkOutcome");
    return outcome;
  }

  /** What the old device typed, read strictly; an older app's code is refused. */
  private readCode(code: string) {
    if (isOldLinkCode(code)) throw new LinkCodeError(LINK_UPDATE_NEW_DEVICE);
    const parsed = parseLinkCode(code);
    if (!parsed) throw new LinkCodeError(LINK_CODE_WRONG);
    return parsed;
  }
  /** On an existing device: the check number the new device should be showing. */
  async linkCheckFor(code: string) {
    const { id, secret } = this.readCode(code);
    return linkCheckV2(await this.linkKey(id), secret);
  }
  /** The link key the code names. The code is that key's fingerprint, so a swapped key is refused. */
  private async linkKey(id: string) {
    const link = await this.api<{ publicKey: string }>(
      "GET",
      `/private-dms/links/${encodeURIComponent(id)}`,
    );
    if ((await linkCode(link.publicKey)) !== id)
      throw new Error(
        "That code does not match the new device's key, so nothing was shared.",
      );
    return link.publicKey;
  }
  /**
   * On an existing device, after the person confirmed the numbers match and
   * confirmed it's them (the server asks "Confirm it's you" for every
   * upload, so nothing is stored before that). With `history` (on unless
   * turned off), this device's messages are built once, sealed and uploaded
   * part by part; a retry reuses the same sealed parts. Then the bundle is
   * sealed and posted. A 409 on the seal means another device answered
   * first: LinkAnsweredError, and the person must not use the new device.
   */
  async approveLink(
    code: string,
    check: string,
    options: {
      history?: boolean;
      onProgress?: (sent: number, total: number) => void;
    } = {},
  ) {
    const { id, secret } = this.readCode(code);
    const publicKey = await this.linkKey(id);
    if ((await linkCheckV2(publicKey, secret)) !== check)
      throw new Error("The numbers do not match, so nothing was shared.");
    const key = await linkKeyV2(publicKey, secret);
    const path = `/private-dms/links/${encodeURIComponent(id)}`;
    let history: LinkHistory | null = null;
    if (options.history ?? true) {
      const approval = await this.approvalFor(id, publicKey, key);
      history = approval.history;
      const total = approval.sealed.length;
      for (let index = 0; index < total; index++) {
        if (!approval.sent.has(index)) {
          await this.api("POST", `${path}/history`, {
            index,
            count: total,
            sealed: approval.sealed[index],
          }).catch((error: ApiError) => {
            // The first upload of a part wins; only "this part is already
            // there" counts as sent (link v2 audit LW-4).
            if (error.status === 409 && error.code === "LINK_PART_SENT") return;
            // The link was sealed by someone else first: the same warning as
            // a 409 on /seal, so the person doesn't use the new device.
            if (error.status === 409 && error.code !== "LINK_HISTORY_BUSY") {
              this.approvals.delete(id);
              throw new LinkAnsweredError(LINK_ANSWERED_FIRST);
            }
            // Anything else, such as the account's history slot being busy,
            // stops here with its own words.
            throw error;
          });
          approval.sent.add(index);
        }
        options.onProgress?.(index + 1, total);
      }
    }
    const bundle: LinkBundle = {
      ...(await this.bundle()),
      v: 2,
      // The new device learns how new a backup must be.
      backupCounter: await this.backupCounter(),
      history,
    };
    const sealed = await sealLinkV2(
      publicKey,
      key,
      te.encode(JSON.stringify(bundle)),
      linkInnerAad("bundle", 0, 1, this.userId, publicKey),
    );
    try {
      await this.api("POST", `${path}/seal`, { sealed });
    } catch (error) {
      if ((error as ApiError).status === 409) {
        this.approvals.delete(id);
        throw new LinkAnsweredError(LINK_ANSWERED_FIRST);
      }
      throw error;
    }
    this.approvals.delete(id);
  }
  /** On an existing device: the person cancelled; the sealed parts are forgotten. */
  cancelApproval(code: string) {
    const parsed = parseLinkCode(code);
    if (parsed) this.approvals.delete(parsed.id);
  }
  /** The history for one approval, built and sealed once and kept for retries. */
  private async approvalFor(id: string, publicKey: string, key: Uint8Array) {
    const held = this.approvals.get(id);
    if (held && held.publicKey === publicKey) return held;
    const { parts, truncated, real } = await this.exportHistory();
    const count = parts.length;
    const sealed: string[] = [];
    for (let index = 0; index < count; index++) {
      const wire = await sealLinkV2(
        publicKey,
        key,
        parts[index],
        linkInnerAad("history", index, count, this.userId, publicKey),
      );
      if (wire.length !== PRIVATE_DM_HISTORY_SEALED_CHARS)
        throw new Error("A history part did not seal to its fixed size.");
      sealed.push(wire);
    }
    // Nothing to send: the bundle says history null and nothing is uploaded
    // (spec clarification 2).
    const approval = {
      publicKey,
      sealed: real ? sealed : [],
      sent: new Set<number>(),
      history: real
        ? {
            parts: count as LinkHistory["parts"],
            digest: await historyDigest(parts),
            truncated,
          }
        : null,
    };
    this.approvals.set(id, approval);
    return approval;
  }

  /**
   * This device's history for a new device: every conversation the server
   * still lists (so none that ended) with its text and timer lines, never
   * notices, never anything expired. Packed newest first into parts of at
   * most PRIVATE_DM_HISTORY_JSON_MAX bytes of JSON, so when it would pass
   * 64 parts the newest messages are kept and `truncated` is set. The part
   * count is padded to 1, 4, 16 or 64 with empty parts.
   */
  private async exportHistory(): Promise<{
    parts: Uint8Array[];
    truncated: boolean;
    /** Parts with messages in them, before the empty padding parts. */
    real: number;
  }> {
    const { conversations } = await this.api<{
      conversations: PrivateDmConversation[];
    }>("GET", "/private-dms/conversations");
    const open = new Map(conversations.map((c) => [c.id, c]));
    type Head = Omit<HistoryConversation, "messages">;
    const items: { head: Head; message: HistoryMessage }[] = [];
    for (const key of await this.store.keys("messages:")) {
      const conversationId = key.slice("messages:".length);
      const listed = open.get(conversationId);
      if (!listed) continue;
      const local = await this.local(conversationId);
      const peer =
        local.peer ??
        listed.members.find((m) => m.userId !== this.userId)?.userId;
      if (!peer) continue;
      const head: Head = {
        conversationId,
        peer,
        timer:
          local.timerSeconds !== undefined &&
          local.timerSentAt !== undefined &&
          local.timerId !== undefined
            ? {
                seconds: local.timerSeconds,
                sentAt: local.timerSentAt,
                id: local.timerId,
              }
            : null,
      };
      for (const m of await this.messages(conversationId)) {
        if (m.kind === "text")
          items.push({
            head,
            message: {
              id: m.id,
              kind: "text",
              body: m.body,
              sentAt: m.sentAt,
              expiresAt: m.expiresAt,
              senderUserId: m.senderUserId,
              ...(m.proof ? { proof: m.proof } : {}),
            },
          });
        else if (m.kind === "timer") {
          const seconds = m.seconds ?? timerFromWords(m.body);
          if (seconds === undefined) continue;
          items.push({
            head,
            message: {
              id: m.id,
              kind: "timer",
              body: "",
              seconds,
              sentAt: m.sentAt,
              expiresAt: null,
              senderUserId: m.senderUserId,
            },
          });
        }
      }
    }
    items.sort(
      (a, b) =>
        b.message.sentAt - a.message.sentAt ||
        (a.message.id < b.message.id
          ? -1
          : a.message.id > b.message.id
            ? 1
            : 0),
    );
    const bytes = (value: unknown) => te.encode(JSON.stringify(value)).length;
    const EMPTY = bytes({ v: 1, conversations: [] });
    type Part = {
      size: number;
      conversations: Map<string, HistoryConversation>;
    };
    const fresh = (): Part => ({ size: EMPTY, conversations: new Map() });
    const packed: Part[] = [fresh()];
    let truncated = false;
    for (const { head, message } of items) {
      const cost = (part: Part) => {
        const entry = part.conversations.get(head.conversationId);
        return entry
          ? bytes(message) + (entry.messages.length ? 1 : 0)
          : bytes({ ...head, messages: [] }) +
              (part.conversations.size ? 1 : 0) +
              bytes(message);
      };
      let part = packed.at(-1)!;
      if (part.size + cost(part) > PRIVATE_DM_HISTORY_JSON_MAX) {
        if (packed.length >= PRIVATE_DM_HISTORY_PART_COUNTS.at(-1)!) {
          truncated = true;
          break;
        }
        part = fresh();
        packed.push(part);
      }
      part.size += cost(part);
      const entry = part.conversations.get(head.conversationId);
      if (entry) entry.messages.push(message);
      else
        part.conversations.set(head.conversationId, {
          ...head,
          messages: [message],
        });
    }
    const parts = packed.map((part) => {
      const json = JSON.stringify({
        v: 1,
        conversations: [...part.conversations.values()],
      });
      if (te.encode(json).length !== part.size)
        throw new Error("The history did not pack to its measured size.");
      return padHistoryPart(json);
    });
    const real = parts.length;
    const count = paddedHistoryCount(Math.max(1, real))!;
    while (parts.length < count)
      parts.push(padHistoryPart(JSON.stringify({ v: 1, conversations: [] })));
    return { parts, truncated, real };
  }

  /**
   * On the new device: move the link along its states (waiting, spent,
   * registered, imported, failed), kept in the store. True once the link
   * finished; false while it waits or while another call runs. A failure
   * throws LinkFailedError with the sentence to show, and the link is over.
   * Only one call runs at a time here, a seal is opened at most once, and
   * no other seal is ever opened for the same link.
   */
  finishLink(): Promise<boolean> {
    if (this.finishing) return Promise.resolve(false);
    // One finishLink at a time across every tab and window of this account
    // (Web Locks), not just in this tab (link v2 audit LW-3).
    const run = () => this.finishLinkHere();
    const locked = this.locks
      ? this.locks.request(`hubs-private-link:${this.userId}`, run)
      : run();
    this.finishing = locked.finally(() => {
      this.finishing = null;
    });
    return this.finishing;
  }
  private async finishLinkHere(): Promise<boolean> {
    let link = await this.store.get<LinkRecord>(LINK_KEY);
    if (!link) return false;
    if (link.state === "failed")
      throw new LinkFailedError(link.failure ?? LINK_NOT_YOURS);
    if (link.state === "waiting") {
      // Abandoned or expired: the keys and secret go (link v2 audit LW-5).
      if (this.now() - link.startedAt > PRIVATE_DM_LINK_SECONDS * 1000)
        return this.failLink(link, LINK_TOO_LONG);
      let state: { sealed: string | null };
      try {
        state = await this.api<{ sealed: string | null }>(
          "GET",
          `/private-dms/links/${link.id}`,
        );
      } catch (error) {
        if ((error as ApiError).status === 404)
          return this.failLink(link, LINK_TOO_LONG);
        throw error;
      }
      if (!state.sealed) return false;
      // A v2 app never opens anything else.
      if (readLinkWire(state.sealed).kind !== "v2")
        return this.failLink(link, LINK_UPDATE_OTHER_DEVICE);
      if (this.now() - link.startedAt > PRIVATE_DM_LINK_SECONDS * 1000)
        return this.failLink(link, LINK_TOO_LONG);
      // The identity keys this account's devices use, read before the link
      // is spent so a network error here leaves it waiting.
      const { devices } = await this.api<PrivateDmState>("GET", "/private-dms");
      const identityKeys = devices
        .filter((d) => d.userId === this.userId)
        .map((d) => d.identityKey);
      // Spent, durably, before anything is opened.
      const token = randomId();
      const id = link.id;
      await this.store.update<LinkRecord>(LINK_KEY, (current) =>
        current?.id === id && current.state === "waiting"
          ? { ...current, state: "spent", spentAt: this.now(), spentBy: token }
          : undefined,
      );
      link = await this.store.get<LinkRecord>(LINK_KEY);
      if (!link || link.spentBy !== token) return false;
      const bundle = await this.openBundle(link, state.sealed, identityKeys);
      if (!bundle) return this.failLink(link, LINK_NOT_YOURS);
      link = { ...link, bundle };
      await this.store.set(LINK_KEY, link);
    }
    if (link.state === "spent") {
      if (!link.bundle) {
        // Another tab or window spent it and is opening it; one that
        // stopped part way never opens it again.
        if (this.now() - (link.spentAt ?? 0) < LINK_OPEN_GRACE_MS) return false;
        return this.failLink(link, LINK_TOO_LONG);
      }
      // Errors here (Confirm it's you, the network) are retried by the next
      // call, from the kept bundle. A retry after this device already
      // registered under the bundle's identity does not register another
      // device (link v2 audit LW-3).
      const already = await this.identity();
      if (
        already?.publicKey === link.bundle.identity.publicKey &&
        (await this.device())
      )
        await this.refreshKeyPackages().catch(() => undefined);
      else
        await this.register(
          link.bundle.identity,
          link.bundle as unknown as IdentityBundle,
        );
      await this.sawBackupCounter(link.bundle.backupCounter);
      link = { ...link, state: "registered" };
      await this.store.set(LINK_KEY, link);
    }
    if (link.state === "registered") {
      const history = link.bundle?.history
        ? await this.importHistory(link, link.bundle.history)
        : "none";
      link = {
        ...link,
        state: "imported",
        outcome: {
          history,
          truncated:
            history === "imported" && !!link.bundle?.history?.truncated,
        },
      };
      await this.store.set(LINK_KEY, link);
    }
    if (link.state === "imported") {
      await this.api("POST", `/private-dms/links/${link.id}/finish`, {}).catch(
        (error: ApiError) => {
          // Already gone on the server (finished or expired): nothing to do.
          if (error.status !== 404) throw error;
        },
      );
      await this.store.set("linkOutcome", link.outcome ?? { history: "none" });
      await this.store.delete(LINK_KEY);
      return true;
    }
    return false;
  }
  /** The link ends here: its keys, secret and bundle go, and the server forgets it. */
  private async failLink(link: LinkRecord, failure: string): Promise<never> {
    await this.store.set(LINK_KEY, {
      id: link.id,
      state: "failed",
      startedAt: link.startedAt,
      failure,
    } satisfies LinkRecord);
    // No /finish: the sweep removes the link, and the old device still sees
    // "Another device answered this link first" (spec clarification 7; LW-7).
    throw new LinkFailedError(failure);
  }
  /**
   * Opens the hand-off: the outer layer, then the inner layer under K with
   * the bundle AAD, then the strict bundle rules and the account's identity
   * key. Null for every failure, so they all look the same.
   */
  private async openBundle(
    link: LinkRecord,
    wire: string,
    identityKeys: string[],
  ): Promise<LinkBundle | null> {
    try {
      if (!link.privateKey || !link.secret) return null;
      const key = await linkKeyV2(link.publicKey!, fromBase64(link.secret));
      const opened = await openLinkV2(
        link.privateKey,
        key,
        wire,
        linkInnerAad("bundle", 0, 1, this.userId, link.publicKey!),
      );
      const text = strictText(opened);
      if (text === null) return null;
      const bundle = linkBundleOf(JSON.parse(text), this.userId);
      if (!bundle) return null;
      // The identity must be the one this account's devices already use.
      if (
        identityKeys.length &&
        !identityKeys.includes(bundle.identity.publicKey)
      )
        return null;
      return bundle;
    } catch {
      return null;
    }
  }

  /**
   * Brings the history the bundle names: every part fetched first, then
   * opened, unpadded, checked against the digest and read, before anything
   * is stored. Any failure there imports nothing ("failed"). A field that
   * fails drops only its message. Never replaces a message this device
   * holds. Network trouble throws, and the next call tries again.
   */
  private async importHistory(
    link: LinkRecord,
    history: LinkHistory,
  ): Promise<"imported" | "failed"> {
    const count = history.parts;
    const fetched: string[] = [];
    for (let index = 0; index < count; index++) {
      try {
        const { sealed } = await this.api<{ sealed: unknown }>(
          "GET",
          `/private-dms/links/${link.id}/history/${index}`,
        );
        // The wrong size is refused before anything is decrypted.
        if (
          typeof sealed !== "string" ||
          sealed.length !== PRIVATE_DM_HISTORY_SEALED_CHARS
        )
          return "failed";
        fetched.push(sealed);
      } catch (error) {
        const status = (error as ApiError).status ?? 0;
        if (status >= 400 && status < 500 && status !== 429) return "failed";
        // Past the link's 15 minutes, any failure ends the import, so a
        // server can't hold this device on the linking screen (LW-15).
        if (this.now() - link.startedAt > PRIVATE_DM_LINK_SECONDS * 1000)
          return "failed";
        throw error;
      }
    }
    const { conversations: listed } = await this.api<{
      conversations: PrivateDmConversation[];
    }>("GET", "/private-dms/conversations");
    const now = this.now();
    let read: Map<string, HistoryConversation>;
    try {
      if (!link.privateKey || !link.secret) return "failed";
      const key = await linkKeyV2(link.publicKey!, fromBase64(link.secret));
      const parts: Uint8Array[] = [];
      for (let index = 0; index < count; index++)
        parts.push(
          await openLinkV2(
            link.privateKey,
            key,
            fetched[index],
            linkInnerAad("history", index, count, this.userId, link.publicKey!),
          ),
        );
      if ((await historyDigest(parts)) !== history.digest) return "failed";
      read = new Map();
      const seenIds = new Map<string, Set<string>>();
      for (const part of parts) {
        const json = unpadHistoryPart(part);
        if (json === null) return "failed";
        const value = JSON.parse(json);
        if (
          !isRecord(value) ||
          value.v !== 1 ||
          !Array.isArray(value.conversations)
        )
          return "failed";
        for (const entry of value.conversations) {
          const conversation = historyConversationOf(entry, this.userId, now);
          if (!conversation) continue;
          // A conversation's peer and timer come from its first appearance,
          // and a message id seen twice keeps the first.
          // A set of ids per conversation keeps this linear (LW-8).
          const first = read.get(conversation.conversationId);
          if (!first) {
            read.set(conversation.conversationId, conversation);
            seenIds.set(
              conversation.conversationId,
              new Set(conversation.messages.map((m) => m.id)),
            );
          } else if (first.peer === conversation.peer) {
            const seen = seenIds.get(conversation.conversationId)!;
            for (const message of conversation.messages)
              if (!seen.has(message.id)) {
                seen.add(message.id);
                first.messages.push(message);
              }
          }
        }
      }
    } catch {
      return "failed";
    }
    // Only conversations the server still lists; ended ones are skipped.
    const open = new Set(listed.map((c) => c.id));
    for (const conversation of read.values()) {
      const { conversationId, peer } = conversation;
      if (!open.has(conversationId)) continue;
      const local = await this.store.get<LocalConversation>(
        conversationKey(conversationId),
      );
      if (local?.peer && local.peer !== peer) continue;
      if (!local?.peer)
        await this.patchLocal(conversationId, (l) =>
          l.peer ? null : { peer },
        );
      const timer = conversation.timer;
      if (timer)
        await this.patchLocal(conversationId, (current) =>
          current.peer === peer && newerTimer(current, timer.sentAt, timer.id)
            ? {
                timerSeconds: timer.seconds,
                timerSentAt: timer.sentAt,
                timerId: timer.id,
              }
            : null,
        );
      const lines: StoredMessage[] = conversation.messages.map((m) =>
        m.kind === "timer"
          ? {
              id: m.id,
              kind: "timer",
              body: timerWords(m.seconds!),
              seconds: m.seconds,
              sentAt: m.sentAt,
              expiresAt: m.expiresAt,
              senderUserId: m.senderUserId,
              imported: true,
            }
          : {
              id: m.id,
              kind: "text",
              body: m.body,
              sentAt: m.sentAt,
              expiresAt: m.expiresAt,
              senderUserId: m.senderUserId,
              imported: true,
              ...(m.proof ? { proof: m.proof } : {}),
            },
      );
      await this.store.update<StoredMessage[]>(
        messagesKey(conversationId),
        (current) => {
          const list = (current ?? []).filter(
            (m) => m.expiresAt === null || m.expiresAt > now,
          );
          const held = new Set(list.map((m) => m.id));
          const added = lines.filter((m) => !held.has(m.id));
          if (!added.length) return undefined;
          list.push(...added);
          list.sort((a, b) => a.sentAt - b.sentAt);
          return list;
        },
      );
    }
    return "imported";
  }

  // Passkey backup
  /**
   * Save the passkey backup. Its counter is one more than any this device
   * has seen and than the one the server holds, so the server keeps only
   * the newest and devices can refuse an older one.
   */
  async saveBackup(prfOutput: Uint8Array, credentialId: string) {
    const held = await this.api<{ counter?: number | null }>(
      "GET",
      "/private-dms/backup",
    ).catch((error: ApiError) => {
      if (error.status === 404) return { counter: 0 };
      throw error;
    });
    // The server's number only moves this one forward. One that leaves no
    // room for the next count would make the backup unrestorable.
    const reported = Number(held.counter ?? 0);
    const counter =
      Math.max(
        await this.backupCounter(),
        Number.isSafeInteger(reported) && reported < Number.MAX_SAFE_INTEGER
          ? reported
          : 0,
      ) + 1;
    const sealed = await sealBackup(prfOutput, {
      ...(await this.bundle()),
      counter,
    });
    await this.api("PUT", "/private-dms/backup", {
      ...sealed,
      credentialId,
      counter,
    });
    await this.sawBackupCounter(counter);
  }
  async restoreBackup(prfOutput: Uint8Array) {
    const { backup } = await this.api<{
      backup: SealedBackup & { credentialId: string };
    }>("GET", "/private-dms/backup");
    const bundle = await openBackup(prfOutput, this.userId, backup);
    const problem = backupRollbackProblem(
      bundle.counter,
      await this.backupCounter(),
    );
    if (problem) throw new Error(problem);
    await this.register(bundle.identity, bundle);
    await this.sawBackupCounter(bundle.counter);
  }

  // Removing a device and starting over
  /**
   * Remove another device of this account. The server signs out every
   * session that device used, so a lost device cannot register again with
   * the identity key it holds.
   */
  async removeDevice(deviceId: string) {
    const identity = await this.identity();
    const { devices } = await this.api<PrivateDmState>("GET", "/private-dms");
    const target = devices.find((d) => d.id === deviceId);
    // Signed by the identity key, so other people's devices remove it too.
    const proof = async (id: string, deviceKey: string) => {
      const at = this.now();
      return {
        at,
        signature: await signDeviceRemoval(
          identity!,
          this.userId,
          id,
          deviceKey,
          at,
        ),
      };
    };
    const path = (id: string) =>
      `/private-dms/devices/${encodeURIComponent(id)}/remove`;
    const result = await this.api<{
      ok: true;
      removed?: { id: string; deviceKey: string }[];
      signedOut?: number;
    }>(
      "POST",
      path(deviceId),
      identity && target?.identityKey === identity.publicKey
        ? await proof(deviceId, target.deviceKey)
        : {},
    );
    // Devices removed with it (registered from the lost device's sign-in)
    // get the same signed removal.
    if (identity)
      for (const extra of result.removed ?? [])
        if (extra.id !== deviceId)
          await this.api(
            "POST",
            path(extra.id),
            await proof(extra.id, extra.deviceKey),
          ).catch(() => undefined);
    return result;
  }

  /**
   * This device leaves the account. Its own key proves it, so this needs no
   * fresh confirmation, and other people's devices accept the removal. The
   * caller then deletes the store. False when this store holds no device.
   */
  async removeThisDevice() {
    const device = await this.device();
    if (!device) return false;
    const at = this.now();
    await this.api(
      "POST",
      `/private-dms/devices/${encodeURIComponent(device.deviceId)}/remove`,
      { at, proof: await signSelfRemoval(device, at) },
    );
    return true;
  }

  /**
   * Say, signed by the identity key, that every removal of this account's
   * devices is signed, once every device the account uses can sign them.
   * Other people's devices then ignore unsigned removals of this person's
   * devices. True when the statement is in place.
   */
  async declareSignedRemovals(): Promise<boolean> {
    const identity = await this.identity();
    if (!identity) return false;
    const state = await this.api<PrivateDmState>("GET", "/private-dms");
    if (!state.enabled) return false;
    const signature = await signRemovalStatement(identity, this.userId);
    const statement = {
      userId: this.userId,
      identityKey: identity.publicKey,
      signature,
    };
    if (state.signedRemovals === identity.publicKey) {
      await this.pinRemovalStatements([statement]);
      return true;
    }
    if (
      !state.devices.length ||
      !state.devices.every(
        (d) => d.signsRemovals && d.identityKey === identity.publicKey,
      )
    )
      return false;
    await this.api("POST", "/private-dms/signed-removals", {
      identityKey: identity.publicKey,
      signature,
    });
    await this.pinRemovalStatements([statement]);
    return true;
  }

  /** People whose identity key said their removals are signed (user id to identity key), pinned once seen. */
  private async removalStatements() {
    return (
      (await this.store.get<Record<string, string>>("signedRemovals")) ?? {}
    );
  }
  /** Keep each statement that verifies for the identity key this device pinned for that person. */
  private async pinRemovalStatements(statements: PrivateDmRemovalStatement[]) {
    const trusted = await this.trusted();
    const valid: PrivateDmRemovalStatement[] = [];
    for (const statement of statements)
      if (
        trusted[statement.userId] === statement.identityKey &&
        (await verifyRemovalStatement(statement))
      )
        valid.push(statement);
    if (!valid.length) return;
    await this.store.update<Record<string, string>>(
      "signedRemovals",
      (pins) => {
        const next = { ...(pins ?? {}) };
        for (const statement of valid)
          next[statement.userId] = statement.identityKey;
        return next;
      },
    );
  }
  /** The facts `removalCounts` needs for a member the server no longer lists as active. */
  private async removalFacts(
    member: GroupMember,
    revoked: PrivateDmRevocation[],
  ) {
    const revocation = revoked.find(
      (r) => r.id === member.deviceId && r.userId === member.userId,
    );
    return {
      proof: (revocation?.signature
        ? (await verifyRemoval(member, revocation))
          ? "valid"
          : "invalid"
        : "none") as "valid" | "invalid" | "none",
      signedRemovals:
        (await this.removalStatements())[member.userId] ===
        member.identityPublicKey,
    };
  }
  /**
   * The note for this device's commits once its account has made the
   * statement, signed again here so it needs no copy from the server.
   */
  private async ownRemovalsNote(identity: IdentityKeys | undefined) {
    if (
      !identity ||
      (await this.removalStatements())[this.userId] !== identity.publicKey
    )
      return null;
    return signedRemovalsNote(
      fromBase64(await signRemovalStatement(identity, this.userId)),
    );
  }

  /**
   * Start over with a new identity on this device. A lost or stolen device
   * still holds the old identity key, so new keys are the only way to be
   * sure it reads nothing new. The server removes every device of the old
   * identity; contacts see the safety code change. Each conversation keeps
   * its history here and waits for the other person's device to add this
   * one again.
   */
  async startOver() {
    // A contact's pinned key and removals statement are facts about that
    // contact, so they stay: a welcome under another key for them is still
    // held for review. Verified marks were about the old pair of keys and
    // go; open key change alerts stay.
    const { [this.userId]: _, ...trusted } = await this.trusted();
    const signedRemovals =
      (await this.store.get<Record<string, string>>("signedRemovals")) ?? {};
    const keyChanges =
      (await this.store.get<Record<string, KeyChange>>("keyChanges")) ?? {};
    const identity = await createIdentity();
    await this.register(
      identity,
      { trusted, signedRemovals, keyChanges },
      true,
    );
  }

  // Conversations
  /** Make an accepted one-to-one message private, or open the one that exists. */
  async start(channelId: string, timerSeconds?: number) {
    const { conversation } = await this.api<{
      conversation: PrivateDmConversation;
    }>("POST", "/private-dms/conversations", {
      channelId,
      ...(timerSeconds !== undefined ? { timerSeconds } : {}),
    });
    await this.exclusive(conversation.id, async () => {
      const local = await this.local(conversation.id);
      const peer =
        local.peer ??
        conversation.members.find((m) => m.userId !== this.userId)?.userId;
      if (!local.group && conversation.epoch === 0) {
        const device = (await this.device())!;
        await this.storeGroup(
          conversation.id,
          await startGroup(device, conversation.id),
          local.generation ?? 0,
          () => ({
            cursor: 0,
            createdHere: true,
            updatedAt: this.now(),
            trackedFrom: 0,
            ...(peer ? { peer } : {}),
            ...(timerSeconds !== undefined ? { timerSeconds } : {}),
          }),
        );
      } else if (peer && !local.peer)
        await this.patchLocal(conversation.id, (l) =>
          l.peer ? null : { peer },
        );
      await this.syncHere(conversation.id);
    });
    return conversation;
  }

  private async local(id: string): Promise<LocalConversation> {
    return (
      (await this.store.get<LocalConversation>(conversationKey(id))) ??
      emptyLocal()
    );
  }
  /**
   * Change some of a conversation's fields in one step, never its group
   * state (that goes through `storeGroup`). `change` sees the stored
   * value and returns the fields to change, or null to leave it.
   */
  private patchLocal(
    id: string,
    change: (current: LocalConversation) => Partial<LocalConversation> | null,
  ) {
    return this.store.update<LocalConversation>(
      conversationKey(id),
      (stored) => {
        const current = stored ?? emptyLocal();
        const fields = change(current);
        if (!fields) return undefined;
        return {
          ...current,
          ...fields,
          group: current.group,
          epoch: current.epoch,
          generation: current.generation,
        };
      },
    );
  }

  /**
   * Store a conversation's group state behind the write guard
   * (`groupWriteProblem`): `baseGeneration` is the generation the caller
   * read before it started. Returns the generation now stored; throws
   * StaleGroupError, storing nothing, when someone stored newer state
   * meanwhile.
   */
  private async storeGroup(
    id: string,
    group: ClientState | null,
    baseGeneration: number,
    fields: (
      current: LocalConversation,
    ) => Partial<LocalConversation> = () => ({}),
  ): Promise<number> {
    const epoch = group ? Number(group.groupContext.epoch) : null;
    const encoded = group ? saveGroup(group) : null;
    let generation = 0;
    await this.store.update<LocalConversation>(
      conversationKey(id),
      (stored) => {
        const problem = groupWriteProblem(stored, { epoch, baseGeneration });
        if (problem) throw new StaleGroupError(problem);
        const current = stored ?? emptyLocal();
        generation = (current.generation ?? 0) + 1;
        return {
          ...current,
          ...fields(current),
          group: encoded,
          epoch: epoch ?? current.epoch,
          generation,
        };
      },
    );
    return generation;
  }

  /** The messages this device holds, without any that have disappeared. */
  async messages(conversationId: string): Promise<StoredMessage[]> {
    const all =
      (await this.store.get<StoredMessage[]>(messagesKey(conversationId))) ??
      [];
    const now = this.now();
    const live = (m: StoredMessage) =>
      m.expiresAt === null || m.expiresAt > now;
    const kept = all.filter(live);
    if (kept.length !== all.length)
      // Filtered again as it is written, so a line added meanwhile stays.
      await this.store.update<StoredMessage[]>(
        messagesKey(conversationId),
        (current) => current?.filter(live),
      );
    return kept;
  }
  private async append(conversationId: string, message: StoredMessage) {
    const now = this.now();
    await this.store.update<StoredMessage[]>(
      messagesKey(conversationId),
      (current) => {
        const list = (current ?? []).filter(
          (m) => m.expiresAt === null || m.expiresAt > now,
        );
        if (list.some((m) => m.id === message.id)) return undefined;
        list.push(message);
        list.sort((a, b) => a.sentAt - b.sentAt);
        return list;
      },
    );
  }

  /** Search runs here, on this device's own copy. The server never sees a query. */
  async search(query: string) {
    const needle = query.trim().toLowerCase();
    if (!needle) return [];
    const found: { conversationId: string; message: StoredMessage }[] = [];
    for (const key of await this.store.keys("messages:")) {
      const conversationId = key.slice("messages:".length);
      for (const message of await this.messages(conversationId))
        if (
          message.kind === "text" &&
          message.body.toLowerCase().includes(needle)
        )
          found.push({ conversationId, message });
    }
    return found;
  }

  /** Compare an identity with the pinned one; a change becomes a notice. */
  private async checkIdentities(
    conversationId: string,
    people: { userId: string; identityPublicKey: string }[],
  ) {
    // Pinned in one step, so a pin from another tab is never lost.
    const changedPeople: { userId: string; identityPublicKey: string }[] = [];
    await this.store.update<Record<string, string>>("trusted", (stored) => {
      const trusted = { ...(stored ?? {}) };
      let changed = false;
      changedPeople.length = 0;
      for (const person of people) {
        const pinned = trusted[person.userId];
        if (pinned === person.identityPublicKey) continue;
        if (pinned && person.userId !== this.userId) changedPeople.push(person);
        if (person.userId !== this.userId || !pinned) {
          trusted[person.userId] = person.identityPublicKey;
          changed = true;
        }
      }
      return changed ? trusted : undefined;
    });
    for (const person of changedPeople) {
      const verified = await this.verified();
      await this.store.update<Record<string, KeyChange>>(
        "keyChanges",
        (changes) => ({
          ...changes,
          [person.userId]: {
            at: this.now(),
            // Still true when a second change arrives before any review.
            wasVerified:
              !!verified[person.userId] ||
              !!changes?.[person.userId]?.wasVerified,
          },
        }),
      );
      await this.store.update<Record<string, string>>("verified", (current) => {
        if (!current?.[person.userId]) return undefined;
        const { [person.userId]: _, ...rest } = current;
        return rest;
      });
      await this.append(conversationId, {
        id: `notice:${person.userId}:${person.identityPublicKey}`,
        kind: "notice",
        body: "Their safety code changed. They may have reinstalled Hubs or set up a new phone. Compare codes again to be sure it is them.",
        sentAt: this.now(),
        expiresAt: null,
        senderUserId: person.userId,
      });
    }
  }

  /** Bring this device's copy up to date, then add or retire devices. */
  sync(conversationId: string): Promise<void> {
    return this.exclusive(conversationId, () =>
      this.syncHere(conversationId),
    ).finally(() => this.sweepWhenDue());
  }

  /** Disappeared messages in every conversation go, at most once a minute. */
  private async sweepWhenDue() {
    const now = this.now();
    if (now - this.sweptAt < SWEEP_MS) return;
    this.sweptAt = now;
    await sweepDisappeared(this.store, now).catch(() => undefined);
  }

  /**
   * `sync` inside the conversation's queue. A stale write (possible only
   * without Web Locks, from another tab) starts it again from the state
   * that tab stored.
   */
  private async syncHere(conversationId: string, attempt = 0): Promise<void> {
    for (let tries = 0; ; tries++) {
      try {
        return await this.syncOnce(conversationId, attempt);
      } catch (error) {
        if (!(error instanceof StaleGroupError) || tries >= 2) throw error;
      }
    }
  }

  private async syncOnce(conversationId: string, attempt: number) {
    const device = await this.device();
    if (!device)
      throw new Error("Set up private conversations on this device first.");
    let local = await this.local(conversationId);
    if (!local.peer) {
      // Pin the other person before opening any welcome, so a welcome that
      // brings in someone else is refused from the start.
      const { conversation } = await this.api<{
        conversation: PrivateDmConversation;
      }>("GET", `/private-dms/conversations/${conversationId}`);
      const peer = conversation.members.find(
        (m) => m.userId !== this.userId,
      )?.userId;
      if (peer) {
        await this.patchLocal(conversationId, (l) =>
          l.peer ? null : { peer },
        );
        local = await this.local(conversationId);
      }
    }
    let group: ClientState | null = local.group ? loadGroup(local.group) : null;
    let cursor = local.cursor;
    // The generation this sync started from: every write below must follow it.
    let generation = local.generation ?? 0;
    if (local.heldWelcome) {
      const joined = await this.joinReviewed(conversationId, local.heldWelcome);
      if (joined) {
        group = joined;
        // With no group to open them in, what came during the review was
        // passed by. It is read now, or a commit in it would leave this
        // device behind for good.
        cursor = Math.min(cursor, local.heldWelcome.seq ?? cursor);
        generation = await this.storeGroup(
          conversationId,
          group,
          generation,
          () => ({ cursor }),
        );
      }
    }
    for (;;) {
      const { envelopes } = await this.api<{ envelopes: PrivateDmEnvelope[] }>(
        "GET",
        `/private-dms/conversations/${conversationId}/envelopes?deviceId=${encodeURIComponent(device.deviceId)}&after=${cursor}`,
      );
      if (!envelopes.length) break;
      for (const envelope of envelopes) {
        group = await this.apply(conversationId, device, group, envelope);
        cursor = Math.max(cursor, envelope.seq);
        // Save as we go: an advanced ratchet must never be used twice.
        generation = await this.storeGroup(
          conversationId,
          group,
          generation,
          (current) => ({ cursor: Math.max(current.cursor, cursor) }),
        );
      }
      if (envelopes.length < 200) break;
    }
    await this.tellMissing(conversationId);
    if (group) await this.reconcile(conversationId, group, generation, attempt);
  }

  private async apply(
    conversationId: string,
    device: DeviceKeys,
    group: ClientState | null,
    envelope: PrivateDmEnvelope,
  ): Promise<ClientState | null> {
    const here = await this.local(conversationId);
    if (envelope.kind === "welcome") {
      // A group made here never went out, so a welcome, which did, wins.
      if ((group && !here.createdHere) || !envelope.keyPackageId) return group;
      const keyPackage = await this.store.get<DeviceKeyPackage>(
        `keyPackage:${envelope.keyPackageId}`,
      );
      if (!keyPackage) return group;
      let joined: ClientState;
      try {
        joined = await joinFromWelcome(envelope.ciphertext, keyPackage);
      } catch {
        return group;
      }
      // A welcome must be for this conversation's own group, so a welcome
      // from another conversation cannot be replayed here.
      if (
        groupConversationId(joined) !== conversationId ||
        !(await this.acceptMembers(conversationId, groupMembers(joined)))
      ) {
        await this.spend(keyPackage);
        await this.refused(conversationId, envelope);
        return group;
      }
      // Keys only move forward: this device has passed that epoch.
      if (Number(joined.groupContext.epoch) < (here.epoch ?? 0)) {
        await this.spend(keyPackage);
        return group;
      }
      if (await this.holdWelcome(conversationId, envelope, joined))
        return group;
      return this.enter(conversationId, joined, keyPackage);
    }
    // Before this device joined, or its own echo: nothing to open. A group
    // made here has reached nobody, so nothing from others can open in it.
    if (
      !group ||
      here.createdHere ||
      envelope.senderDeviceId === device.deviceId
    )
      return group;
    // The same ciphertext again (a replay under a new envelope): skip it.
    const fingerprint = await envelopeFingerprint(envelope.ciphertext);
    if ((await this.local(conversationId)).seen?.includes(fingerprint))
      return group;
    // Its place in the sender's chain, so a message that never comes shows
    // as missing, whether this one opens or not.
    const header = await messageHeader(group, envelope.ciphertext);
    const arrived = (userId: string | undefined, shownAt: number) =>
      header && userId
        ? this.noteArrival(conversationId, header, userId, shownAt)
        : undefined;
    try {
      const result = await receive(group, envelope.ciphertext, {
        userId: envelope.senderUserId,
        deviceId: envelope.senderDeviceId,
      });
      await this.markSeen(conversationId, fingerprint);
      if (result.kind === "change") {
        // This device is out: its group can do nothing more, and the next
        // welcome brings it back.
        if (result.state.groupActiveState.kind === "removedFromGroup") {
          result.release();
          await this.append(conversationId, {
            id: `removed:${envelope.id}`,
            kind: "notice",
            body: DEVICE_REMOVED_NOTICE,
            sentAt: Date.parse(envelope.createdAt) || this.now(),
            expiresAt: null,
            senderUserId: envelope.senderUserId,
          });
          return null;
        }
        // Refused changes leave this device on the epoch it trusts.
        if (
          result.state.groupActiveState.kind !== "active" ||
          !(await this.acceptMembers(
            conversationId,
            groupMembers(result.state),
          ))
        ) {
          await this.refused(conversationId, envelope);
          return group;
        }
        result.release();
        await this.checkIdentities(conversationId, groupMembers(result.state));
        await this.followFrom(conversationId, result.state);
        if (result.sender && result.removalStatement)
          await this.noteStatement(
            conversationId,
            result.sender,
            result.removalStatement,
          );
        await this.notePeerLeft(
          conversationId,
          groupMembers(group),
          groupMembers(result.state),
          Number(result.state.groupContext.epoch),
        );
        return result.state;
      }
      const payload = result.payload;
      // The sender's clock only orders the message: never later than now,
      // and never far before the server relayed it. Disappearing time
      // counts from when this device received it, so a back-dated message
      // cannot vanish before anyone reads (or reports) it.
      const receivedAt = this.now();
      const relayedAt = Date.parse(envelope.createdAt);
      const shownAt = Math.min(
        receivedAt,
        Number.isFinite(relayedAt)
          ? Math.max(payload.sentAt, relayedAt - PRIVATE_DM_CLOCK_SKEW_MS)
          : payload.sentAt,
      );
      await arrived(result.sender.userId, shownAt);
      if (payload.kind === "timer")
        await this.patchLocal(conversationId, (current) =>
          newerTimer(current, payload.sentAt, payload.id)
            ? {
                timerSeconds: payload.expiresInSeconds,
                timerSentAt: payload.sentAt,
                timerId: payload.id,
              }
            : null,
        );
      await this.append(conversationId, {
        id: payload.id,
        kind: payload.kind,
        body:
          payload.kind === "timer"
            ? payload.expiresInSeconds
              ? `Messages now disappear after ${timerLabel(payload.expiresInSeconds).toLowerCase()}.`
              : "Disappearing messages are off."
            : payload.body,
        ...(payload.kind === "timer"
          ? { seconds: payload.expiresInSeconds }
          : {}),
        sentAt: shownAt,
        expiresAt:
          payload.kind === "text" && payload.expiresInSeconds
            ? receivedAt + payload.expiresInSeconds * 1000
            : null,
        senderUserId: payload.userId,
        ...(payload.kind === "text" &&
        payload.userId !== this.userId &&
        envelope.frankingTag
          ? {
              proof: {
                envelopeId: envelope.id,
                payload,
                commitment: result.commitment,
                frankingTag: envelope.frankingTag,
                ...(envelope.frankingKeyId
                  ? { frankingKeyId: envelope.frankingKeyId }
                  : {}),
                stampedAt: envelope.createdAt,
              },
            }
          : {}),
      });
      return result.state;
    } catch {
      const sentAt = Date.parse(envelope.createdAt) || this.now();
      // It arrived, even if it did not open: that line says so already.
      await arrived(
        groupMembers(group).find((m) => m.leafIndex === header?.leafIndex)
          ?.userId,
        sentAt,
      );
      await this.append(conversationId, {
        id: `unreadable:${envelope.id}`,
        kind: "notice",
        body: "A message could not be opened on this device.",
        sentAt,
        expiresAt: null,
        senderUserId: envelope.senderUserId,
      });
      return group;
    }
  }

  /** A one-time package is spent. The last-resort one may open another welcome. */
  private async spend(keyPackage: DeviceKeyPackage) {
    if (!keyPackage.lastResort)
      await this.store.delete(`keyPackage:${keyPackage.id}`);
  }

  /** Take a welcome this device accepted: this group is now its copy of the conversation. */
  private async enter(
    conversationId: string,
    joined: ClientState,
    keyPackage: DeviceKeyPackage,
  ) {
    await this.spend(keyPackage);
    await this.checkIdentities(conversationId, groupMembers(joined));
    // A device joins with fresh keys of its own, and follows this epoch from
    // its start. After a last-resort package, whose private half stays here,
    // the next sync commits new keys at once.
    await this.patchLocal(conversationId, () => ({
      updatedAt: keyPackage.lastResort ? 0 : this.now(),
      trackedFrom: Number(joined.groupContext.epoch),
      createdHere: false,
      heldWelcome: undefined,
    }));
    return joined;
  }

  /**
   * Hold a welcome whose other person carries an identity key this device
   * did not pin: the alert goes up as for any key change, and the device
   * joins only after the person reviews it. True when it is held. While one
   * is held, a welcome under the key trusted before it goes ahead.
   */
  private async holdWelcome(
    conversationId: string,
    envelope: PrivateDmEnvelope,
    joined: ClientState,
  ) {
    const other = groupMembers(joined).find((m) => m.userId !== this.userId);
    if (!other) return false;
    const key = other.identityPublicKey;
    const pinned = (await this.trusted())[other.userId];
    const held = (await this.local(conversationId)).heldWelcome;
    const open = held && (await this.keyChangeWith(other.userId));
    if (open ? key === held.previousKey : !pinned || pinned === key)
      return false;
    // A welcome replacing a held one keeps the earlier place to read from,
    // so what came during the review is never passed by.
    const from = Math.min(envelope.seq, held?.seq ?? envelope.seq);
    await this.patchLocal(conversationId, () => ({
      heldWelcome: {
        envelopeId: envelope.id,
        seq: from,
        keyPackageId: envelope.keyPackageId!,
        ciphertext: envelope.ciphertext,
        userId: other.userId,
        previousKey: open ? held.previousKey : pinned,
      },
    }));
    await this.checkIdentities(conversationId, [other]);
    await this.store.update<Record<string, KeyChange>>(
      "keyChanges",
      (changes) => {
        const change = changes?.[other.userId];
        return change && !change.held
          ? { ...changes, [other.userId]: { ...change, held: true } }
          : undefined;
      },
    );
    return true;
  }

  /** The held welcome, once the person has reviewed the change. */
  private async joinReviewed(conversationId: string, held: HeldWelcome) {
    if (await this.keyChangeWith(held.userId)) return null;
    const keyPackage = await this.store.get<DeviceKeyPackage>(
      `keyPackage:${held.keyPackageId}`,
    );
    await this.patchLocal(conversationId, () => ({ heldWelcome: undefined }));
    if (!keyPackage) return null;
    let joined: ClientState;
    try {
      joined = await joinFromWelcome(held.ciphertext, keyPackage);
    } catch {
      return null;
    }
    if (
      groupConversationId(joined) !== conversationId ||
      !(await this.acceptMembers(conversationId, groupMembers(joined)))
    )
      return null;
    return this.enter(conversationId, joined, keyPackage);
  }

  /** A statement carried in a commit: the same check as one from the server. */
  private async noteStatement(
    conversationId: string,
    sender: GroupMember,
    signature: Uint8Array,
  ) {
    await this.pinRemovalStatements([
      {
        userId: sender.userId,
        identityKey: sender.identityPublicKey,
        signature: toBase64(signature),
      },
    ]);
    const pinned = (await this.removalStatements())[sender.userId];
    // One device of an account announcing it is enough here.
    if (sender.userId === this.userId && pinned === sender.identityPublicKey)
      await this.patchLocal(conversationId, () => ({ removalsNoted: pinned }));
  }

  /** One line when a change leaves no device of the other person here. */
  private async notePeerLeft(
    conversationId: string,
    before: GroupMember[],
    after: GroupMember[],
    epoch: number,
  ) {
    const { peer } = await this.local(conversationId);
    if (
      !peer ||
      !before.some((m) => m.userId === peer) ||
      after.some((m) => m.userId === peer)
    )
      return;
    await this.append(conversationId, {
      id: `peer-gone:${epoch}`,
      kind: "notice",
      body: NO_PEER_DEVICE_NOTICE,
      sentAt: this.now(),
      expiresAt: null,
      senderUserId: peer,
    });
  }

  /** From the first epoch this device follows from its start, count each sender's generations. */
  private async followFrom(conversationId: string, state: ClientState) {
    const epoch = Number(state.groupContext.epoch);
    await this.patchLocal(conversationId, (local) =>
      local.trackedFrom === undefined ? { trackedFrom: epoch } : null,
    );
  }

  /**
   * Note the other person's message at its generation (`trackGeneration`).
   * A late one settles the notice that called it missing.
   */
  private async noteArrival(
    conversationId: string,
    header: { epoch: number; leafIndex: number; generation: number },
    userId: string,
    shownAt: number,
  ) {
    if (userId === this.userId) return;
    let settled: string | null = null;
    const now = this.now();
    await this.patchLocal(conversationId, (local) => {
      if (local.trackedFrom === undefined || header.epoch < local.trackedFrom)
        return null;
      const key = `${header.epoch}:${header.leafIndex}`;
      const tracks = { ...(local.generations ?? {}) };
      const result = trackGeneration(
        tracks[key] ?? { userId, next: 0, gaps: [], told: [] },
        header.generation,
        now,
        shownAt,
      );
      tracks[key] = result.track;
      settled = result.settled;
      // Late messages open only within the retained epochs; older
      // tracks with nothing left to wait for go.
      for (const [name, track] of Object.entries(tracks))
        if (Number(name.split(":")[0]) < header.epoch - 4 && !track.gaps.length)
          delete tracks[name];
      return { generations: tracks };
    });
    if (settled) await this.settleMissing(conversationId, settled);
  }

  /** One calm line for each sender's gaps that stayed open past the grace time. */
  private async tellMissing(conversationId: string) {
    const now = this.now();
    const notices: StoredMessage[] = [];
    await this.patchLocal(conversationId, (local) => {
      notices.length = 0;
      const tracks = { ...(local.generations ?? {}) };
      let changed = false;
      for (const [key, track] of Object.entries(tracks)) {
        const id = `missing:${key}:${now}`;
        const { track: next, due } = dueGenerations(track, now, id);
        if (!due.length) continue;
        tracks[key] = next;
        changed = true;
        notices.push({
          id,
          kind: "notice",
          body: missingBody(due.length),
          missing: due.length,
          sentAt: Math.min(...due.map((g) => g.before)),
          expiresAt: null,
          senderUserId: track.userId,
        });
      }
      return changed ? { generations: tracks } : null;
    });
    for (const notice of notices) await this.append(conversationId, notice);
  }

  /** A message called missing came after all: count it off its notice. */
  private async settleMissing(conversationId: string, noticeId: string) {
    await this.store.update<StoredMessage[]>(
      messagesKey(conversationId),
      (current) => {
        const at = current?.findIndex((m) => m.id === noticeId) ?? -1;
        if (!current || at < 0) return undefined;
        const notice = current[at];
        const left = (notice.missing ?? 1) - 1;
        return left > 0
          ? current.map((m, i) =>
              i === at ? { ...m, missing: left, body: missingBody(left) } : m,
            )
          : current.filter((_, i) => i !== at);
      },
    );
  }

  /** Add devices the conversation's people have set up, and retire removed ones. */
  private async reconcile(
    conversationId: string,
    group: ClientState,
    generation: number,
    attempt: number,
  ) {
    const {
      devices,
      conversation,
      revoked = [],
      signedRemovals = [],
    } = await this.api<{
      devices: PrivateDmDevice[];
      conversation?: PrivateDmConversation;
      revoked?: PrivateDmRevocation[];
      signedRemovals?: PrivateDmRemovalStatement[];
    }>("GET", `/private-dms/conversations/${conversationId}`);
    await this.pinRemovalStatements(signedRemovals);
    const members = groupMembers(group);
    const local = await this.local(conversationId);
    const own = await this.identity();
    const peer =
      local.peer ??
      members.find((m) => m.userId !== this.userId)?.userId ??
      conversation?.members.find((m) => m.userId !== this.userId)?.userId;
    if (peer && !local.peer)
      await this.patchLocal(conversationId, (l) => (l.peer ? null : { peer }));
    const inGroup = new Set(members.map((m) => m.deviceId));
    const active = new Set(devices.map((d) => d.id));
    const missing: PrivateDmDevice[] = [];
    for (const candidate of devices) {
      if (inGroup.has(candidate.id)) continue;
      // Only the two people's devices, and for this account only devices
      // that carry this device's own identity key.
      if (candidate.userId === this.userId) {
        if (candidate.identityKey !== own?.publicKey) continue;
      } else if (candidate.userId !== peer) continue;
      const valid = await verifyDeviceCertificate(
        {
          v: 1,
          userId: candidate.userId,
          deviceId: candidate.id,
          identityPublicKey: candidate.identityKey,
          certificate: candidate.certificate,
        },
        fromBase64(candidate.deviceKey),
      );
      if (valid) missing.push(candidate);
    }
    // Only removals the person (or the device itself) signed, unless the
    // rule in removalCounts says an unsigned one still counts. `replaced`
    // counts only if a new key joins in this commit, known after the claim.
    const retired: GroupMember[] = [];
    const replaced: GroupMember[] = [];
    for (const member of members) {
      if (active.has(member.deviceId)) continue;
      const facts = await this.removalFacts(member, revoked);
      if (removalCounts({ ...facts, startedOver: false })) retired.push(member);
      else if (removalCounts({ ...facts, startedOver: true }))
        replaced.push(member);
    }
    // Every commit from an account that made the statement carries it, and
    // each conversation gets one soon after, so a contact learns it from the
    // group even if the server never shows it.
    const note = await this.ownRemovalsNote(own);
    // With nothing to add or remove, a commit still goes out when this
    // device's own keys are due a refresh (post-compromise security).
    const due =
      this.now() - (local.updatedAt ?? 0) >=
        PRIVATE_DM_KEY_UPDATE_SECONDS * 1000 ||
      (!!note && local.removalsNoted !== own?.publicKey);
    if (!missing.length && !retired.length && !due) return;
    const claimed = missing.length
      ? (
          await this.api<{
            claimed: {
              device: PrivateDmDevice;
              keyPackageId: string;
              keyPackage: string;
            }[];
          }>("POST", `/private-dms/conversations/${conversationId}/claim`, {
            deviceIds: missing.map((d) => d.id),
          })
        ).claimed
      : [];
    // Only key packages inside the lifetime policy (90 days at most); a
    // device whose package was refused is added once it publishes new ones.
    // Each must be the package of a device asked for here, once: the answer
    // comes from the server, which chooses what is in it.
    const asked = new Map(missing.map((d) => [d.id, d]));
    const usable = claimed.filter((c) => {
      const device = asked.get(c.device.id);
      const credential = keyPackageCredential(c.keyPackage);
      if (
        !device ||
        !credential ||
        credential.userId !== device.userId ||
        credential.deviceId !== device.id ||
        credential.identityPublicKey !== device.identityKey ||
        keyPackageProblem(c.keyPackage, this.now())
      )
        return false;
      asked.delete(c.device.id);
      return true;
    });
    const joining = usable.map((c) => keyPackageCredential(c.keyPackage));
    retired.push(
      ...replaced.filter((member) =>
        joining.some(
          (credential) =>
            credential?.userId === member.userId &&
            credential.identityPublicKey !== member.identityPublicKey,
        ),
      ),
    );
    if (!usable.length && !retired.length && !due) return;
    const change = await changeDevices(
      group,
      usable.map((c) => c.keyPackage),
      retired.map((m) => m.leafIndex),
      note ?? undefined,
    );
    if (!(await this.acceptMembers(conversationId, groupMembers(change.state))))
      return;
    const device = (await this.device())!;
    try {
      await this.api(
        "POST",
        `/private-dms/conversations/${conversationId}/envelopes`,
        {
          deviceId: device.deviceId,
          kind: "commit",
          epoch: change.epoch,
          ciphertext: change.commit,
          welcomes: change.welcome
            ? usable.map((c) => ({
                deviceId: c.device.id,
                keyPackageId: c.keyPackageId,
                ciphertext: change.welcome,
              }))
            : [],
        },
      );
    } catch (error) {
      if ((error as ApiError).code !== "EPOCH_CHANGED" || attempt > 2)
        throw error;
      // Someone else changed the conversation first. A group made here that
      // never went out gives way to theirs; then catch up and try again.
      // It reads from the start again: a welcome it passed joins now.
      if ((await this.local(conversationId)).createdHere)
        await this.storeGroup(conversationId, null, generation, () => ({
          createdHere: false,
          cursor: 0,
        }));
      return this.syncHere(conversationId, attempt + 1);
    }
    await this.storeGroup(conversationId, change.state, generation, () => ({
      createdHere: false,
      updatedAt: this.now(),
      ...(note ? { removalsNoted: own?.publicKey } : {}),
    }));
    await this.checkIdentities(conversationId, groupMembers(change.state));
    await this.followFrom(conversationId, change.state);
    await this.notePeerLeft(
      conversationId,
      members,
      groupMembers(change.state),
      Number(change.state.groupContext.epoch),
    );
  }

  /** Encrypt and send one message. Returns the message as stored here. */
  async send(
    conversation: Pick<PrivateDmConversation, "id" | "timerSeconds">,
    text: string,
    kind: "text" | "timer" = "text",
  ): Promise<StoredMessage> {
    const body = text.trim();
    if (kind === "text") {
      if (!body) throw new Error("Write a message first.");
      if (body.length > PRIVATE_DM_MAX_BODY)
        throw new Error(
          `Private messages can be up to ${PRIVATE_DM_MAX_BODY} characters.`,
        );
      const problem = this.sendCheck?.(body) ?? null;
      if (problem) throw new Error(problem);
    }
    return this.exclusive(conversation.id, () =>
      this.sendHere(conversation, body, kind),
    );
  }

  /** `send` inside the conversation's queue. */
  private async sendHere(
    conversation: Pick<PrivateDmConversation, "id" | "timerSeconds">,
    body: string,
    kind: "text" | "timer",
  ): Promise<StoredMessage> {
    await this.syncHere(conversation.id);
    const device = (await this.device())!;
    for (let tries = 0; ; tries++) {
      try {
        return await this.encryptAndSend(conversation, body, kind, device);
      } catch (error) {
        // Refused before anything went out: encrypt again from the stored state.
        if (!(error instanceof StaleGroupError) || tries >= 2) throw error;
      }
    }
  }

  private async encryptAndSend(
    conversation: Pick<PrivateDmConversation, "id" | "timerSeconds">,
    body: string,
    kind: "text" | "timer",
    device: DeviceKeys,
  ): Promise<StoredMessage> {
    const local = await this.local(conversation.id);
    if (local.peer && (await this.keyChangeWith(local.peer))?.wasVerified)
      throw Object.assign(
        new Error(
          "Their safety code changed since you verified it. Compare codes or choose Keep talking without comparing before sending.",
        ),
        { code: "KEY_CHANGED" },
      );
    if (local.heldWelcome)
      throw Object.assign(
        new Error(
          "Their safety code changed before this device joined. Compare codes or choose Keep talking without comparing to join.",
        ),
        { code: "KEY_CHANGED" },
      );
    if (!local.group)
      throw new Error("This device is still joining. Try again in a moment.");
    const group = loadGroup(local.group);
    if (
      kind === "text" &&
      local.peer &&
      !groupMembers(group).some((m) => m.userId === local.peer)
    )
      throw Object.assign(
        new Error(
          "The other person has no devices in this conversation right now, so this wasn't sent.",
        ),
        { code: "NO_PEER_DEVICE" },
      );
    // A timer change is always newer than the one it replaces, even when
    // that one came from a clock a little ahead of this one.
    const sentAt =
      kind === "timer"
        ? Math.max(this.now(), (local.timerSentAt ?? 0) + 1)
        : this.now();
    const payloadId = randomId();
    // A timer change carries the new value; a text uses the timer last
    // announced inside the encryption, never a server-only change.
    const timerSeconds =
      kind === "timer"
        ? conversation.timerSeconds
        : this.timerFrom(local, conversation.timerSeconds);
    const encrypted = await encryptMessage(group, {
      v: 1,
      id: payloadId,
      kind,
      body: kind === "text" ? body : "",
      sentAt,
      expiresInSeconds: timerSeconds,
      userId: this.userId,
      deviceId: device.deviceId,
    });
    // Saved before sending, so a failed send never reuses a message key,
    // and only over the state it was made from (the write guard).
    await this.storeGroup(
      conversation.id,
      encrypted.state,
      local.generation ?? 0,
      () =>
        kind === "timer"
          ? { timerSeconds, timerSentAt: sentAt, timerId: payloadId }
          : {},
    );
    await this.api(
      "POST",
      `/private-dms/conversations/${conversation.id}/envelopes`,
      {
        deviceId: device.deviceId,
        kind: "message",
        epoch: Number(encrypted.state.groupContext.epoch),
        ciphertext: encrypted.ciphertext,
      },
    );
    const stored: StoredMessage = {
      id: encrypted.payload.id,
      kind,
      body:
        kind === "timer"
          ? timerSeconds
            ? `Messages now disappear after ${timerLabel(timerSeconds).toLowerCase()}.`
            : "Disappearing messages are off."
          : body,
      ...(kind === "timer" ? { seconds: timerSeconds } : {}),
      sentAt,
      expiresAt:
        kind === "text" && timerSeconds ? sentAt + timerSeconds * 1000 : null,
      senderUserId: this.userId,
    };
    await this.append(conversation.id, stored);
    return stored;
  }

  private timerFrom(local: LocalConversation, serverTimer: number) {
    if (local.timerSeconds !== undefined) return local.timerSeconds;
    // Before any announcement the server's value is used, except that the
    // server alone can never turn disappearing messages off.
    return serverTimer || PRIVATE_DM_DEFAULT_TIMER;
  }
  /** The disappearing timer this device uses for a conversation. */
  async timerFor(
    conversation: Pick<PrivateDmConversation, "id" | "timerSeconds">,
  ) {
    return this.timerFrom(
      await this.local(conversation.id),
      conversation.timerSeconds,
    );
  }

  /**
   * True when a group's members are ones this device accepts
   * (`membershipProblem`); the first other account seen becomes the pinned
   * peer.
   */
  private async acceptMembers(
    conversationId: string,
    members: GroupMember[],
  ): Promise<boolean> {
    const local = await this.local(conversationId);
    const problem = membershipProblem(members, {
      userId: this.userId,
      identityPublicKey: (await this.identity())?.publicKey ?? "",
      peer: local.peer ?? null,
    });
    if (problem) return false;
    const other = members.find((m) => m.userId !== this.userId)?.userId;
    if (other && !local.peer)
      await this.patchLocal(conversationId, (l) =>
        l.peer ? null : { peer: other },
      );
    return true;
  }
  private async markSeen(conversationId: string, fingerprint: string) {
    await this.patchLocal(conversationId, (local) => ({
      seen: [...(local.seen ?? []), fingerprint].slice(-SEEN_LIMIT),
    }));
  }
  private async refused(conversationId: string, envelope: PrivateDmEnvelope) {
    await this.append(conversationId, {
      id: `refused:${envelope.id}`,
      kind: "notice",
      body: REFUSED_MEMBER_NOTICE,
      sentAt: Date.parse(envelope.createdAt) || this.now(),
      expiresAt: null,
      senderUserId: envelope.senderUserId,
    });
  }

  /** Pick a new disappearing timer and tell everyone in the conversation. */
  async setTimer(conversationId: string, timerSeconds: number) {
    return this.exclusive(conversationId, async () => {
      await this.api("PATCH", `/private-dms/conversations/${conversationId}`, {
        timerSeconds,
      });
      return this.sendHere({ id: conversationId, timerSeconds }, "", "timer");
    });
  }

  /** The 60-digit code two people compare to be sure no one is in between. */
  async safetyCodeWith(otherUserId: string) {
    const trusted = await this.trusted();
    const mine = (await this.identity())?.publicKey;
    const theirs = trusted[otherUserId];
    if (!mine || !theirs) return null;
    return safetyCode(
      { userId: this.userId, identityPublicKey: mine },
      { userId: otherUserId, identityPublicKey: theirs },
    );
  }
  /**
   * Mark the code the person compared as verified. `shownCode` is the code
   * on their screen: if the pinned key changed since it was drawn (a sync
   * ran meanwhile), nothing is marked and the person compares again.
   */
  async markVerified(otherUserId: string, shownCode: string) {
    const trusted = await this.trusted();
    if (!trusted[otherUserId]) return;
    if ((await this.safetyCodeWith(otherUserId)) !== shownCode)
      throw Object.assign(
        new Error(
          "Their safety code changed while you were comparing. Compare the new code.",
        ),
        { code: "KEY_CHANGED" },
      );
    await this.store.update<Record<string, string>>("verified", (verified) => ({
      ...verified,
      [otherUserId]: trusted[otherUserId],
    }));
    await this.acknowledgeKeyChange(otherUserId);
  }

  /** Report messages: this device reveals them with the proof they were sent. */
  async report(conversationId: string, messageIds: string[], details = "") {
    const chosen = (await this.messages(conversationId)).filter(
      (m) => messageIds.includes(m.id) && m.proof,
    );
    if (!chosen.length) throw new Error("Pick a message someone else sent.");
    const messages: PrivateDmReportedMessage[] = chosen.map((m) => ({
      envelopeId: m.proof!.envelopeId,
      payload: m.proof!.payload,
      commitment: m.proof!.commitment,
      frankingTag: m.proof!.frankingTag,
      ...(m.proof!.frankingKeyId
        ? { frankingKeyId: m.proof!.frankingKeyId }
        : {}),
      senderUserId: m.senderUserId,
      conversationId,
      stampedAt: m.proof!.stampedAt,
    }));
    return this.api("POST", "/private-dms/reports", {
      conversationId,
      details,
      messages,
    });
  }

  /**
   * The conversation was read on this device, so the server marks its "New
   * private message" notice read on every device.
   */
  async markRead(conversationId: string) {
    return this.api<{ ok: true; read: boolean }>(
      "POST",
      `/private-dms/conversations/${conversationId}/read`,
      { expectedUserId: this.userId },
    );
  }

  /** Forget a conversation on this device only. */
  forget(conversationId: string) {
    return this.exclusive(conversationId, async () => {
      await this.store.delete(conversationKey(conversationId));
      await this.store.delete(messagesKey(conversationId));
    });
  }

  // Calls (calls.ts): the same device key and pins vouch for this device's
  // connections to end-to-end encrypted calls.

  /**
   * Signs the binding for one call connection with this device's key, or
   * null when this device has no private conversation device (the
   * connection then joins unbound and shows as Not verified).
   */
  async callBinding(
    channelId: string,
    leaseId: string,
    connectionPublicKey: string,
  ): Promise<CallBinding | null> {
    const device = await this.device();
    if (!device || !(await callSignaturesSupported())) return null;
    return signCallBinding(device, {
      channelId,
      leaseId,
      connectionPublicKey,
    });
  }

  /**
   * Signs a roster statement: the connections this device's connection sees
   * in the call (the transcript digest), for the current epoch and slot.
   * Null without a device.
   */
  async callView(input: {
    channelId: string;
    leaseId: string;
    epoch: string;
    keyIndex: number;
    transcriptDigest: Uint8Array;
  }): Promise<CallView | null> {
    const device = await this.device();
    if (!device || !(await callSignaturesSupported())) return null;
    return signCallView(device.signKey, input);
  }

  /**
   * Decides, for every other connection in a call, whether it gets the call
   * key (calls.ts callPeerDecisions), and records what it learns in the
   * same trust store private conversations use: a first-seen identity key
   * is pinned, and a changed one raises the key change alert and clears
   * the verified mark. The pins are written in one atomic update.
   */
  async callPeers(
    participants: readonly CallConnection[],
    context: CallPeersContext,
  ): Promise<CallPeer[]> {
    const others = participants.filter((p) => p.leaseId !== context.leaseId);
    const signatures = await callSignaturesSupported();
    const checks: CallBindingCheck[] = await Promise.all(
      others.map((p) =>
        // Without Ed25519 here a binding cannot be checked, so it counts
        // as no binding: Not verified, never Verified.
        signatures
          ? checkCallBinding(context.channelId, p)
          : Promise.resolve<CallBindingCheck>({ status: "none" }),
      ),
    );
    const identity = signatures ? await this.identity() : undefined;
    const verified = await this.verified();
    const changes = await this.keyChanges();
    let decisions: CallPeerDecision[] = [];
    let inputs: CallPeerInput[] = [];
    const changed = new Map<string, string>();
    const inputsFor = (trusted: Record<string, string>) =>
      others.map((p, i): CallPeerInput => ({
        self: {
          userId: this.userId,
          identityPublicKey: identity?.publicKey ?? null,
        },
        oneToOnePeer: context.oneToOnePeer,
        closed: context.closed,
        connection: {
          userId: p.userId,
          v: p.v ?? 2,
          binding: checks[i].status,
          identityPublicKey:
            checks[i].status === "valid"
              ? (checks[i] as { identityPublicKey: string }).identityPublicKey
              : null,
        },
        pin: identity ? (trusted[p.userId] ?? null) : null,
        verified: verified[p.userId] ?? null,
        keyChange: changes[p.userId]
          ? { wasVerified: changes[p.userId].wasVerified }
          : null,
      }));
    if (identity)
      await this.store.update<Record<string, string>>("trusted", (stored) => {
        const trusted = { ...(stored ?? {}) };
        inputs = inputsFor(trusted);
        decisions = callPeerDecisions(inputs);
        changed.clear();
        let write = false;
        decisions.forEach((decision, i) => {
          const key = inputs[i].connection.identityPublicKey;
          if (decision.pin === "none" || !key) return;
          if (decision.pin === "changed") changed.set(others[i].userId, key);
          if (trusted[others[i].userId] !== key) {
            trusted[others[i].userId] = key;
            write = true;
          }
        });
        return write ? trusted : undefined;
      });
    else {
      inputs = inputsFor({});
      decisions = callPeerDecisions(inputs);
    }
    for (const userId of changed.keys()) await this.recordCallKeyChange(userId);
    const after = changed.size ? await this.keyChanges() : changes;
    return others.map((p, i) => ({
      ...p,
      ...decisions[i],
      identityPublicKey: inputs[i].connection.identityPublicKey,
      devicePublicKey:
        checks[i].status === "valid"
          ? (checks[i] as { devicePublicKey: string }).devicePublicKey
          : null,
      keyChangeAt: after[p.userId]?.at ?? null,
    }));
  }

  /** The key change alert for a contact seen in a call, as checkIdentities raises it. */
  private async recordCallKeyChange(userId: string) {
    const verified = await this.verified();
    await this.store.update<Record<string, KeyChange>>(
      "keyChanges",
      (changes) => ({
        ...changes,
        [userId]: {
          at: this.now(),
          wasVerified: !!verified[userId] || !!changes?.[userId]?.wasVerified,
        },
      }),
    );
    await this.store.update<Record<string, string>>("verified", (current) => {
      if (!current?.[userId]) return undefined;
      const { [userId]: _, ...rest } = current;
      return rest;
    });
  }
}

/** What callPeers needs to know about the call. */
export type CallPeersContext = {
  channelId: string;
  /** This device's own connection, which is skipped. */
  leaseId: string;
  /** One-to-one calls: the only other account allowed in. null in group calls. */
  oneToOnePeer: string | null;
  /** The server accepts only protocol 3, so older apps are refused. */
  closed: boolean;
};
/** One other connection in a call, with what this device decided for it. */
export type CallPeer = CallConnection &
  CallPeerDecision & {
    /** The identity key of a valid binding, else null. */
    identityPublicKey: string | null;
    /** The device key of a valid binding, which signs its roster statements. */
    devicePublicKey: string | null;
    /** When this account's unreviewed Safety code change was seen, else null. */
    keyChangeAt: number | null;
  };
