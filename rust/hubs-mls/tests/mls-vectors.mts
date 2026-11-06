// MLS interop vectors for private conversations, made with the TypeScript
// implementation on ts-mls, so a native MLS core can show it reads and
// writes exactly what the TypeScript side does: ciphersuite 1, the Hubs
// basic credential, default capabilities, the 90-day key package lifetime,
// the ratchet tree inside the welcome, commits as MLS private messages,
// 256-byte padding and the franking commitment in the authenticated data.
//
// Run with Node 24 from the TypeScript package's folder, with its
// dependencies installed:
//
//   node --import tsx <this repository>/rust/hubs-mls/tests/mls-vectors.mts \
//       generate <out.json>
//
// Every input is fixed (keys and ids come from short labels through
// SHA-256), the clock is fixed at `generator.nowSeconds` (key package
// lifetimes run from it), and the randomness ts-mls asks for comes from a
// seeded SHA-256 stream, so running it again writes the same bytes. The
// seeded randomness and the clock are for these vectors only: they replace
// crypto.getRandomValues, Math.random, X25519 key generation and Date.now
// inside this process and nowhere else. Every key in the file is a test key.
// Native tests pass the vectors' time to the core's lifetime checks.
//
// Two more commands let a native implementation talk back:
//
//   mls-vectors.mts answer <vectors.json> <native-replies.json> \
//       [<native-key-package.json> <out.json>]
//     Alice (ts-mls, from the state saved in the vectors) opens what the
//     native Bob sent after joining: messages and an update commit. Given a
//     key package the native side made, she then adds that device (commit
//     plus welcome) and sends a message for both native devices to open.
//
//   mls-vectors.mts join <vectors.json> <native-group.json> <out.json>
//     Bob (ts-mls) joins a group the native side made with Bob's spare key
//     package, opens its messages and commit, then writes a reply message,
//     an update commit and a message after it for the native side to open.
//
// The JSON shapes are the ones live_ts_mls.rs in this folder writes and
// reads.
import { createHash, createPrivateKey, createPublicKey } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
// Type imports are removed when the script runs, so these names do not need
// to resolve from this folder.
import type {
  DeviceKeyPackage,
  DeviceKeys,
  PrivateDmPayload,
} from "@hubs/private-messages";
import {
  privateMessages,
  tsMls,
  tsMlsRatchetTree,
  tsMlsVersion,
} from "./typescript-package.mts";

const {
  decodeMlsMessage,
  defaultCapabilities,
  defaultLifetime,
  encodeMlsMessage,
  generateKeyPackageWithKey,
} = tsMls;
const { encodeRatchetTree } = tsMlsRatchetTree;
const {
  PRIVATE_DM_CIPHERSUITE,
  PRIVATE_DM_KEY_PACKAGE_LIFETIME_SECONDS,
  PRIVATE_DM_KEY_PACKAGE_REFRESH_SECONDS,
  canonicalPayloadBytes,
  changeDevices,
  ciphersuite,
  createKeyPackages,
  deviceCertificateBody,
  encodeKeyPackageMessage,
  encryptMessage,
  fromBase64,
  groupMembers,
  joinFromWelcome,
  keyPackageLifetime,
  loadGroup,
  receive,
  saveGroup,
  startGroup,
  toBase64,
} = privateMessages;

/** The vectors' clock: key package lifetimes run from here. */
const VECTOR_NOW_MS = 1_760_000_000_000;

const sha256 = (...parts: (string | Uint8Array)[]) => {
  const h = createHash("sha256");
  for (const part of parts) h.update(part);
  return new Uint8Array(h.digest());
};
const hex = (bytes: Uint8Array) => Buffer.from(bytes).toString("hex");
const unhex = (text: string) => new Uint8Array(Buffer.from(text, "hex"));
const b64ToHex = (text: string) => hex(fromBase64(text));
const hexToB64 = (text: string) => toBase64(unhex(text));

function assert(condition: unknown, message: string): asserts condition {
  if (!condition) throw new Error(message);
}

// Randomness.

/** A SHA-256 counter stream. Test vectors only. */
function seededStream(label: string) {
  let counter = 0;
  let pool = new Uint8Array(0);
  return (n: number) => {
    const out = new Uint8Array(n);
    let at = 0;
    while (at < n) {
      if (!pool.length) {
        const c = new Uint8Array(8);
        new DataView(c.buffer).setBigUint64(0, BigInt(counter++));
        pool = sha256("hubs mls vectors rng v1\0", label, c);
      }
      const take = Math.min(pool.length, n - at);
      out.set(pool.subarray(0, take), at);
      pool = pool.subarray(take);
      at += take;
    }
    return out;
  };
}

/**
 * Route every source of randomness ts-mls and @hpke/core use through one
 * seeded stream: crypto.getRandomValues (ts-mls rng, reuse guards, path
 * secrets), Math.random (ts-mls GREASE in capabilities) and WebCrypto
 * X25519 key generation (HPKE init, leaf and ephemeral keys).
 */
function seedRandomness(label: string) {
  const next = seededStream(label);
  const webcrypto = globalThis.crypto;
  const subtle = webcrypto.subtle;
  const originalGenerateKey = subtle.generateKey.bind(subtle);
  Object.defineProperty(webcrypto, "getRandomValues", {
    configurable: true,
    value: <T extends ArrayBufferView | null>(array: T): T => {
      if (array) {
        const bytes = next(array.byteLength);
        new Uint8Array(array.buffer, array.byteOffset, array.byteLength).set(
          bytes,
        );
      }
      return array;
    },
  });
  Math.random = () => {
    const bytes = next(7);
    let value = 0;
    for (const byte of bytes) value = value * 256 + byte;
    return (value % 2 ** 53) / 2 ** 53;
  };
  Object.defineProperty(subtle, "generateKey", {
    configurable: true,
    value: async (
      algorithm: AlgorithmIdentifier,
      extractable: boolean,
      usages: KeyUsage[],
    ) => {
      const name =
        typeof algorithm === "string" ? algorithm : (algorithm as Algorithm).name;
      if (name !== "X25519")
        return originalGenerateKey(algorithm as never, extractable, usages);
      const der = Buffer.concat([
        Buffer.from("302e020100300506032b656e04220420", "hex"),
        Buffer.from(next(32)),
      ]);
      const publicRaw = createPublicKey(
        createPrivateKey({ key: der, format: "der", type: "pkcs8" }),
      )
        .export({ format: "der", type: "spki" })
        .subarray(-32);
      return {
        privateKey: await subtle.importKey(
          "pkcs8",
          der,
          { name: "X25519" },
          extractable,
          usages,
        ),
        publicKey: await subtle.importKey(
          "raw",
          publicRaw,
          { name: "X25519" },
          true,
          [],
        ),
      };
    },
  });
}

// Fixed keys.

/** An Ed25519 key from a label: the 32-byte seed, its PKCS#8 form and the public key. */
function ed25519From(label: string) {
  const seed = sha256(label);
  const pkcs8 = Buffer.concat([
    Buffer.from("302e020100300506032b657004220420", "hex"),
    Buffer.from(seed),
  ]);
  const publicKey = new Uint8Array(
    createPublicKey(createPrivateKey({ key: pkcs8, format: "der", type: "pkcs8" }))
      .export({ format: "der", type: "spki" })
      .subarray(-32),
  );
  return { seed, pkcs8: new Uint8Array(pkcs8), publicKey };
}

/**
 * The same keys createIdentity and createDevice make, from fixed seeds. The
 * website stores signing keys as PKCS#8 (what WebCrypto exports); ts-mls
 * also accepts the raw 32-byte seed.
 */
async function fixedDevice(userId: string, deviceId: string, label: string) {
  const cs = await ciphersuite();
  const identity = ed25519From(`hubs mls vector: ${label} identity`);
  const device = ed25519From(`hubs mls vector: ${label} device`);
  const certificate = await cs.signature.sign(
    identity.pkcs8,
    deviceCertificateBody(userId, deviceId, device.publicKey),
  );
  const keys: DeviceKeys = {
    userId,
    deviceId,
    identityPublicKey: toBase64(identity.publicKey),
    publicKey: toBase64(device.publicKey),
    signKey: toBase64(device.pkcs8),
    certificate: toBase64(certificate),
  };
  return {
    keys,
    vector: {
      userId,
      deviceId,
      identitySeedHex: hex(identity.seed),
      identityPublicKeyHex: hex(identity.publicKey),
      deviceSeedHex: hex(device.seed),
      devicePublicKeyHex: hex(device.publicKey),
      certificateHex: hex(certificate),
      credentialIdentityUtf8: JSON.stringify({
        v: 1,
        userId,
        deviceId,
        identityPublicKey: keys.identityPublicKey,
        certificate: keys.certificate,
      }),
    },
  };
}

function keyPackageVector(item: DeviceKeyPackage) {
  const priv = JSON.parse(item.privatePackage);
  return {
    id: item.id,
    mlsMessageHex: b64ToHex(item.publicPackage),
    initPrivateKeyHex: b64ToHex(priv.initPrivateKey),
    encryptionPrivateKeyHex: b64ToHex(priv.hpkePrivateKey),
    signaturePrivateKeyPkcs8Hex: b64ToHex(priv.signaturePrivateKey),
  };
}
const keyPackageFrom = (v: ReturnType<typeof keyPackageVector>): DeviceKeyPackage => ({
  id: v.id,
  publicPackage: hexToB64(v.mlsMessageHex),
  privatePackage: JSON.stringify({
    initPrivateKey: hexToB64(v.initPrivateKeyHex),
    hpkePrivateKey: hexToB64(v.encryptionPrivateKeyHex),
    signaturePrivateKey: hexToB64(v.signaturePrivateKeyPkcs8Hex),
  }),
});

const payloadFor = (
  device: DeviceKeys,
  id: string,
  body: string,
  sentAt: number,
): Omit<PrivateDmPayload, "frankingKey"> => ({
  v: 1,
  id,
  kind: "text",
  body,
  sentAt,
  expiresInSeconds: 604800,
  userId: device.userId,
  deviceId: device.deviceId,
});

async function messageVector(
  state: Parameters<typeof encryptMessage>[0],
  device: DeviceKeys,
  id: string,
  body: string,
  sentAt: number,
) {
  const sent = await encryptMessage(state, payloadFor(device, id, body, sentAt));
  return {
    state: sent.state,
    vector: {
      epoch: Number(state.groupContext.epoch),
      mlsMessageHex: b64ToHex(sent.ciphertext),
      plaintextUtf8: JSON.stringify(sent.payload),
      payload: sent.payload,
      canonicalBytesUtf8: new TextDecoder().decode(
        canonicalPayloadBytes(sent.payload),
      ),
      authenticatedDataHex: b64ToHex(sent.commitment),
    },
  };
}

/** Open a message the other side sent and check it is the one it says it is. */
async function expectMessage(
  state: Parameters<typeof receive>[0],
  mlsMessageHex: string,
  expected?: { body: string; userId: string },
) {
  const result = await receive(state, hexToB64(mlsMessageHex));
  assert(result.kind === "message", "expected an application message");
  if (expected) {
    assert(result.payload.body === expected.body, "plaintext mismatch");
    assert(result.payload.userId === expected.userId, "sender mismatch");
  }
  return result;
}
async function expectCommit(
  state: Parameters<typeof receive>[0],
  mlsMessageHex: string,
) {
  const result = await receive(state, hexToB64(mlsMessageHex));
  assert(result.kind === "change", "expected a commit");
  return result.state;
}

// Generate.

async function generate(out: string) {
  seedRandomness("hubs mls interop vectors v1");
  // ts-mls checks a key package's lifetime against Date.now when it adds one.
  Date.now = () => VECTOR_NOW_MS;
  const cs = await ciphersuite();
  const conversationId = "7f9a2c4e-1b3d-4e5f-8a6b-0c1d2e3f4a5b";
  const alice = await fixedDevice("u_alice", "device_alice_1", "alice");
  const bob = await fixedDevice("u_bob", "device_bob_1", "bob");

  // Key packages exactly as createKeyPackages makes them for upload.
  const [aliceKeyPackage] = await createKeyPackages(
    alice.keys,
    1,
    VECTOR_NOW_MS,
  );
  const [bobKeyPackage, bobSpareKeyPackage] = await createKeyPackages(
    bob.keys,
    2,
    VECTOR_NOW_MS,
  );

  // Alice starts the conversation and adds Bob's device (commit + welcome).
  let aliceState = await startGroup(alice.keys, conversationId, VECTOR_NOW_MS);
  const added = await changeDevices(aliceState, [bobKeyPackage.publicPackage]);
  aliceState = added.state;
  assert(added.welcome, "no welcome");
  const ratchetTree = encodeRatchetTree(aliceState.ratchetTree);

  // Bob joins with the TypeScript implementation too, so the vectors are
  // known to work there.
  let bobState = await joinFromWelcome(added.welcome, bobKeyPackage);
  assert(groupMembers(bobState).length === 2, "bob sees two members");

  const m1 = await messageVector(
    aliceState,
    alice.keys,
    "m_0001",
    "Meet at the north gate at six.",
    1760000000000,
  );
  aliceState = m1.state;
  bobState = (await expectMessage(bobState, m1.vector.mlsMessageHex)).state;

  // The weekly key refresh: a commit with no proposals, only an update path.
  const update = await changeDevices(aliceState, []);
  aliceState = update.state;
  bobState = await expectCommit(bobState, b64ToHex(update.commit));

  const m2 = await messageVector(
    aliceState,
    alice.keys,
    "m_0002",
    "Bring the blue folder. 🗂️ \"quoted\" and a\nnew line.",
    1760000060000,
  );
  aliceState = m2.state;
  bobState = (await expectMessage(bobState, m2.vector.mlsMessageHex)).state;

  const welcomeDecoded = decodeMlsMessage(fromBase64(added.welcome), 0)?.[0];
  assert(welcomeDecoded?.wireformat === "mls_welcome", "welcome wire format");

  // A key package that never expires (ts-mls defaultLifetime). Adders and
  // the server refuse it.
  const legacy = await generateKeyPackageWithKey(
    {
      credentialType: "basic",
      identity: new TextEncoder().encode(bob.vector.credentialIdentityUtf8),
    },
    defaultCapabilities(),
    defaultLifetime,
    [],
    {
      publicKey: fromBase64(bob.keys.publicKey),
      signKey: fromBase64(bob.keys.signKey),
    },
    cs,
  );
  const lifetime = keyPackageLifetime(VECTOR_NOW_MS);

  const vectors = {
    note: "MLS interop vectors made by the TypeScript implementation (ts-mls) with fixed keys and seeded randomness. Test keys only. Made by rust/hubs-mls/tests/mls-vectors.mts and read by the Rust interop tests. MLS bytes are complete MLSMessage encodings in hex (the wire carries the same bytes in base64).",
    generator: {
      tsMls: tsMlsVersion,
      ciphersuite: PRIVATE_DM_CIPHERSUITE,
      ciphersuiteId: 1,
      protocolVersion: "mls10",
      nowSeconds: VECTOR_NOW_MS / 1000,
    },
    settings: {
      credentialType: "basic",
      lifetime: {
        policy: "valid 90 days from an hour back; replaced after 30 days; an adder refuses one valid for longer than 90 days and an hour",
        lifetimeSeconds: PRIVATE_DM_KEY_PACKAGE_LIFETIME_SECONDS,
        refreshSeconds: PRIVATE_DM_KEY_PACKAGE_REFRESH_SECONDS,
        notBefore: String(lifetime.notBefore),
        notAfter: String(lifetime.notAfter),
      },
      keyPackageExtensions: [],
      leafNodeExtensions: [],
      groupContextExtensions: [],
      ratchetTreeInWelcome: true,
      handshakeWireFormat: "mls_private_message",
      padding: "pad the encrypted content to at least 256 bytes",
      keyRetention: { epochs: 4, generations: 10, maxForwardSteps: 200 },
    },
    conversationId,
    groupIdHex: hex(new TextEncoder().encode(conversationId)),
    alice: alice.vector,
    bob: bob.vector,
    aliceKeyPackage: keyPackageVector(aliceKeyPackage),
    bobKeyPackage: keyPackageVector(bobKeyPackage),
    bobSpareKeyPackage: keyPackageVector(bobSpareKeyPackage),
    /** Never expires (ts-mls defaultLifetime). Must be refused. */
    legacyKeyPackageHex: hex(
      fromBase64(encodeKeyPackageMessage(legacy.publicPackage)),
    ),
    addBob: {
      epochBefore: added.epoch,
      commitHex: b64ToHex(added.commit),
      welcomeHex: b64ToHex(added.welcome),
      ratchetTreeHex: hex(ratchetTree),
      epochAfter: added.epoch + 1,
    },
    message1: m1.vector,
    updateCommit: {
      epochBefore: update.epoch,
      commitHex: b64ToHex(update.commit),
      epochAfter: update.epoch + 1,
    },
    message2: m2.vector,
    /** Alice's ts-mls group state after message2 (ts-mls's own encoding), for `answer`. */
    aliceStateAfter: saveGroup(aliceState),
  };
  // A last self-check: the welcome decodes and encodes back to the same size.
  assert(
    encodeMlsMessage(welcomeDecoded).length === fromBase64(added.welcome).length,
    "welcome round trip",
  );
  writeFileSync(out, `${JSON.stringify(vectors, null, 2)}\n`);
  console.error(`wrote ${out} (${cs.name})`);
}

// Answer.

type Vectors = {
  alice: { userId: string };
  bob: { userId: string };
  aliceStateAfter: string;
  bobSpareKeyPackage: ReturnType<typeof keyPackageVector>;
};
type NativeMessage = { mlsMessageHex: string; plaintextBody?: string };
type NativeStep =
  | ({ kind: "message" } & NativeMessage)
  | { kind: "commit"; mlsMessageHex: string };

/**
 * Alice (ts-mls) opens what the native Bob sent after joining. With a
 * native key package, she then adds that device (the way a browser adds a
 * phone that just set up private conversations) and sends a message.
 */
async function answer(
  vectorsPath: string,
  repliesPath: string,
  keyPackagePath?: string,
  out?: string,
) {
  const vectors: Vectors = JSON.parse(readFileSync(vectorsPath, "utf8"));
  const replies: { steps: NativeStep[] } = JSON.parse(
    readFileSync(repliesPath, "utf8"),
  );
  let state = loadGroup(vectors.aliceStateAfter);
  for (const step of replies.steps) {
    if (step.kind === "commit") {
      state = await expectCommit(state, step.mlsMessageHex);
      console.log(`commit ok, now epoch ${state.groupContext.epoch}`);
    } else {
      const opened = await expectMessage(
        state,
        step.mlsMessageHex,
        step.plaintextBody !== undefined
          ? { body: step.plaintextBody, userId: vectors.bob.userId }
          : undefined,
      );
      state = opened.state;
      console.log(
        `message ok at epoch ${state.groupContext.epoch}: ${JSON.stringify(opened.payload.body)} (franking checked, sender ${opened.sender.userId}/${opened.sender.deviceId})`,
      );
    }
  }
  if (!keyPackagePath || !out) return;
  const native: { keyPackageHex: string } = JSON.parse(
    readFileSync(keyPackagePath, "utf8"),
  );
  const added = await changeDevices(state, [hexToB64(native.keyPackageHex)]);
  state = added.state;
  assert(added.welcome, "no welcome");
  console.log(
    `added the native key package, now epoch ${state.groupContext.epoch}; members: ${groupMembers(state).map((m) => `${m.userId}/${m.deviceId}`).join(", ")}`,
  );
  const alice = groupMembers(state).find(
    (m) => m.userId === vectors.alice.userId,
  );
  assert(alice, "alice is a member");
  const sent = await encryptMessage(
    state,
    payloadFor(
      { userId: alice.userId, deviceId: alice.deviceId } as DeviceKeys,
      "m_0003",
      "Welcome, new phone.",
      1760000360000,
    ),
  );
  writeFileSync(
    out,
    `${JSON.stringify(
      {
        commitHex: b64ToHex(added.commit),
        welcomeHex: b64ToHex(added.welcome),
        message: {
          mlsMessageHex: b64ToHex(sent.ciphertext),
          plaintextBody: sent.payload.body,
        },
      },
      null,
      2,
    )}\n`,
  );
  console.log(`wrote ${out}`);
}

// Join.

/** Bob (ts-mls) joins a group the native side made, then replies. */
async function join(vectorsPath: string, groupPath: string, out: string) {
  const vectors: Vectors = JSON.parse(readFileSync(vectorsPath, "utf8"));
  const group: {
    conversationId: string;
    welcomeHex: string;
    steps: NativeStep[];
  } = JSON.parse(readFileSync(groupPath, "utf8"));
  const bob = keyPackageFrom(vectors.bobSpareKeyPackage);
  let state = await joinFromWelcome(hexToB64(group.welcomeHex), bob);
  const conversation = new TextDecoder().decode(state.groupContext.groupId);
  assert(conversation === group.conversationId, "group id is the conversation id");
  const members = groupMembers(state);
  console.log(
    `joined at epoch ${state.groupContext.epoch}; members (certificates checked): ${members.map((m) => `${m.userId}/${m.deviceId}`).join(", ")}`,
  );
  for (const step of group.steps) {
    if (step.kind === "commit") {
      state = await expectCommit(state, step.mlsMessageHex);
      console.log(`commit ok, now epoch ${state.groupContext.epoch}`);
    } else {
      const opened = await expectMessage(state, step.mlsMessageHex);
      if (step.plaintextBody !== undefined)
        assert(opened.payload.body === step.plaintextBody, "plaintext mismatch");
      state = opened.state;
      console.log(
        `message ok at epoch ${state.groupContext.epoch}: ${JSON.stringify(opened.payload.body)} (franking checked, sender ${opened.sender.userId}/${opened.sender.deviceId})`,
      );
    }
  }
  // Reply: a message, the weekly update commit, and a message after it.
  const bobDevice = members.find((m) => m.userId === vectors.bob.userId);
  assert(bobDevice, "bob is a member");
  const device = {
    userId: bobDevice.userId,
    deviceId: bobDevice.deviceId,
  } as DeviceKeys;
  const steps: NativeStep[] = [];
  const r1 = await encryptMessage(
    state,
    payloadFor(device, "m_reply_1", "Got it, from ts-mls.", 1760000120000),
  );
  state = r1.state;
  steps.push({
    kind: "message",
    mlsMessageHex: b64ToHex(r1.ciphertext),
    plaintextBody: r1.payload.body,
  });
  const update = await changeDevices(state, []);
  state = update.state;
  steps.push({ kind: "commit", mlsMessageHex: b64ToHex(update.commit) });
  const r2 = await encryptMessage(
    state,
    payloadFor(device, "m_reply_2", "And after the update.", 1760000180000),
  );
  state = r2.state;
  steps.push({
    kind: "message",
    mlsMessageHex: b64ToHex(r2.ciphertext),
    plaintextBody: r2.payload.body,
  });
  writeFileSync(out, `${JSON.stringify({ steps }, null, 2)}\n`);
  console.log(`wrote ${out}`);
}

const [command, ...args] = process.argv.slice(2);
if (command === "generate" && args.length === 1) await generate(args[0]);
else if (command === "answer" && (args.length === 2 || args.length === 4))
  await answer(args[0], args[1], args[2], args[3]);
else if (command === "join" && args.length === 3) await join(args[0], args[1], args[2]);
else {
  console.error(
    "usage: mls-vectors.mts generate <out.json> | answer <vectors.json> <replies.json> [<key-package.json> <out.json>] | join <vectors.json> <group.json> <out.json>",
  );
  process.exit(2);
}
