// A live ts-mls peer for the native core's interop tests (live_ts_mls.rs in
// this folder). It runs the TypeScript implementation on ts-mls and answers
// one JSON request per line on stdin with one JSON line on stdout. Bytes are
// hex. From the TypeScript package's folder, with its dependencies
// installed:
//
//   node --import tsx <this repository>/rust/hubs-mls/tests/ts-mls-peer.mts
//
// Each participant has a name. A participant is one device (its own
// identity, or a second device of another participant's identity) and at
// most one conversation. Requests:
//
//   {op:"device", name, userId, deviceId, identityOf?, forgeWith?}
//   {op:"keyPackages", name, count, nowMs?}     -> {packages:[{id, hex}]}
//   {op:"start", name, conversationId}
//   {op:"change", name, add:[hex], removeLeaves:[n], note?} -> {commit, welcome, epoch}
//   {op:"proposal", name, removeLeaf}           -> {message} (a standalone proposal)
//   {op:"reinit", name}                         -> {commit} (a commit closing the group)
//   {op:"join", name, welcome, keyPackageId}
//   {op:"send", name, id, body, sentAt, kind?}  -> {ciphertext, commitment, payload}
//   {op:"receive", name, message}               -> {kind, payload?, sender?, epoch, members?, statement?}
//   {op:"header", name, message}                -> {header: {epoch, leafIndex, generation} | null}
//                                                  (packages with messageHeader only)
//   {op:"members", name}
//   {op:"canonical", payload}                   -> {hex, json}
//   {op:"lifetime", keyPackage}                 -> {notBefore, notAfter}
//
// Test keys only, made fresh for every run.
import { createInterface } from "node:readline";
// Type imports are removed when the script runs, so these names do not need
// to resolve from this folder.
import type {
  DeviceKeyPackage,
  DeviceKeys,
  IdentityKeys,
  PrivateDmPayload,
} from "@hubs/private-messages";
import type { ClientState } from "ts-mls";
import { privateMessages, tsMls } from "./typescript-package.mts";

const {
  createCommit,
  createProposal,
  decodeMlsMessage,
  encodeMlsMessage,
  getCiphersuiteFromName,
  getCiphersuiteImpl,
} = tsMls;
const {
  canonicalPayloadBytes,
  changeDevices,
  ciphersuite,
  createDevice,
  createIdentity,
  createKeyPackages,
  encryptMessage,
  fromBase64,
  groupMembers,
  joinFromWelcome,
  receive,
  startGroup,
  toBase64,
} = privateMessages;

const hex = (bytes: Uint8Array) => Buffer.from(bytes).toString("hex");
const unhex = (text: string) => new Uint8Array(Buffer.from(text, "hex"));
const b64ToHex = (text: string) => hex(fromBase64(text));
const hexToB64 = (text: string) => toBase64(unhex(text));

type Participant = {
  identity: IdentityKeys;
  device: DeviceKeys;
  keyPackages: Map<string, DeviceKeyPackage>;
  state?: ClientState;
};
const people = new Map<string, Participant>();
const who = (name: string) => {
  const found = people.get(name);
  if (!found) throw new Error(`no participant ${name}`);
  return found;
};
const group = (name: string) => {
  const state = who(name).state;
  if (!state) throw new Error(`${name} has no conversation`);
  return state;
};
const memberList = (state: ClientState) =>
  groupMembers(state).map((m) => ({
    leafIndex: m.leafIndex,
    userId: m.userId,
    deviceId: m.deviceId,
  }));
const epochOf = (state: ClientState) => Number(state.groupContext.epoch);

async function handle(request: any): Promise<object> {
  switch (request.op) {
    case "device": {
      const identity = request.identityOf
        ? who(request.identityOf).identity
        : await createIdentity();
      let device = await createDevice(identity, request.userId, request.deviceId);
      if (request.forgeWith) {
        // A device certificate signed by someone else's identity key while
        // the credential names this identity, as a forger would send.
        const forger = await createDevice(
          await createIdentity(),
          request.userId,
          request.deviceId,
        );
        device = { ...forger, identityPublicKey: identity.publicKey };
      }
      people.set(request.name, { identity, device, keyPackages: new Map() });
      return {
        identityPublicKey: b64ToHex(identity.publicKey),
        devicePublicKey: b64ToHex(device.publicKey),
      };
    }
    case "keyPackages": {
      const person = who(request.name);
      const realNow = Date.now;
      if (request.nowMs !== undefined) Date.now = () => request.nowMs;
      try {
        const made = await createKeyPackages(person.device, request.count);
        for (const item of made) person.keyPackages.set(item.id, item);
        return {
          packages: made.map((item) => ({
            id: item.id,
            hex: b64ToHex(item.publicPackage),
          })),
        };
      } finally {
        Date.now = realNow;
      }
    }
    case "start": {
      const person = who(request.name);
      person.state = await startGroup(person.device, request.conversationId);
      return { epoch: epochOf(person.state) };
    }
    case "change": {
      const person = who(request.name);
      const result = await changeDevices(
        group(request.name),
        (request.add ?? []).map(hexToB64),
        request.removeLeaves ?? [],
        request.note ? unhex(request.note) : undefined,
      );
      person.state = result.state;
      return {
        commit: b64ToHex(result.commit),
        welcome: result.welcome ? b64ToHex(result.welcome) : null,
        epoch: result.epoch,
        members: memberList(result.state),
      };
    }
    case "proposal": {
      const cs = await getCiphersuiteImpl(
        getCiphersuiteFromName("MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"),
      );
      const made = await createProposal(
        group(request.name),
        false,
        { proposalType: "remove", remove: { removed: request.removeLeaf } },
        cs,
        new Uint8Array(32),
      );
      return { message: hex(encodeMlsMessage(made.message)) };
    }
    case "reinit": {
      const state = group(request.name);
      const cs = await getCiphersuiteImpl(
        getCiphersuiteFromName("MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519"),
      );
      const made = await createCommit(
        { state, cipherSuite: cs },
        {
          ratchetTreeExtension: true,
          extraProposals: [
            {
              proposalType: "reinit",
              reinit: {
                groupId: new Uint8Array(32).fill(9),
                version: state.groupContext.version,
                cipherSuite: state.groupContext.cipherSuite,
                extensions: [],
              },
            },
          ],
        },
      );
      return { commit: hex(encodeMlsMessage(made.commit)) };
    }
    case "join": {
      const person = who(request.name);
      const keyPackage = person.keyPackages.get(request.keyPackageId);
      if (!keyPackage) throw new Error("unknown key package");
      person.state = await joinFromWelcome(hexToB64(request.welcome), keyPackage);
      person.keyPackages.delete(request.keyPackageId);
      return {
        conversationId: new TextDecoder().decode(person.state.groupContext.groupId),
        epoch: epochOf(person.state),
        members: memberList(person.state),
      };
    }
    case "send": {
      const person = who(request.name);
      const sent = await encryptMessage(group(request.name), {
        v: 1,
        id: request.id,
        kind: request.kind ?? "text",
        body: request.body,
        sentAt: request.sentAt,
        expiresInSeconds: request.expiresInSeconds ?? 604800,
        userId: person.device.userId,
        deviceId: person.device.deviceId,
      });
      person.state = sent.state;
      return {
        ciphertext: b64ToHex(sent.ciphertext),
        commitment: b64ToHex(sent.commitment),
        payload: sent.payload,
        epoch: epochOf(sent.state),
      };
    }
    case "receive": {
      const person = who(request.name);
      const result = await receive(group(request.name), hexToB64(request.message));
      person.state = result.state;
      if (result.kind === "change")
        return {
          kind: "change",
          epoch: epochOf(result.state),
          members: memberList(result.state),
          statement: result.removalStatement
            ? hex(result.removalStatement)
            : null,
        };
      return {
        kind: "message",
        payload: result.payload,
        commitment: b64ToHex(result.commitment),
        sender: { userId: result.sender.userId, deviceId: result.sender.deviceId },
        epoch: epochOf(result.state),
      };
    }
    case "header": {
      if (typeof privateMessages.messageHeader !== "function")
        throw new Error("this package has no messageHeader");
      return {
        header: await privateMessages.messageHeader(
          group(request.name),
          hexToB64(request.message),
        ),
      };
    }
    case "members":
      return { members: memberList(group(request.name)), epoch: epochOf(group(request.name)) };
    case "canonical": {
      // Built in the same key order the TypeScript client uses when it
      // sends, then the franking key.
      const p = request.payload;
      const payload: PrivateDmPayload = {
        v: 1,
        id: p.id,
        kind: p.kind,
        body: p.body,
        sentAt: p.sentAt,
        expiresInSeconds: p.expiresInSeconds,
        userId: p.userId,
        deviceId: p.deviceId,
        frankingKey: p.frankingKey,
      };
      return {
        hex: hex(canonicalPayloadBytes(payload)),
        json: JSON.stringify(payload),
      };
    }
    case "lifetime": {
      const decoded = decodeMlsMessage(unhex(request.keyPackage), 0)?.[0];
      if (decoded?.wireformat !== "mls_key_package")
        throw new Error("not a key package");
      const lifetime = decoded.keyPackage.leafNode.lifetime;
      if (!lifetime) throw new Error("no lifetime");
      return {
        notBefore: String(lifetime.notBefore),
        notAfter: String(lifetime.notAfter),
      };
    }
    default:
      throw new Error(`unknown op ${request.op}`);
  }
}

await ciphersuite();
process.stdout.write(`${JSON.stringify({ ready: true })}\n`);
const lines = createInterface({ input: process.stdin });
for await (const line of lines) {
  if (!line.trim()) continue;
  let reply: object;
  try {
    reply = { ok: true, ...(await handle(JSON.parse(line))) };
  } catch (error) {
    reply = { ok: false, error: error instanceof Error ? error.message : String(error) };
  }
  process.stdout.write(`${JSON.stringify(reply)}\n`);
}
