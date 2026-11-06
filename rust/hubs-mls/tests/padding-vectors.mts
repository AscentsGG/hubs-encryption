// Writes padding-vectors.json in this folder: the sizes ts-mls gives an
// encrypted application message for each content length, so the native core
// can check it pads the same way (the padding tests in src/device.rs). From
// the TypeScript package's folder, with its dependencies installed:
//
//   node --import tsx <this repository>/rust/hubs-mls/tests/padding-vectors.mts
//
// The group comes from the TypeScript implementation (its ciphersuite and
// clientConfig, so ts-mls defaultPaddingConfig). The content is raw bytes,
// not a Hubs payload, so every length can be tried. Test keys only.
import { writeFileSync } from "node:fs";
import { privateMessages, tsMls } from "./typescript-package.mts";

const { createApplicationMessage, defaultPaddingConfig, encodeMlsMessage } = tsMls;
const { ciphersuite, createDevice, createIdentity, startGroup } = privateMessages;

const lengths = [0, 1, 31, 32, 200, 255, 256, 257, 1000, 5000];
const groupId = "padding-vectors";
// Every message carries the 32-byte franking commitment as authenticated data.
const authenticatedData = new Uint8Array(32);
// The AEAD tag AES-128-GCM adds to the padded content.
const tagLength = 16;

if (
  defaultPaddingConfig.kind !== "padUntilLength" ||
  defaultPaddingConfig.padUntilLength !== 256
)
  throw new Error(`unexpected ts-mls padding: ${JSON.stringify(defaultPaddingConfig)}`);

const cs = await ciphersuite();
const device = await createDevice(await createIdentity(), "u_vectors", "d_vectors");
let state = await startGroup(device, groupId);
const cases = [];
for (const contentLength of lengths) {
  const result = await createApplicationMessage(
    state,
    new Uint8Array(contentLength).fill(0x61),
    cs,
    authenticatedData,
  );
  state = result.newState;
  const ciphertextLength = result.privateMessage.ciphertext.length;
  cases.push({
    contentLength,
    paddedContentLength: ciphertextLength - tagLength,
    ciphertextLength,
    mlsMessageLength: encodeMlsMessage({
      privateMessage: result.privateMessage,
      wireformat: "mls_private_message",
      version: "mls10",
    }).length,
  });
}

const out = new URL("./padding-vectors.json", import.meta.url);
writeFileSync(
  out,
  JSON.stringify(
    {
      generator: {
        script: "rust/hubs-mls/tests/padding-vectors.mts",
        tsMls: "1.6.4",
        paddingConfig: defaultPaddingConfig,
        groupId,
        epoch: 0,
        authenticatedDataLength: authenticatedData.length,
        note: "paddedContentLength is the encoded PrivateMessageContent (content, signature, zero padding); ciphertextLength adds the 16-byte AEAD tag; mlsMessageLength is the whole MLSMessage.",
      },
      cases,
    },
    null,
    2,
  ) + "\n",
);
console.log(JSON.stringify(cases));
