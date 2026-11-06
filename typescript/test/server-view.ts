import { createHash } from "node:crypto";
import { decodeMlsMessage } from "ts-mls";
import {
  PRIVATE_DM_CIPHERSUITE,
  fromBase64,
  keyPackageLifetimeOf,
} from "../src/index.js";

/*
 * Values the Hubs server computes from public bytes, written out here so
 * the vector tests can check them without the server's code. Neither touches
 * a key or any message content.
 */

/**
 * The franking commitment the server reads from a private message: its
 * authenticated data, which travels in the clear, when it is 32 bytes.
 */
export function commitmentOf(ciphertext: string): string | null {
  try {
    const decoded = decodeMlsMessage(fromBase64(ciphertext), 0)?.[0];
    if (
      decoded?.wireformat !== "mls_private_message" ||
      decoded.privateMessage.contentType !== "application"
    )
      return null;
    const data = decoded.privateMessage.authenticatedData;
    return data.length === 32 ? Buffer.from(data).toString("base64") : null;
  } catch {
    return null;
  }
}

/** The link code for a link public key: the same bytes as `linkCode`. */
export const linkCodeOf = (publicKey: string) =>
  createHash("sha256")
    .update(Buffer.from("hubs private dms link id v1\0"))
    .update(fromBase64(publicKey))
    .digest("hex")
    .slice(0, 12);

/**
 * A published key package's lifetime, or null when it is not a key package
 * for ciphersuite 1 from a key package leaf.
 */
export function publishedLifetimeOf(text: string) {
  try {
    const decoded = decodeMlsMessage(fromBase64(text), 0)?.[0];
    if (decoded?.wireformat !== "mls_key_package") return null;
    if (decoded.keyPackage.cipherSuite !== PRIVATE_DM_CIPHERSUITE) return null;
    return keyPackageLifetimeOf(decoded.keyPackage);
  } catch {
    return null;
  }
}
