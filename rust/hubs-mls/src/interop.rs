//! For the cross-platform vectors only: a group state saved by the
//! TypeScript implementation (ts-mls 1.6.4 `encodeGroupState`, what its
//! `saveGroup` keeps), read into this core's snapshot. With it, a native
//! test can replay the steps in the vectors as the TypeScript device itself
//! (`receiverStateHex` in `test-vectors/e2ee-test-vectors.json` at the root
//! of this repository). Apps never call it: a device only ever loads
//! snapshots it saved itself.
//!
//! Nothing here derives a new secret. The shared group state (the group
//! context, the ratchet tree, the confirmation tag), the device's private
//! path keys, its signing key and the epoch's secrets are copied from the
//! saved state into the snapshot form mls-rs 0.56.0 reads
//! (`group/snapshot.rs`). mls-rs then rebuilds its tree index and tree
//! hashes itself, and every check it runs on a received message or commit
//! runs as usual. The past epochs ts-mls keeps for late messages are left
//! out, so a message from before the imported epoch does not open.

use std::collections::BTreeMap;

use mls_rs::{
    group::{ExportedTree, GroupContext},
    mls_rs_codec::{MlsDecode, MlsEncode, VarInt},
    CipherSuiteProvider,
};

use crate::{
    error::{malformed, Result},
    hubs::signing_key,
    storage::wrap_snapshot,
    suite, CIPHER_SUITE,
};

/// The snapshot format version mls-rs 0.56.0 writes (`Snapshot::version`).
const MLS_RS_SNAPSHOT_VERSION: u16 = 1;

struct Reader<'a>(&'a [u8]);

impl<'a> Reader<'a> {
    fn take(&mut self, count: usize) -> Result<&'a [u8]> {
        if self.0.len() < count {
            return Err(malformed("the web state is cut short"));
        }
        let (head, rest) = self.0.split_at(count);
        self.0 = rest;
        Ok(head)
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().expect("4 bytes"),
        ))
    }
    /// A length-prefixed field (the MLS variable-length integer), with its prefix.
    fn field_with_prefix(&mut self) -> Result<&'a [u8]> {
        let start = self.0;
        let mut probe = self.0;
        let length = VarInt::mls_decode(&mut probe)
            .map_err(|_| malformed("a length in the web state is not valid"))?;
        let prefix = start.len() - probe.len();
        self.take(prefix + u32::from(length) as usize)
    }
    /// A length-prefixed field's contents.
    fn field(&mut self) -> Result<&'a [u8]> {
        let mut whole = self.field_with_prefix()?;
        VarInt::mls_decode(&mut whole).map_err(|_| malformed("a length is not valid"))?;
        Ok(whole)
    }
}

fn put_field(out: &mut Vec<u8>, bytes: &[u8]) -> Result<()> {
    VarInt::try_from(bytes.len())?.mls_encode(out)?;
    out.extend_from_slice(bytes);
    Ok(())
}

/// One ratchet (application or handshake) of a leaf in the secret tree.
struct Ratchet {
    secret: Vec<u8>,
    generation: u32,
    /// Generations skipped and kept for late messages: their secrets.
    unused: BTreeMap<u32, Vec<u8>>,
}

fn read_ratchet(reader: &mut Reader) -> Result<Ratchet> {
    let secret = reader.field()?.to_vec();
    let generation = reader.u32()?;
    let mut unused = BTreeMap::new();
    let mut entries = Reader(reader.field()?);
    while !entries.0.is_empty() {
        let at = entries.u32()?;
        unused.insert(at, entries.field()?.to_vec());
    }
    Ok(Ratchet {
        secret,
        generation,
        unused,
    })
}

/// RFC 9420 DeriveTreeSecret: ExpandWithLabel(secret, label, generation, length).
fn derive_tree_secret(
    secret: &[u8],
    label: &str,
    generation: u32,
    length: usize,
) -> Result<Vec<u8>> {
    let mut info = (length as u16).to_be_bytes().to_vec();
    put_field(&mut info, format!("MLS 1.0 {label}").as_bytes())?;
    put_field(&mut info, &generation.to_be_bytes())?;
    suite()
        .kdf_expand(secret, &info, length)
        .map(|bytes| bytes.to_vec())
        .map_err(|error| malformed(format!("expand: {error:?}")))
}

/// mls-rs `SecretKeyRatchet`: the secret, the next generation, then the
/// kept message keys (nonce, key, generation) of skipped generations.
fn encode_ratchet(out: &mut Vec<u8>, ratchet: &Ratchet) -> Result<()> {
    put_field(out, &ratchet.secret)?;
    out.extend_from_slice(&ratchet.generation.to_be_bytes());
    let mut kept = Vec::new();
    for (generation, secret) in &ratchet.unused {
        // AES-128-GCM: a 12-byte nonce and a 16-byte key.
        put_field(
            &mut kept,
            &derive_tree_secret(secret, "nonce", *generation, 12)?,
        )?;
        put_field(
            &mut kept,
            &derive_tree_secret(secret, "key", *generation, 16)?,
        )?;
        kept.extend_from_slice(&generation.to_be_bytes());
    }
    put_field(out, &kept)
}

/// RFC 9420 Appendix C: the parent of a node in a tree of `leaves` leaves.
fn parent(node: u32) -> u32 {
    let level = node.trailing_ones();
    let bit = (node >> (level + 1)) & 1;
    (node | (1 << level)) ^ (bit << (level + 1))
}

/// Read a group state saved by the TypeScript implementation and write this
/// core's snapshot of it, for `MlsDevice::load_group` (which then refuses it
/// unless it is this device's leaf and key).
pub fn import_web_group_state(state: &[u8]) -> Result<Vec<u8>> {
    let mut reader = Reader(state);

    // The group context, in its RFC 9420 encoding.
    let mut rest = reader.0;
    let context = GroupContext::mls_decode(&mut rest)
        .map_err(|_| malformed("the web state's group context is not valid"))?;
    let context_bytes = reader.take(reader.0.len() - rest.len())?;
    if context.mls_encode_to_vec()? != context_bytes {
        return Err(malformed("the group context does not read back the same"));
    }
    if context.cipher_suite != CIPHER_SUITE {
        return Err(malformed("not ciphersuite 1"));
    }

    // The key schedule: two old empty slots, then the epoch's secrets.
    let mut schedule = Vec::with_capacity(10);
    for _ in 0..10 {
        schedule.push(reader.field()?.to_vec());
    }
    let [_, sender_data_secret, _, exporter_secret, external_secret, _confirmation_key, membership_key, _resumption_psk, epoch_authenticator, init_secret] =
        <[Vec<u8>; 10]>::try_from(schedule).expect("ten secrets");

    // The secret tree: every node's handshake and application ratchets.
    let mut tree_nodes = Vec::new();
    let mut secret_tree = Reader(reader.field()?);
    while !secret_tree.0.is_empty() {
        let handshake = read_ratchet(&mut secret_tree)?;
        let application = read_ratchet(&mut secret_tree)?;
        tree_nodes.push((handshake, application));
    }

    // The ratchet tree, in its RFC 9420 encoding (the same bytes mls-rs
    // keeps as its node list).
    let tree_bytes = reader.field_with_prefix()?;
    let tree = ExportedTree::mls_decode(&mut &tree_bytes[..])
        .map_err(|_| malformed("the web state's ratchet tree is not valid"))?;
    let node_count = tree.nodes().len() as u32;
    let leaf_count = (node_count / 2 + 1).next_power_of_two();
    if tree_nodes.len() as u32 != 2 * leaf_count - 1 {
        return Err(malformed("the secret tree does not fit the ratchet tree"));
    }

    // This device's leaf and the private keys on its direct path.
    let leaf_index = reader.u32()?;
    let mut private_keys = BTreeMap::new();
    let mut keys = Reader(reader.field()?);
    while !keys.0.is_empty() {
        let node = keys.u32()?;
        private_keys.insert(node, keys.field()?.to_vec());
    }
    let signer = signing_key(reader.field()?)?;
    // Proposals waiting for a commit: none in a Hubs conversation.
    let proposals = reader.field()?;
    if !proposals.is_empty() {
        return Err(malformed("the web state holds proposals"));
    }
    let confirmation_tag = reader.field()?.to_vec();

    // The leaf must be inside the tree before the walk up to the root: a
    // leaf outside it would overflow `2 * leaf_index` or never reach the root.
    if leaf_index >= leaf_count {
        return Err(malformed("the web state's leaf is outside its tree"));
    }
    let root = leaf_count - 1;
    let mut path = vec![2 * leaf_index];
    while *path.last().expect("one node") != root {
        path.push(parent(*path.last().expect("one node")));
    }

    let mut snapshot = MLS_RS_SNAPSHOT_VERSION.to_be_bytes().to_vec();
    // RawGroupState: the context, then the tree with an empty index and no
    // cached hashes (mls-rs rebuilds both), the interim transcript hash, no
    // pending reinit, the confirmation tag.
    snapshot.extend_from_slice(context_bytes);
    snapshot.extend_from_slice(&[0, 0, 0, 0]);
    snapshot.extend_from_slice(tree_bytes);
    snapshot.push(0);
    let mut interim_input = context.confirmed_transcript_hash.to_vec();
    put_field(&mut interim_input, &confirmation_tag)?;
    let interim = suite()
        .hash(&interim_input)
        .map_err(|error| malformed(format!("hash: {error:?}")))?;
    put_field(&mut snapshot, &interim)?;
    snapshot.push(0);
    put_field(&mut snapshot, &confirmation_tag)?;
    // TreeKemPrivate: the leaf, then its key and each node's on the direct path.
    snapshot.extend_from_slice(&leaf_index.to_be_bytes());
    let mut secret_keys = Vec::new();
    for node in &path {
        match private_keys.get(node) {
            Some(key) => {
                secret_keys.push(1);
                put_field(&mut secret_keys, key)?;
            }
            None => secret_keys.push(0),
        }
    }
    put_field(&mut snapshot, &secret_keys)?;
    // EpochSecrets (no PSK feature): the sender data secret, then the
    // secret tree with every leaf as its two ratchets.
    put_field(&mut snapshot, &sender_data_secret)?;
    let mut known = Vec::new();
    for leaf in 0..leaf_count {
        let node = 2 * leaf;
        let (handshake, application) = &tree_nodes[node as usize];
        known.extend_from_slice(&node.to_be_bytes());
        known.push(1);
        encode_ratchet(&mut known, application)?;
        encode_ratchet(&mut known, handshake)?;
    }
    put_field(&mut snapshot, &known)?;
    snapshot.extend_from_slice(&leaf_count.to_be_bytes());
    // KeySchedule.
    for secret in [
        &exporter_secret,
        &epoch_authenticator,
        &external_secret,
        &membership_key,
        &init_secret,
    ] {
        put_field(&mut snapshot, secret)?;
    }
    // No pending commit, then the signer as the provider keeps it.
    snapshot.push(0);
    put_field(&mut snapshot, &signer.to_keypair_bytes())?;

    Ok(wrap_snapshot(&context.group_id, &snapshot))
}

#[cfg(test)]
mod tests {
    use super::parent;

    #[test]
    fn parents_follow_rfc_9420() {
        // Four leaves: nodes 0..6, root 3.
        assert_eq!(parent(0), 1);
        assert_eq!(parent(2), 1);
        assert_eq!(parent(1), 3);
        assert_eq!(parent(4), 5);
        assert_eq!(parent(5), 3);
        assert_eq!(parent(6), 5);
    }
}
