//! One device's MLS client and its conversations, following the engine of
//! the TypeScript implementation: key packages, starting a group, adding and
//! removing devices (a commit stays pending until the server accepts it),
//! joining from a welcome, encrypting with the franking commitment, and
//! receiving.

use std::{
    sync::{Arc, Mutex, MutexGuard},
    time::Duration,
};

use mls_rs::{
    client_builder::{
        BaseConfig, PaddingMode, WithCryptoProvider, WithGroupStateStorage, WithIdentityProvider,
        WithKeyPackageRepo, WithMlsRules,
    },
    crypto::{SignaturePublicKey, SignatureSecretKey},
    group::{CommitEffect, ReceivedMessage},
    identity::{basic::BasicCredential, SigningIdentity},
    mls_rs_codec::{MlsDecode, MlsEncode},
    mls_rules::{CommitOptions, DefaultMlsRules, EncryptionOptions},
    storage_provider::in_memory::InMemoryKeyPackageStorage,
    time::MlsTime,
    Client, ExtensionList, Group, MlsMessage, WireFormat,
};
use mls_rs_core::{crypto::HpkeSecretKey, key_package::KeyPackageData};
use mls_rs_crypto_rustcrypto::RustCryptoProvider;
use zeroize::Zeroizing;

use crate::{
    error::{malformed, HubsMlsError, Result},
    hubs::{
        check_outgoing, credential_identity, franking_commitment, parse_payload, payload_json,
        pkcs8, random_bytes, random_id, signing_key, verify_device_certificate, DeviceCredential,
        MessageDraft, MessagePayload,
    },
    identity::HubsIdentity,
    policy::{
        check_key_package, identity_info, not_before_for, KeyPackageInfo,
        KEY_PACKAGE_CLOCK_SKEW_SECONDS, KEY_PACKAGE_LIFETIME_SECONDS,
    },
    removal::read_signed_removals_note,
    storage::SnapshotStore,
    suite, CIPHER_SUITE,
};

type HubsConfig = WithMlsRules<
    DefaultMlsRules,
    WithGroupStateStorage<
        SnapshotStore,
        WithKeyPackageRepo<
            InMemoryKeyPackageStorage,
            WithIdentityProvider<HubsIdentity, WithCryptoProvider<RustCryptoProvider, BaseConfig>>,
        >,
    >,
>;

/// The account identity key. It lives only on the person's devices and in
/// their passkey backup.
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct IdentityKeys {
    /// Raw Ed25519 public key, 32 bytes.
    pub public_key: Vec<u8>,
    /// PKCS#8 (48 bytes), the form the website stores. A 32-byte seed also
    /// works.
    pub signing_key: Vec<u8>,
}

/// One device's keys and its certificate from the account identity key.
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct DeviceKeys {
    pub user_id: String,
    pub device_id: String,
    pub identity_public_key: Vec<u8>,
    pub device_public_key: Vec<u8>,
    /// PKCS#8 (48 bytes) or a 32-byte seed.
    pub device_signing_key: Vec<u8>,
    pub certificate: Vec<u8>,
}

/// Keys never reach a log or a crash report through `Debug`.
impl std::fmt::Debug for IdentityKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("IdentityKeys").finish_non_exhaustive()
    }
}

impl std::fmt::Debug for DeviceKeys {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceKeys")
            .field("user_id", &self.user_id)
            .field("device_id", &self.device_id)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Debug for DeviceKeyPackage {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DeviceKeyPackage")
            .field("id", &self.id)
            .finish_non_exhaustive()
    }
}

/// A key package ready to upload, and the private half that stays on the
/// device (as `DeviceKeyPackage` on the web).
#[derive(Clone, PartialEq, Eq, uniffi::Record)]
pub struct DeviceKeyPackage {
    /// The id the server knows it by: 12 random bytes, base64url.
    pub id: String,
    /// The complete MLSMessage to upload (base64 on the wire).
    pub public_package: Vec<u8>,
    /// Secret: the init and leaf private keys. Keep it in the encrypted store.
    pub private_package: Vec<u8>,
    pub created_at: u64,
    pub not_after: u64,
}

/// A member of a conversation, as its certificate says.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct GroupMember {
    pub leaf_index: u32,
    pub user_id: String,
    pub device_id: String,
    pub identity_public_key: Vec<u8>,
    pub device_public_key: Vec<u8>,
}

/// A commit made here, waiting for the server. Merge it once the server
/// accepts it (`merge_pending_commit`). Clear it when the server answers
/// `EPOCH_CHANGED`, which means another commit for that epoch got there
/// first.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct PendingChange {
    /// The MLS private message for the devices already in the conversation.
    pub commit: Vec<u8>,
    /// One welcome for every device added, or none.
    pub welcome: Option<Vec<u8>>,
    /// The epoch before the commit: the server's compare-and-swap value.
    pub epoch: u64,
    /// The devices being added, as their key packages say.
    pub added: Vec<KeyPackageInfo>,
    pub removed_leaves: Vec<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct EncryptedMessage {
    /// The MLS private message (base64 on the wire).
    pub ciphertext: Vec<u8>,
    /// The franking commitment, also the message's authenticated data.
    pub commitment: Vec<u8>,
    pub payload: MessagePayload,
    pub epoch: u64,
}

/// Where an application message sits, read from its sender data: its
/// epoch, the sender's leaf, and its generation (its place in that leaf's
/// application ratchet for the epoch, counting from 0).
#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Record)]
pub struct MessageHeader {
    pub epoch: u64,
    pub sender_leaf_index: u32,
    pub generation: u32,
}

// A message is the common case; boxing it would only add an allocation.
#[allow(clippy::large_enum_variant)]
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum Incoming {
    /// A message, its franking commitment checked and its sender matched.
    Message {
        payload: MessagePayload,
        commitment: Vec<u8>,
        sender: GroupMember,
        epoch: u64,
    },
    /// A commit moved the conversation to a new epoch. Check the members
    /// before saving; to refuse, drop this group and load the last snapshot.
    Change {
        members: Vec<GroupMember>,
        committer: u32,
        /// The committer as the group showed it before this commit.
        committer_member: Option<GroupMember>,
        /// The signature from a signed removals note in this commit, unverified.
        removal_statement: Option<Vec<u8>>,
        epoch: u64,
    },
    /// A commit removed this device.
    Removed { epoch: u64 },
}

fn rules() -> DefaultMlsRules {
    DefaultMlsRules::new()
        .with_commit_options(
            CommitOptions::new()
                // The ratchet tree travels in the welcome; the server never needs it.
                .with_ratchet_tree_extension(true)
                // Every commit refreshes the committer's keys.
                .with_path_required(true)
                .with_single_welcome_message(true),
        )
        // Commits are private messages too; the server refuses plaintext.
        // Every private message's content is padded the way ts-mls pads by
        // default: up to 256 bytes, and not at all above that. PadUntil256
        // comes from the vendored mls-rs (see vendor/mls-rs/CHANGES.md).
        .with_encryption_options(EncryptionOptions::new(true, PaddingMode::PadUntil256))
}

fn member(identity: &SigningIdentity, leaf_index: u32) -> Result<GroupMember> {
    let info = identity_info(identity)?;
    Ok(GroupMember {
        leaf_index,
        user_id: info.user_id,
        device_id: info.device_id,
        identity_public_key: info.identity_public_key,
        device_public_key: info.device_public_key,
    })
}

fn members_of(group: &Group<HubsConfig>) -> Vec<GroupMember> {
    group
        .roster()
        .members()
        .iter()
        .filter_map(|m| member(&m.signing_identity, m.index).ok())
        .collect()
}

#[derive(uniffi::Object)]
pub struct MlsDevice {
    keys: DeviceKeys,
    client: Client<HubsConfig>,
    key_packages: InMemoryKeyPackageStorage,
    groups: SnapshotStore,
}

impl std::fmt::Debug for MlsDevice {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MlsDevice")
            .field("user_id", &self.keys.user_id)
            .field("device_id", &self.keys.device_id)
            .finish_non_exhaustive()
    }
}

#[uniffi::export]
impl MlsDevice {
    /// A device from its keys. Refuses keys whose public half or certificate
    /// does not match.
    #[uniffi::constructor]
    pub fn new(keys: DeviceKeys) -> Result<Arc<Self>> {
        let signer = signing_key(&keys.device_signing_key)?;
        if signer.verifying_key().as_bytes() != keys.device_public_key.as_slice() {
            return Err(malformed("the device key does not match its public key"));
        }
        let credential = DeviceCredential {
            user_id: keys.user_id.clone(),
            device_id: keys.device_id.clone(),
            identity_public_key: keys.identity_public_key.clone(),
            certificate: keys.certificate.clone(),
        };
        if !verify_device_certificate(&credential, &keys.device_public_key) {
            return Err(HubsMlsError::Credential {
                reason: "the device certificate does not verify".into(),
            });
        }
        let identity = SigningIdentity::new(
            BasicCredential::new(credential_identity(&credential)).into_credential(),
            SignaturePublicKey::from(keys.device_public_key.clone()),
        );
        let key_packages = InMemoryKeyPackageStorage::new();
        let groups = SnapshotStore::default();
        let client = Client::builder()
            .crypto_provider(RustCryptoProvider::with_enabled_cipher_suites(vec![
                CIPHER_SUITE,
            ]))
            .identity_provider(HubsIdentity)
            .key_package_repo(key_packages.clone())
            .group_state_storage(groups.clone())
            .mls_rules(rules())
            .signing_identity(
                identity,
                SignatureSecretKey::new(signer.to_keypair_bytes().to_vec()),
                CIPHER_SUITE,
            )
            // Made with notBefore = now - 1 hour, so this lands notAfter at now + 90 days.
            .key_package_lifetime(Duration::from_secs(
                KEY_PACKAGE_LIFETIME_SECONDS + KEY_PACKAGE_CLOCK_SKEW_SECONDS,
            ))
            .build();
        Ok(Arc::new(Self {
            keys: DeviceKeys {
                device_signing_key: pkcs8(&signer),
                ..keys
            },
            client,
            key_packages,
            groups,
        }))
    }

    pub fn user_id(&self) -> String {
        self.keys.user_id.clone()
    }

    pub fn device_id(&self) -> String {
        self.keys.device_id.clone()
    }

    /// One-time key packages other devices use to add this one, valid for
    /// 90 days from `now`.
    pub fn create_key_packages(
        &self,
        count: u32,
        now_seconds: u64,
    ) -> Result<Vec<DeviceKeyPackage>> {
        let mut made = Vec::with_capacity(count as usize);
        for _ in 0..count {
            let message = self.client.generate_key_package_message(
                ExtensionList::new(),
                ExtensionList::new(),
                Some(MlsTime::from(not_before_for(now_seconds))),
            )?;
            let key_package = message
                .clone()
                .into_key_package()
                .ok_or_else(|| malformed("not a key package"))?;
            let reference = key_package.to_reference(&suite())?;
            let data = self
                .key_packages
                .get(&reference)
                .ok_or_else(|| malformed("the key package's private half went missing"))?;
            // The app keeps the private half; the core forgets it.
            self.key_packages.delete(&reference);
            made.push(DeviceKeyPackage {
                id: random_id(12)?,
                public_package: message.to_bytes()?,
                private_package: data.mls_encode_to_vec()?,
                created_at: now_seconds,
                not_after: key_package.expiration()?.seconds_since_epoch(),
            });
        }
        Ok(made)
    }

    /// Start a conversation as its only member. The group id is the
    /// conversation id's UTF-8 bytes.
    pub fn start_group(&self, conversation_id: String, now_seconds: u64) -> Result<Arc<MlsGroup>> {
        let group = self
            .client
            .group_builder()?
            .with_group_id(conversation_id.into_bytes())
            .with_now_time(MlsTime::from(not_before_for(now_seconds)))
            .build()?;
        Ok(self.wrap(group))
    }

    /// Join a conversation from a welcome addressed to one of this device's
    /// key packages, and check the group is that conversation.
    pub fn join_from_welcome(
        &self,
        welcome: Vec<u8>,
        key_package: DeviceKeyPackage,
        conversation_id: String,
    ) -> Result<Arc<MlsGroup>> {
        let welcome = MlsMessage::from_bytes(&welcome)?;
        if welcome.wire_format() != WireFormat::Welcome {
            return Err(malformed("not a welcome"));
        }
        let public = MlsMessage::from_bytes(&key_package.public_package)?
            .into_key_package()
            .ok_or_else(|| malformed("not a key package"))?;
        let data = KeyPackageData::mls_decode(&mut key_package.private_package.as_slice())?;
        if data.key_package_bytes != public.mls_encode_to_vec()? {
            return Err(malformed("the private half belongs to another key package"));
        }
        let reference = public.to_reference(&suite())?.to_vec();
        self.key_packages.insert(reference.clone(), data);
        // No time: the lifetimes of members already in the tree are not
        // checked on join, matching ts-mls. Otherwise one device that has
        // been offline for 90 days would stop any new device from joining.
        let joined = self.client.join_group(None, &welcome, None);
        self.key_packages.delete(&reference);
        let (group, _) = joined?;
        if group.group_id() != conversation_id.as_bytes() {
            // A join writes nothing to the store, so there is nothing to undo.
            return Err(HubsMlsError::WrongConversation);
        }
        // A new start: nothing from an earlier group of this conversation
        // on this device (its past epochs) carries over.
        self.groups.remove(group.group_id());
        Ok(self.wrap(group))
    }

    /// A conversation from the snapshot the app saved.
    pub fn load_group(&self, snapshot: Vec<u8>) -> Result<Arc<MlsGroup>> {
        let group_id = self.groups.import(&snapshot)?;
        let group = self.client.load_group(&group_id);
        let group = match group {
            Ok(group) => group,
            Err(error) => {
                self.groups.remove(&group_id);
                return Err(error.into());
            }
        };
        let own = group
            .member_at_index(group.current_member_index())
            .ok_or(HubsMlsError::WrongDevice)?;
        if own.signing_identity.signature_key.as_ref() != self.keys.device_public_key.as_slice() {
            self.groups.remove(&group_id);
            return Err(HubsMlsError::WrongDevice);
        }
        // Past epochs must run up to this one. Records that do not (an
        // earlier group of this conversation, saved before the join cleared
        // them) block every later commit, so they go.
        self.groups
            .drop_stale_epochs(&group_id, group.current_epoch());
        Ok(self.wrap(group))
    }
}

impl MlsDevice {
    fn wrap(&self, group: Group<HubsConfig>) -> Arc<MlsGroup> {
        Arc::new(MlsGroup {
            group: Mutex::new(group),
            groups: self.groups.clone(),
            user_id: self.keys.user_id.clone(),
            device_id: self.keys.device_id.clone(),
        })
    }
}

/// One conversation's MLS group on this device.
#[derive(uniffi::Object)]
pub struct MlsGroup {
    group: Mutex<Group<HubsConfig>>,
    groups: SnapshotStore,
    user_id: String,
    device_id: String,
}

impl std::fmt::Debug for MlsGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("MlsGroup").finish_non_exhaustive()
    }
}

impl MlsGroup {
    fn lock(&self) -> MutexGuard<'_, Group<HubsConfig>> {
        self.group
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[uniffi::export]
impl MlsGroup {
    pub fn conversation_id(&self) -> String {
        String::from_utf8_lossy(self.lock().group_id()).into_owned()
    }

    pub fn epoch(&self) -> u64 {
        self.lock().current_epoch()
    }

    pub fn own_leaf_index(&self) -> u32 {
        self.lock().current_member_index()
    }

    /// The epoch authenticator (RFC 9420, section 8.7): the same on every
    /// member's device at one epoch. For diagnostics and the interop checks.
    pub fn epoch_authenticator(&self) -> Result<Vec<u8>> {
        Ok(self.lock().epoch_authenticator()?.as_bytes().to_vec())
    }

    /// The people and devices in the conversation, as their certificates say.
    pub fn members(&self) -> Vec<GroupMember> {
        members_of(&self.lock())
    }

    /// Add and remove devices in one commit (`changeDevices`). With nothing
    /// to add or remove, it is the weekly key refresh: a commit with only an
    /// update path. Each key package must pass the Hubs checks and the
    /// lifetime policy at `now` (valid now, at most 90 days long); nothing
    /// is staged when one fails. `note` (see `signed_removals_note`) goes in
    /// the commit's authenticated data. The commit stays pending.
    pub fn change_devices(
        &self,
        add: Vec<Vec<u8>>,
        remove_leaves: Vec<u32>,
        now_seconds: u64,
        note: Option<Vec<u8>>,
    ) -> Result<PendingChange> {
        let mut group = self.lock();
        if group.has_pending_commit() {
            return Err(HubsMlsError::PendingCommit {
                reason: "a commit is already waiting for the server".into(),
            });
        }
        let epoch = group.current_epoch();
        let mut added = Vec::with_capacity(add.len());
        let mut builder = group
            .commit_builder()
            .commit_time(MlsTime::from(now_seconds));
        if let Some(note) = note {
            builder = builder.authenticated_data(note);
        }
        for key_package in add {
            added.push(check_key_package(key_package.clone(), now_seconds)?);
            builder = builder.add_member(MlsMessage::from_bytes(&key_package)?)?;
        }
        for leaf in &remove_leaves {
            builder = builder.remove_member(*leaf)?;
        }
        let output = builder.build()?;
        Ok(PendingChange {
            commit: output.commit_message.to_bytes()?,
            welcome: match output.welcome_messages.first() {
                Some(welcome) => Some(welcome.to_bytes()?),
                None => None,
            },
            epoch,
            added,
            removed_leaves: remove_leaves,
        })
    }

    pub fn has_pending_commit(&self) -> bool {
        self.lock().has_pending_commit()
    }

    /// The server accepted the commit: move to the new epoch.
    pub fn merge_pending_commit(&self) -> Result<Vec<GroupMember>> {
        let mut group = self.lock();
        if !group.has_pending_commit() {
            return Err(HubsMlsError::PendingCommit {
                reason: "no commit is waiting".into(),
            });
        }
        group.apply_pending_commit()?;
        Ok(members_of(&group))
    }

    /// The server refused the commit (`EPOCH_CHANGED`): forget it.
    pub fn clear_pending_commit(&self) {
        self.lock().clear_pending_commit();
    }

    /// Encrypt one message for everyone in the conversation, with a fresh
    /// franking key and its commitment as the authenticated data. Save the
    /// snapshot before sending, so a failed send never reuses a message key.
    pub fn encrypt_message(&self, draft: MessageDraft) -> Result<EncryptedMessage> {
        let payload = MessagePayload {
            id: draft.id,
            kind: draft.kind,
            body: draft.body,
            sent_at: draft.sent_at,
            expires_in_seconds: draft.expires_in_seconds,
            user_id: self.user_id.clone(),
            device_id: self.device_id.clone(),
            franking_key: random_bytes(32)?,
        };
        // Nothing goes out that a receiver would refuse.
        check_outgoing(&payload)?;
        let commitment = franking_commitment(&payload.franking_key, &payload)?;
        let plaintext = Zeroizing::new(payload_json(&payload));
        let mut group = self.lock();
        let message = group.encrypt_application_message(&plaintext, commitment.clone())?;
        Ok(EncryptedMessage {
            ciphertext: message.to_bytes()?,
            commitment,
            payload,
            epoch: group.current_epoch(),
        })
    }

    /// Decrypt a message or apply a commit. Plaintext MLS messages are
    /// refused; a message whose commitment does not match its contents, or
    /// that names another device than its MLS sender, is refused. On any
    /// error the group stays as it was before the call.
    pub fn receive(&self, message: Vec<u8>) -> Result<Incoming> {
        let message = MlsMessage::from_bytes(&message)?;
        if message.wire_format() != WireFormat::PrivateMessage {
            return Err(HubsMlsError::NotEncrypted);
        }
        let mut group = self.lock();
        let before = group.clone();
        let result = Self::process(&mut group, message);
        match &result {
            Err(_) => *group = before,
            // Nothing of this group is of use any more.
            Ok(Incoming::Removed { .. }) => self.groups.remove(group.group_id()),
            Ok(_) => {}
        }
        result
    }

    /// The epoch, sender leaf and generation of an application message,
    /// read from its sender data without opening the content (the web's
    /// `messageHeader`), for the missing message rule. Read it before
    /// `receive`, so a message that then fails to open still counts.
    ///
    /// `None` for a commit, for bytes that are not a private message of
    /// this conversation, and for an epoch this device does not hold (not
    /// reached yet, or older than the retained ones). Only the sender
    /// data's own encryption is checked, not the sender's signature: use it
    /// to count messages, never to say who sent one. The group does not
    /// change.
    pub fn message_header(&self, message: Vec<u8>) -> Option<MessageHeader> {
        let message = MlsMessage::from_bytes(&message).ok()?;
        if message.wire_format() != WireFormat::PrivateMessage {
            return None;
        }
        let epoch = message.epoch()?;
        let mut group = {
            let group = self.lock();
            if message.group_id()? != group.group_id() {
                return None;
            }
            // A copy, so loading a retained epoch leaves no trace in the group.
            group.clone()
        };
        let (sender_leaf_index, generation) = group.application_sender_data(&message).ok()??;
        Some(MessageHeader {
            epoch,
            sender_leaf_index,
            generation,
        })
    }

    /// The conversation's state for the app's encrypted store.
    pub fn snapshot(&self) -> Result<Vec<u8>> {
        let mut group = self.lock();
        group.write_to_storage()?;
        self.groups
            .export(group.group_id())
            .map(|bytes| bytes.to_vec())
            .ok_or_else(|| malformed("nothing saved for this conversation"))
    }
}

impl MlsGroup {
    fn process(group: &mut Group<HubsConfig>, message: MlsMessage) -> Result<Incoming> {
        let before = members_of(group);
        match group.process_incoming_message(message)? {
            ReceivedMessage::ApplicationMessage(application) => {
                let payload = parse_payload(application.data())?;
                let expected = franking_commitment(&payload.franking_key, &payload)?;
                if expected != application.authenticated_data {
                    return Err(HubsMlsError::FrankingMismatch);
                }
                let sender = before
                    .into_iter()
                    .find(|m| m.leaf_index == application.sender_index)
                    .ok_or(HubsMlsError::SenderMismatch)?;
                if sender.user_id != payload.user_id || sender.device_id != payload.device_id {
                    return Err(HubsMlsError::SenderMismatch);
                }
                Ok(Incoming::Message {
                    payload,
                    commitment: application.authenticated_data,
                    sender,
                    epoch: group.current_epoch(),
                })
            }
            ReceivedMessage::Commit(commit) => match commit.effect {
                CommitEffect::NewEpoch(_) => Ok(Incoming::Change {
                    members: members_of(group),
                    committer: commit.committer,
                    committer_member: before
                        .into_iter()
                        .find(|m| m.leaf_index == commit.committer),
                    removal_statement: read_signed_removals_note(commit.authenticated_data),
                    epoch: group.current_epoch(),
                }),
                CommitEffect::Removed { .. } => Ok(Incoming::Removed {
                    epoch: group.current_epoch(),
                }),
                CommitEffect::ReInit(_) => {
                    Err(malformed("reinitializing a conversation is not supported"))
                }
            },
            _ => Err(malformed("only messages and commits are accepted")),
        }
    }
}

/// A key package made by another implementation (ts-mls, in the interop
/// vectors), with its init and leaf (encryption) private keys, so this
/// device can join from a welcome addressed to it. The signing key is the
/// device's own.
#[uniffi::export]
pub fn import_key_package(
    id: String,
    public_package: Vec<u8>,
    init_private_key: Vec<u8>,
    encryption_private_key: Vec<u8>,
    created_at: u64,
) -> Result<DeviceKeyPackage> {
    let key_package = MlsMessage::from_bytes(&public_package)?
        .into_key_package()
        .ok_or_else(|| malformed("not a key package"))?;
    let not_after = key_package.expiration()?.seconds_since_epoch();
    let data = KeyPackageData::new(
        key_package.mls_encode_to_vec()?,
        HpkeSecretKey::from(init_private_key),
        HpkeSecretKey::from(encryption_private_key),
        not_after,
    );
    Ok(DeviceKeyPackage {
        id,
        public_package,
        private_package: data.mls_encode_to_vec()?,
        created_at,
        not_after,
    })
}

/// A new account identity key.
#[uniffi::export]
pub fn create_identity() -> Result<IdentityKeys> {
    let key = signing_key(&random_bytes(32)?)?;
    Ok(IdentityKeys {
        public_key: key.verifying_key().as_bytes().to_vec(),
        signing_key: pkcs8(&key),
    })
}

/// A new device key, signed by the account identity key.
#[uniffi::export]
pub fn create_device(
    identity: IdentityKeys,
    user_id: String,
    device_id: String,
) -> Result<DeviceKeys> {
    use ed25519_dalek::Signer;
    let identity_key = signing_key(&identity.signing_key)?;
    if identity_key.verifying_key().as_bytes() != identity.public_key.as_slice() {
        return Err(malformed("the identity key does not match its public key"));
    }
    let device_key = signing_key(&random_bytes(32)?)?;
    let device_public_key = device_key.verifying_key().as_bytes().to_vec();
    let certificate = identity_key
        .sign(&crate::hubs::device_certificate_body(
            &user_id,
            &device_id,
            &device_public_key,
        ))
        .to_bytes()
        .to_vec();
    Ok(DeviceKeys {
        user_id,
        device_id,
        identity_public_key: identity.public_key,
        device_public_key,
        device_signing_key: pkcs8(&device_key),
        certificate,
    })
}

/// A device id in the same form the website uses: 16 random bytes,
/// base64url, no padding.
#[uniffi::export]
pub fn new_device_id() -> Result<String> {
    random_id(16)
}

#[cfg(test)]
mod padding_tests {
    use super::*;

    /// The sizes ts-mls gives each content length, with the TypeScript
    /// implementation's group settings (tests/padding-vectors.mts writes the
    /// file).
    fn vectors() -> serde_json::Value {
        let path = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/padding-vectors.json");
        serde_json::from_str(&std::fs::read_to_string(path).expect("the padding vectors"))
            .expect("JSON")
    }

    #[test]
    fn application_messages_have_the_web_sizes() {
        let v = vectors();
        let g = &v["generator"];
        assert_eq!(g["paddingConfig"]["padUntilLength"], 256);
        let identity = create_identity().unwrap();
        let keys = create_device(identity, "u_vectors".into(), "d_vectors".into()).unwrap();
        let device = MlsDevice::new(keys).unwrap();
        let group = device
            .start_group(g["groupId"].as_str().unwrap().into(), 1_760_000_000)
            .unwrap();
        assert_eq!(group.epoch(), g["epoch"].as_u64().unwrap());
        let authenticated_data = vec![0; g["authenticatedDataLength"].as_u64().unwrap() as usize];
        for case in v["cases"].as_array().unwrap() {
            let length = case["contentLength"].as_u64().unwrap() as usize;
            let message = group
                .lock()
                .encrypt_application_message(&vec![0x61; length], authenticated_data.clone())
                .unwrap();
            let bytes = message.to_bytes().unwrap();
            // Same group id, epoch and authenticated data as the vectors, and
            // the sender data has a fixed size, so equal MLSMessage sizes
            // mean equal ciphertext sizes, which means equal padded contents.
            assert_eq!(
                bytes.len() as u64,
                case["mlsMessageLength"].as_u64().unwrap(),
                "content of {length} bytes"
            );
            assert!(case["paddedContentLength"].as_u64().unwrap() >= 256);
        }
    }
}
