//! The credential check as an mls-rs `IdentityProvider`: every leaf in every
//! MLS operation (key packages, welcomes, commits, the ratchet tree on join)
//! must carry a Hubs credential whose device certificate verifies under the
//! identity key it names. mls-rs calls this inside the library before
//! anything is merged, at the same point where ts-mls calls the TypeScript
//! implementation's `authService.validateCredential`.

use std::fmt;

use mls_rs_core::{
    error::IntoAnyError,
    extension::ExtensionList,
    identity::{CredentialType, IdentityProvider, MemberValidationContext, SigningIdentity},
    time::MlsTime,
};

use crate::policy::identity_info;

#[derive(Debug)]
pub struct HubsIdentityError(String);

impl fmt::Display for HubsIdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl std::error::Error for HubsIdentityError {}

impl IntoAnyError for HubsIdentityError {
    fn into_dyn_error(self) -> Result<Box<dyn std::error::Error + Send + Sync>, Self> {
        Ok(self.into())
    }
}

/// (user, device, identity key) of a verified member.
fn verified(identity: &SigningIdentity) -> Result<(String, String, Vec<u8>), HubsIdentityError> {
    identity_info(identity)
        .map(|info| (info.user_id, info.device_id, info.identity_public_key))
        .map_err(|error| HubsIdentityError(error.to_string()))
}

#[derive(Debug, Clone, Copy, Default)]
pub struct HubsIdentity;

impl IdentityProvider for HubsIdentity {
    type Error = HubsIdentityError;

    fn validate_member(
        &self,
        identity: &SigningIdentity,
        _timestamp: Option<MlsTime>,
        _context: MemberValidationContext<'_>,
    ) -> Result<(), Self::Error> {
        verified(identity).map(|_| ())
    }

    fn validate_external_sender(
        &self,
        _identity: &SigningIdentity,
        _timestamp: Option<MlsTime>,
        _extensions: Option<&ExtensionList>,
    ) -> Result<(), Self::Error> {
        // Hubs groups have no external senders.
        Err(HubsIdentityError("external senders are not allowed".into()))
    }

    /// One member per device: the user and device ids, NUL separated.
    fn identity(
        &self,
        identity: &SigningIdentity,
        _extensions: &ExtensionList,
    ) -> Result<Vec<u8>, Self::Error> {
        let (user, device, _) = verified(identity)?;
        Ok(format!("{user}\0{device}").into_bytes())
    }

    /// A leaf may only be replaced by the same person's same device under
    /// the same identity key.
    fn valid_successor(
        &self,
        predecessor: &SigningIdentity,
        successor: &SigningIdentity,
        _extensions: &ExtensionList,
    ) -> Result<bool, Self::Error> {
        Ok(verified(predecessor)? == verified(successor)?)
    }

    fn supported_types(&self) -> Vec<CredentialType> {
        vec![CredentialType::BASIC]
    }
}
