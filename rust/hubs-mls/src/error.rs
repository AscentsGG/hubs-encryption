use std::fmt;

/// Every way a call into the core can fail. The app shows none of these
/// words to people; it maps them to its own copy.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Error)]
pub enum HubsMlsError {
    /// Bytes or values that are not in the expected form.
    Malformed { reason: String },
    /// Not a Hubs device credential, or its device certificate does not
    /// verify under the identity key it names.
    Credential { reason: String },
    /// A key package outside the lifetime policy (90 days, see `policy`).
    KeyPackageLifetime { reason: String },
    /// A welcome whose group is not the conversation it was delivered for.
    WrongConversation,
    /// Private conversations only accept MLS private messages.
    NotEncrypted,
    /// The decrypted payload breaks the rule every device applies
    /// (`privateDmPayloadProblem`). The reason uses the same words as the
    /// TypeScript implementation.
    Payload { reason: String },
    /// The message's franking commitment does not match its contents.
    FrankingMismatch,
    /// The payload names a different person or device than the MLS sender.
    SenderMismatch,
    /// A commit is already waiting for the server, or none is.
    PendingCommit { reason: String },
    /// This snapshot belongs to another device.
    WrongDevice,
    /// The MLS library refused the operation.
    Mls { reason: String },
}

impl fmt::Display for HubsMlsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Malformed { reason } => write!(f, "malformed: {reason}"),
            Self::Credential { reason } => write!(f, "credential: {reason}"),
            Self::KeyPackageLifetime { reason } => write!(f, "key package lifetime: {reason}"),
            Self::WrongConversation => f.write_str("the welcome is for another conversation"),
            Self::NotEncrypted => f.write_str("only MLS private messages are accepted"),
            Self::Payload { reason } => write!(f, "payload: {reason}"),
            Self::FrankingMismatch => f.write_str("the message did not match its commitment"),
            Self::SenderMismatch => {
                f.write_str("the message did not come from the device it names")
            }
            Self::PendingCommit { reason } => write!(f, "pending commit: {reason}"),
            Self::WrongDevice => f.write_str("this state belongs to another device"),
            Self::Mls { reason } => write!(f, "mls: {reason}"),
        }
    }
}

impl std::error::Error for HubsMlsError {}

impl From<mls_rs::error::MlsError> for HubsMlsError {
    fn from(error: mls_rs::error::MlsError) -> Self {
        Self::Mls {
            reason: error.to_string(),
        }
    }
}

impl From<mls_rs::mls_rs_codec::Error> for HubsMlsError {
    fn from(error: mls_rs::mls_rs_codec::Error) -> Self {
        Self::Malformed {
            reason: error.to_string(),
        }
    }
}

pub(crate) fn malformed(reason: impl Into<String>) -> HubsMlsError {
    HubsMlsError::Malformed {
        reason: reason.into(),
    }
}

pub type Result<T, E = HubsMlsError> = std::result::Result<T, E>;
