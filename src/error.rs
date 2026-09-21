//! OSST error types

use core::fmt;

/// Errors that can occur during OSST operations
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OsstError {
    /// No contributions provided
    EmptyContributions,

    /// Not enough contributions for threshold
    InsufficientContributions { got: usize, need: usize },

    /// Duplicate custodian index
    DuplicateIndex(u32),

    /// Challenge hash resulted in zero (astronomically unlikely)
    ZeroChallenge,

    /// Invalid commitment point (not on curve)
    InvalidCommitment,

    /// Invalid response scalar (not canonical)
    InvalidResponse,

    /// Lagrange computation failed (duplicate indices)
    LagrangeError,

    /// Index out of valid range (must be > 0)
    InvalidIndex,

    /// Sub-share from a dealer outside the agreed dealer set
    UnexpectedDealer(u32),

    /// Dealers committed to different new thresholds
    ThresholdMismatch { expected: u32, got: u32 },

    /// The signing package's message is not the message the signer approved
    MessageMismatch,

    /// A commitment in the package is not the one produced in the local round
    UnexpectedCommitment,

    /// A coordinator-supplied outer context does not match the locally
    /// recomputed one (binding factor, challenge or Lagrange coefficient)
    ChallengeMismatch,

    /// Two rounds of the same protocol were mixed (session id mismatch)
    SessionMismatch,

    /// A dealer's proof of knowledge of its constant term did not verify.
    /// Carries the failing dealer's index: this is a complaint, and it names
    /// who to disqualify.
    InvalidProofOfKnowledge(u32),

    /// A dealer's sub-share did not verify against its commitment. Carries the
    /// failing dealer's index.
    InvalidSubShare(u32),

    /// The ceremony cannot continue: too few dealers remain after
    /// disqualification.
    DkgAborted { qualified: usize, need: usize },

    /// A sealed package did not open. Carries the dealer it claimed to come
    /// from. Which of wrong-sender, wrong-recipient, wrong-ceremony or
    /// tampering caused it is deliberately not reported.
    SealedOpenFailed(u32),

    /// A participant is not on the sealed roster.
    UnknownParticipant(u32),

    /// An index in a coordinator-supplied `active_indices` has no round-1
    /// commitment in the set the nested aggregate was formed over (M-14).
    UnknownQuorumMember(u32),

    /// Two participants published different views of the same round-1
    /// commitment set: a dealer equivocated, or the broadcast is not
    /// reliable. Refuse to enter round 2 (M-5).
    EchoMismatch,

    /// A revealed inner commitment has no matching round-0 precommitment, or
    /// does not match the one it claims (M-20).
    PrecommitMismatch(u32),

    /// `(session_id, holder_index)` has already produced a share. Signing
    /// again would be nonce reuse (M-13).
    SessionSpent,

    /// A complaint's signature did not verify under the accuser's identity
    /// key, or it names a ceremony other than this one (M-6).
    InvalidComplaint,
}

impl fmt::Display for OsstError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyContributions => write!(f, "no contributions provided"),
            Self::InsufficientContributions { got, need } => {
                write!(f, "insufficient contributions: got {}, need {}", got, need)
            }
            Self::DuplicateIndex(idx) => write!(f, "duplicate custodian index: {}", idx),
            Self::ZeroChallenge => write!(f, "challenge hash is zero"),
            Self::InvalidCommitment => write!(f, "invalid commitment point"),
            Self::InvalidResponse => write!(f, "invalid response scalar"),
            Self::LagrangeError => write!(f, "lagrange coefficient computation failed"),
            Self::InvalidIndex => write!(f, "index must be greater than 0"),
            Self::UnexpectedDealer(idx) => {
                write!(f, "dealer {} is not in the agreed dealer set", idx)
            }
            Self::ThresholdMismatch { expected, got } => {
                write!(f, "dealer committed to threshold {}, expected {}", got, expected)
            }
            Self::MessageMismatch => {
                write!(f, "signing package message is not the approved message")
            }
            Self::UnexpectedCommitment => {
                write!(f, "commitment is not the one produced in this round")
            }
            Self::ChallengeMismatch => {
                write!(f, "coordinator-supplied outer context does not match")
            }
            Self::SessionMismatch => write!(f, "session id mismatch"),
            Self::InvalidProofOfKnowledge(idx) => {
                write!(f, "dealer {} published an invalid proof of knowledge", idx)
            }
            Self::InvalidSubShare(idx) => {
                write!(f, "dealer {} sent an invalid sub-share", idx)
            }
            Self::SealedOpenFailed(idx) => {
                write!(f, "sealed package from dealer {} did not open", idx)
            }
            Self::UnknownParticipant(idx) => {
                write!(f, "participant {} is not on the roster", idx)
            }
            Self::UnknownQuorumMember(idx) => {
                write!(f, "quorum member {} has no round-1 commitment", idx)
            }
            Self::EchoMismatch => write!(f, "round-1 commitment sets disagree"),
            Self::PrecommitMismatch(idx) => {
                write!(f, "holder {} revealed a commitment it did not precommit to", idx)
            }
            Self::SessionSpent => write!(f, "this session has already produced a share"),
            Self::InvalidComplaint => write!(f, "complaint did not verify"),
            Self::DkgAborted { qualified, need } => write!(
                f,
                "dkg aborted: {} qualified dealers remain, need {}",
                qualified, need
            ),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for OsstError {}
