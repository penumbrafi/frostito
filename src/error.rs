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
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for OsstError {}
