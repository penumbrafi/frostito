//! Liveness proofs for custodian participation
//!
//! Ensures custodians are actively running infrastructure by requiring
//! cryptographic proofs of block verification alongside reshare contributions.
//!
//! # Architecture
//!
//! ```text
//! Custodian Node                           On-Chain
//! ┌──────────────────┐                    ┌──────────────────┐
//! │ Verify block N   │                    │ ReshareState     │
//! │ Generate proof   │───contribution────▶│ + LivenessProofs │
//! │ Compute NOMT root│                    │ verify_all()     │
//! └──────────────────┘                    └──────────────────┘
//! ```
//!
//! # Integration with Ligerito
//!
//! Uses the existing `ligerito::verify_sha256()` or `verify_blake2b()`
//! to verify that a custodian correctly processed a recent block.

use alloc::vec::Vec;

use crate::curve::{OsstPoint, OsstScalar};
use crate::error::OsstError;
use crate::reshare::DealerCommitment;

// ============================================================================
// Checkpoint Types
// ============================================================================

/// A checkpoint anchor for liveness proofs
///
/// Represents a known-good block that custodians must prove they've verified.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CheckpointAnchor {
    /// Block height (relay chain or target chain)
    pub height: u64,
    /// Block hash (32 bytes)
    pub block_hash: [u8; 32],
    /// Timestamp (unix seconds)
    pub timestamp: u64,
}

impl CheckpointAnchor {
    pub fn new(height: u64, block_hash: [u8; 32], timestamp: u64) -> Self {
        Self {
            height,
            block_hash,
            timestamp,
        }
    }

    /// Serialize for hashing/signing
    pub fn to_bytes(&self) -> [u8; 48] {
        let mut buf = [0u8; 48];
        buf[0..8].copy_from_slice(&self.height.to_le_bytes());
        buf[8..40].copy_from_slice(&self.block_hash);
        buf[40..48].copy_from_slice(&self.timestamp.to_le_bytes());
        buf
    }

    /// Check if checkpoint is recent enough
    pub fn is_recent(&self, current_height: u64, max_age_blocks: u64) -> bool {
        current_height.saturating_sub(self.height) <= max_age_blocks
    }
}

/// Domain tag for the liveness contribution signature.
pub const LIVENESS_SIG_DOMAIN: &[u8] = b"osst/liveness-sig/v1";

/// Domain tag for the message a [`LivenessContribution`] signature covers.
///
/// `v2` because 0.5.0 length-prefixed the encoding (M-12); the `v1` tag was
/// the last `SCREAMING-CASE-V1` string in the crate and its digest differs
/// from this one for every input, so a 0.4.x signature does not verify here
/// and vice versa.
pub const CONTRIBUTION_SIG_MSG_DOMAIN: &[u8] = b"osst/contribution-sig/v2";

// ============================================================================
// Liveness Proof
// ============================================================================

/// Proof that custodian verified a checkpoint block
///
/// Contains a Ligerito proof of correct block verification.
#[derive(Clone, Debug)]
pub struct LivenessProof {
    /// The checkpoint being attested
    pub anchor: CheckpointAnchor,
    /// Ligerito proof bytes (from verify_sha256 or verify_blake2b)
    pub ligerito_proof: Vec<u8>,
    /// Custodian's local NOMT state root at this checkpoint
    pub state_root: [u8; 32],
}

impl LivenessProof {
    pub fn new(anchor: CheckpointAnchor, ligerito_proof: Vec<u8>, state_root: [u8; 32]) -> Self {
        Self {
            anchor,
            ligerito_proof,
            state_root,
        }
    }

    /// Estimated proof size for gas/weight estimation
    pub fn byte_size(&self) -> usize {
        48 + 4 + self.ligerito_proof.len() + 32
    }

    /// Serialize for on-chain storage
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(self.byte_size());
        buf.extend_from_slice(&self.anchor.to_bytes());
        buf.extend_from_slice(&(self.ligerito_proof.len() as u32).to_le_bytes());
        buf.extend_from_slice(&self.ligerito_proof);
        buf.extend_from_slice(&self.state_root);
        buf
    }

    /// Deserialize
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, OsstError> {
        if bytes.len() < 48 + 4 + 32 {
            return Err(OsstError::InvalidCommitment);
        }

        let height = u64::from_le_bytes(bytes[0..8].try_into().unwrap());
        let block_hash: [u8; 32] = bytes[8..40].try_into().unwrap();
        let timestamp = u64::from_le_bytes(bytes[40..48].try_into().unwrap());
        let anchor = CheckpointAnchor {
            height,
            block_hash,
            timestamp,
        };

        let proof_len = u32::from_le_bytes(bytes[48..52].try_into().unwrap()) as usize;

        if bytes.len() < 52 + proof_len + 32 {
            return Err(OsstError::InvalidCommitment);
        }

        let ligerito_proof = bytes[52..52 + proof_len].to_vec();
        let state_root: [u8; 32] = bytes[52 + proof_len..52 + proof_len + 32]
            .try_into()
            .unwrap();

        Ok(Self {
            anchor,
            ligerito_proof,
            state_root,
        })
    }
}

// ============================================================================
// Dealer Contribution with Liveness
// ============================================================================

/// Complete dealer contribution for reshare
///
/// Combines reshare commitment with liveness proof.
#[derive(Clone, Debug)]
pub struct DealerContribution<P: OsstPoint> {
    /// Reshare polynomial commitment
    pub commitment: DealerCommitment<P>,
    /// Proof of infrastructure participation
    pub liveness: LivenessProof,
    /// Schnorr signature binding commitment + liveness
    pub signature: ContributionSignature<P>,
}

/// Schnorr signature over contribution
///
/// `r` is held as a point, not as bytes: the curve's canonical compressed
/// encoding is not 32 bytes on every backend (secp256k1 is 33), and carrying
/// bytes meant re-deriving a point from a possibly non-canonical encoding on
/// every verification.
#[derive(Clone)]
pub struct ContributionSignature<P: OsstPoint> {
    /// R = g^k
    pub r: P,
    /// s = k + e * x
    pub s: P::Scalar,
}

impl<P: OsstPoint> ContributionSignature<P> {
    pub fn new(r: P, s: P::Scalar) -> Self {
        Self { r, s }
    }

    /// Byte length of the serialized form.
    #[inline]
    pub fn byte_size() -> usize {
        P::COMPRESSED_SIZE + 32
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(Self::byte_size());
        buf.extend_from_slice(self.r.compress().as_ref());
        buf.extend_from_slice(&self.s.to_bytes());
        buf
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self, OsstError> {
        if bytes.len() != Self::byte_size() {
            return Err(OsstError::InvalidCommitment);
        }
        let n = P::COMPRESSED_SIZE;
        let r = P::decompress(&bytes[0..n]).ok_or(OsstError::InvalidCommitment)?;
        let s = P::Scalar::from_canonical_bytes(&bytes[n..n + 32].try_into().unwrap())
            .ok_or(OsstError::InvalidResponse)?;
        Ok(Self { r, s })
    }
}

impl<P: OsstPoint> core::fmt::Debug for ContributionSignature<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("ContributionSignature")
            .field("r", &hex_short(self.r.compress().as_ref()))
            .field("s", &"[SCALAR]")
            .finish()
    }
}

fn hex_short(bytes: &[u8]) -> alloc::string::String {
    use alloc::format;
    if bytes.len() <= 8 {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    } else {
        format!(
            "{}...{}",
            bytes[0..4]
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<alloc::string::String>(),
            bytes[bytes.len() - 4..]
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<alloc::string::String>()
        )
    }
}

impl<P: OsstPoint> DealerContribution<P> {
    /// Create new contribution (signature must be computed separately)
    pub fn new(
        commitment: DealerCommitment<P>,
        liveness: LivenessProof,
        signature: ContributionSignature<P>,
    ) -> Self {
        Self {
            commitment,
            liveness,
            signature,
        }
    }

    /// Get dealer index
    pub fn dealer_index(&self) -> u32 {
        self.commitment.dealer_index
    }

    /// The message a contribution signature covers.
    ///
    /// ```text
    /// SHA-512(
    ///     len(domain):u64 LE ‖ CONTRIBUTION_SIG_MSG_DOMAIN ‖
    ///     len(commitment):u64 LE ‖ commitment.to_bytes() ‖
    ///     len(liveness):u64 LE ‖ liveness.to_bytes() ‖
    ///     len(context):u64 LE ‖ context
    /// )
    /// ```
    ///
    /// # Injectivity (M-12)
    ///
    /// Until 0.5.0 the four fields were concatenated bare. `DealerCommitment`
    /// serializes as `dealer_index:4 ‖ t compressed points` — variable length,
    /// no prefix, and `from_bytes` needs the threshold out of band.
    /// `LivenessProof` is self-delimiting only once its *start offset* is
    /// known, and that offset is exactly what the missing prefix left
    /// undetermined; `context` is caller-supplied and trailing. So reading
    /// `t+1` coefficients instead of `t` shifted the commitment/liveness
    /// boundary by one point and, where the shifted bytes parsed, produced a
    /// second `(commitment, liveness, context)` triple with the same digest.
    ///
    /// Every variable-length field now carries a `u64` length prefix, so the
    /// encoding is injective and no field can absorb bytes from its
    /// neighbour — the discipline
    /// [`SigningContext::encode`](crate::SigningContext::encode) already
    /// applies and documents.
    ///
    /// The prior severity assessment still stands on the old code: a dealer
    /// only ever signs a commitment it built itself, and a verifier parses
    /// with a threshold pinned out of band, so this was an encoding defect
    /// rather than a live forgery primitive. It rides 0.5.0 because it is
    /// signature-incompatible and 0.5.0 already breaks the wire.
    pub fn signing_message(
        commitment: &DealerCommitment<P>,
        liveness: &LivenessProof,
        context: &[u8],
    ) -> [u8; 64] {
        use sha2::{Digest, Sha512};

        fn field(hasher: &mut sha2::Sha512, bytes: &[u8]) {
            use sha2::Digest;
            hasher.update((bytes.len() as u64).to_le_bytes());
            hasher.update(bytes);
        }

        let mut hasher = Sha512::new();
        field(&mut hasher, CONTRIBUTION_SIG_MSG_DOMAIN);
        field(&mut hasher, &commitment.to_bytes());
        field(&mut hasher, &liveness.to_bytes());
        field(&mut hasher, context);

        hasher.finalize().into()
    }

    /// Sign a contribution
    pub fn sign<R: rand_core::RngCore + rand_core::CryptoRng>(
        commitment: DealerCommitment<P>,
        liveness: LivenessProof,
        secret_key: &P::Scalar,
        context: &[u8],
        rng: &mut R,
    ) -> Self {
        let message = Self::signing_message(&commitment, &liveness, context);

        // Schnorr signature
        let k = P::Scalar::random(rng);
        let r_point = P::generator().mul_scalar(&k);
        let public_key = P::generator().mul_scalar(secret_key);

        // e = H(dom || R || Y || message)
        let e = Self::challenge_hash(&r_point, &public_key, &message);

        // s = k + e * x
        let s = k.add(&e.mul(secret_key));

        let signature = ContributionSignature::new(r_point, s);

        Self {
            commitment,
            liveness,
            signature,
        }
    }

    /// Verify contribution signature
    pub fn verify_signature(&self, public_key: &P, context: &[u8]) -> bool {
        let message = Self::signing_message(&self.commitment, &self.liveness, context);

        // e = H(dom || R || Y || message)
        let e = Self::challenge_hash(&self.signature.r, public_key, &message);

        // Verify: g^s == R + Y^e
        let lhs = P::generator().mul_scalar(&self.signature.s);
        let rhs = self.signature.r.add(&public_key.mul_scalar(&e));

        lhs == rhs
    }

    /// Challenge for the contribution signature.
    ///
    /// `e = H(LIVENESS_SIG_DOMAIN || R || Y || message)`
    ///
    /// # Why the key is in the hash (L-1)
    ///
    /// Until 0.4.0 this was `SHA512(R || message)`. Verification is
    /// `g^s == R + e·Y` with `e` independent of `Y`, so a valid `(R, s)` under
    /// `Y` became a valid `(R, s + e·delta)` under `Y + delta·G` for any
    /// `delta` — equivalently, an adversary could pick `R` and `s` freely and
    /// back-solve a key for which they verify. Whether that was exploitable
    /// depended on whether the registry established dealer keys with a proof
    /// of possession, which osst does not do either way. RFC 8032 and BIP340
    /// both bind the key into the challenge for exactly this reason.
    ///
    /// The domain tag additionally separates this hash from the OSST
    /// contribution challenge, which it used to equal byte-for-byte (H-1).
    pub fn challenge_hash(r: &P, public_key: &P, message: &[u8; 64]) -> P::Scalar {
        use sha2::{Digest, Sha512};

        let mut hasher = Sha512::new();
        hasher.update(LIVENESS_SIG_DOMAIN);
        hasher.update(r.compress());
        hasher.update(public_key.compress());
        hasher.update(message);

        let hash: [u8; 64] = hasher.finalize().into();
        P::Scalar::from_bytes_wide(&hash)
    }
}

// ============================================================================
// Liveness Verifier Trait
// ============================================================================

/// Trait for verifying Ligerito proofs
///
/// Implement this to connect to your on-chain Ligerito verifier.
pub trait LivenessVerifier {
    /// Verify a Ligerito proof for a checkpoint
    fn verify_ligerito_proof(
        &self,
        anchor: &CheckpointAnchor,
        proof: &[u8],
        state_root: &[u8; 32],
    ) -> bool;

    /// Get the current checkpoint anchor
    fn current_anchor(&self) -> CheckpointAnchor;

    /// Maximum age of valid checkpoints (in blocks)
    fn max_checkpoint_age(&self) -> u64;
}

/// Batch verifier for multiple contributions
pub struct ContributionVerifier<'a, P: OsstPoint, V: LivenessVerifier> {
    verifier: &'a V,
    context: &'a [u8],
    _marker: core::marker::PhantomData<P>,
}

impl<'a, P: OsstPoint, V: LivenessVerifier> ContributionVerifier<'a, P, V> {
    pub fn new(verifier: &'a V, context: &'a [u8]) -> Self {
        Self {
            verifier,
            context,
            _marker: core::marker::PhantomData,
        }
    }

    /// Verify a single contribution
    pub fn verify(
        &self,
        contribution: &DealerContribution<P>,
        public_key: &P,
    ) -> Result<(), ContributionError> {
        let current = self.verifier.current_anchor();

        // Check checkpoint is recent
        if !contribution
            .liveness
            .anchor
            .is_recent(current.height, self.verifier.max_checkpoint_age())
        {
            return Err(ContributionError::CheckpointTooOld);
        }

        // Verify Schnorr signature
        if !contribution.verify_signature(public_key, self.context) {
            return Err(ContributionError::InvalidSignature);
        }

        // Verify Ligerito proof
        if !self.verifier.verify_ligerito_proof(
            &contribution.liveness.anchor,
            &contribution.liveness.ligerito_proof,
            &contribution.liveness.state_root,
        ) {
            return Err(ContributionError::InvalidLigerito);
        }

        Ok(())
    }

    /// Verify one contribution against a roster keyed by dealer index.
    ///
    /// # Errors
    ///
    /// [`ContributionError::IndexMismatch`] when the roster has no key for
    /// this contribution's dealer, plus the errors of [`Self::verify`].
    pub fn verify_keyed(
        &self,
        contribution: &DealerContribution<P>,
        public_keys: &[(u32, P)],
    ) -> Result<(), ContributionError> {
        let pk = public_keys
            .iter()
            .find(|(i, _)| *i == contribution.dealer_index())
            .map(|(_, k)| k)
            .ok_or(ContributionError::IndexMismatch)?;
        self.verify(contribution, pk)
    }

    /// Verify multiple contributions, returning the positions of the valid
    /// ones.
    ///
    /// Public keys are looked up by `dealer_index`, not by position: the
    /// previous signature zipped the two lists, so a caller that passed them
    /// in different orders verified every contribution against the wrong key
    /// and the `IndexMismatch` variant was never constructed.
    pub fn verify_batch(
        &self,
        contributions: &[DealerContribution<P>],
        public_keys: &[(u32, P)],
    ) -> Vec<usize> {
        contributions
            .iter()
            .enumerate()
            .filter_map(|(i, contrib)| self.verify_keyed(contrib, public_keys).ok().map(|_| i))
            .collect()
    }
}

/// Contribution verification errors
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ContributionError {
    /// Checkpoint is too old
    CheckpointTooOld,
    /// Schnorr signature invalid
    InvalidSignature,
    /// Ligerito proof invalid
    InvalidLigerito,
    /// Dealer index mismatch
    IndexMismatch,
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(all(test, feature = "ristretto255"))]
mod tests {
    use super::*;
    use crate::reshare::Dealer;
    use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
    use rand::rngs::OsRng;

    /// Mock liveness verifier for testing
    struct MockVerifier {
        current_height: u64,
        max_age: u64,
    }

    impl LivenessVerifier for MockVerifier {
        fn verify_ligerito_proof(
            &self,
            _anchor: &CheckpointAnchor,
            proof: &[u8],
            _state_root: &[u8; 32],
        ) -> bool {
            // Accept any non-empty proof in tests
            !proof.is_empty()
        }

        fn current_anchor(&self) -> CheckpointAnchor {
            CheckpointAnchor::new(self.current_height, [0u8; 32], 0)
        }

        fn max_checkpoint_age(&self) -> u64 {
            self.max_age
        }
    }

    /// M-12: the pre-0.5.0 contribution message concatenated the domain tag,
    /// the commitment, the liveness proof and the context with no length
    /// prefixes, and `DealerCommitment::to_bytes` is variable-length with the
    /// threshold supplied out of band. So the commitment/liveness boundary was
    /// undetermined and the encoding was not injective.
    ///
    /// This builds an explicit collision against the old rule — two distinct
    /// `(commitment, liveness)` pairs whose bare concatenations are equal
    /// byte-for-byte, the second commitment carrying one extra coefficient
    /// that the first pair spends on the head of its liveness proof — and
    /// asserts that the length-prefixed v2 message separates them.
    #[test]
    fn contribution_message_is_injective_across_the_commitment_boundary() {
        let mut rng = OsRng;
        let g = <RistrettoPoint as OsstPoint>::generator();
        let p1 = g.mul_scalar(&Scalar::random(&mut rng));
        let p2 = g.mul_scalar(&Scalar::random(&mut rng));
        // the extra coefficient, which pair A instead reads as the first 32
        // bytes of its anchor
        let x = g.mul_scalar(&Scalar::random(&mut rng));
        let x_bytes = OsstPoint::compress(&x);

        // --- pair A: two coefficients, the extra point absorbed by the anchor
        let commitment_a = DealerCommitment::<RistrettoPoint> {
            dealer_index: 7,
            coefficients: vec![p1, p2],
        };
        let height_a = u64::from_le_bytes(x_bytes[0..8].try_into().unwrap());
        let mut block_hash_a = [0u8; 32];
        block_hash_a[0..24].copy_from_slice(&x_bytes[8..32]);
        block_hash_a[24..32].copy_from_slice(&[0xA1; 8]);
        let timestamp_a = 0x0102_0304_0506_0708u64;
        // 32 proof bytes whose last four are zero: those four are pair B's
        // proof length, and it must read as empty
        let mut proof_a = [0x5Au8; 32];
        proof_a[28..32].copy_from_slice(&0u32.to_le_bytes());
        let state_root = [0xC3u8; 32];
        let liveness_a = LivenessProof::new(
            CheckpointAnchor::new(height_a, block_hash_a, timestamp_a),
            proof_a.to_vec(),
            state_root,
        );

        // --- pair B: three coefficients, its liveness proof made of the
        //     bytes pair A spent on the tail of its anchor and its proof
        let commitment_b = DealerCommitment::<RistrettoPoint> {
            dealer_index: 7,
            coefficients: vec![p1, p2, x],
        };
        let tail = &liveness_a.to_bytes()[32..];
        let liveness_b = LivenessProof::from_bytes(tail).expect("tail parses as a liveness proof");

        let context = b"osst-epoch-42";

        // the old rule: domain ‖ commitment ‖ liveness ‖ context, bare
        let old = |c: &DealerCommitment<RistrettoPoint>, l: &LivenessProof| {
            use sha2::{Digest, Sha512};
            let mut h = Sha512::new();
            h.update(b"OSST-CONTRIBUTION-V1");
            h.update(c.to_bytes());
            h.update(l.to_bytes());
            h.update(context);
            let out: [u8; 64] = h.finalize().into();
            out
        };

        assert_ne!(
            commitment_a.to_bytes(),
            commitment_b.to_bytes(),
            "the two commitments must genuinely differ"
        );
        assert_eq!(
            old(&commitment_a, &liveness_a),
            old(&commitment_b, &liveness_b),
            "the pre-0.5.0 encoding really did collide here"
        );

        assert_ne!(
            DealerContribution::<RistrettoPoint>::signing_message(
                &commitment_a,
                &liveness_a,
                context
            ),
            DealerContribution::<RistrettoPoint>::signing_message(
                &commitment_b,
                &liveness_b,
                context
            ),
            "length prefixes must separate the two triples"
        );
    }

    /// The context field is trailing; a length prefix must stop it absorbing
    /// bytes from, or donating bytes to, its neighbour.
    #[test]
    fn contribution_message_separates_the_context_field() {
        let mut rng = OsRng;
        let dealer: Dealer<RistrettoPoint> =
            Dealer::new(1, Scalar::random(&mut rng), 3, &mut rng).expect("index is 1-indexed by construction");
        let commitment = dealer.commitment().clone();
        let liveness = LivenessProof::new(
            CheckpointAnchor::new(100, [1u8; 32], 1234567890),
            vec![1, 2, 3, 4],
            [2u8; 32],
        );
        assert_ne!(
            DealerContribution::<RistrettoPoint>::signing_message(&commitment, &liveness, b"ab"),
            DealerContribution::<RistrettoPoint>::signing_message(&commitment, &liveness, b"abc"),
        );
    }

    #[test]
    fn test_contribution_sign_verify() {
        let mut rng = OsRng;

        // Generate dealer key
        let secret = Scalar::random(&mut rng);
        let public: RistrettoPoint = RistrettoPoint::generator().mul_scalar(&secret);

        // Create dealer and commitment
        let dealer: Dealer<RistrettoPoint> = Dealer::new(1, Scalar::random(&mut rng), 3, &mut rng).expect("index is 1-indexed by construction");
        let commitment = dealer.commitment().clone();

        // Create liveness proof
        let anchor = CheckpointAnchor::new(100, [1u8; 32], 1234567890);
        let liveness = LivenessProof::new(anchor, vec![1, 2, 3, 4], [2u8; 32]);

        // Sign contribution
        let context = b"test-epoch-42";
        let contribution =
            DealerContribution::sign(commitment, liveness, &secret, context, &mut rng);

        // Verify signature
        assert!(contribution.verify_signature(&public, context));

        // Wrong context should fail
        assert!(!contribution.verify_signature(&public, b"wrong-context"));

        // Wrong public key should fail
        let wrong_public: RistrettoPoint =
            RistrettoPoint::generator().mul_scalar(&Scalar::random(&mut rng));
        assert!(!contribution.verify_signature(&wrong_public, context));
    }

    #[test]
    fn test_contribution_verifier() {
        let mut rng = OsRng;

        let verifier = MockVerifier {
            current_height: 100,
            max_age: 10,
        };

        let secret = Scalar::random(&mut rng);
        let public: RistrettoPoint = RistrettoPoint::generator().mul_scalar(&secret);

        let dealer: Dealer<RistrettoPoint> = Dealer::new(1, Scalar::random(&mut rng), 3, &mut rng).expect("index is 1-indexed by construction");
        let commitment = dealer.commitment().clone();

        // Recent checkpoint - should pass
        let anchor = CheckpointAnchor::new(95, [1u8; 32], 0);
        let liveness = LivenessProof::new(anchor, vec![1, 2, 3], [0u8; 32]);
        let context = b"epoch-1";

        let contribution =
            DealerContribution::sign(commitment.clone(), liveness, &secret, context, &mut rng);

        let cv = ContributionVerifier::<RistrettoPoint, _>::new(&verifier, context);
        assert!(cv.verify(&contribution, &public).is_ok());

        // Old checkpoint - should fail
        let old_anchor = CheckpointAnchor::new(50, [1u8; 32], 0);
        let old_liveness = LivenessProof::new(old_anchor, vec![1, 2, 3], [0u8; 32]);

        let old_contribution =
            DealerContribution::sign(commitment, old_liveness, &secret, context, &mut rng);

        assert_eq!(
            cv.verify(&old_contribution, &public),
            Err(ContributionError::CheckpointTooOld)
        );
    }

    #[test]
    fn test_checkpoint_serialization() {
        let anchor = CheckpointAnchor::new(12345, [0xab; 32], 1700000000);
        let bytes = anchor.to_bytes();

        assert_eq!(bytes.len(), 48);
        assert_eq!(u64::from_le_bytes(bytes[0..8].try_into().unwrap()), 12345);
    }

    #[test]
    fn test_liveness_proof_serialization() {
        let anchor = CheckpointAnchor::new(100, [1u8; 32], 123);
        let proof = LivenessProof::new(anchor.clone(), vec![1, 2, 3, 4, 5], [2u8; 32]);

        let bytes = proof.to_bytes();
        let recovered = LivenessProof::from_bytes(&bytes).unwrap();

        assert_eq!(recovered.anchor, anchor);
        assert_eq!(recovered.ligerito_proof, vec![1, 2, 3, 4, 5]);
        assert_eq!(recovered.state_root, [2u8; 32]);
    }
}
