//! Distributed key generation (Feldman VSS)
//!
//! Trustless DKG where every participant acts as a dealer:
//! each generates a random polynomial, publishes commitments,
//! and sends sub-shares to all other participants.
//!
//! The group secret `s = sum(f_i(0))` is never known to anyone.
//! The group public key `Y = sum(g^{f_i(0)})` is publicly derivable.
//!
//! # Differences from reshare
//!
//! - Reshare: subset of dealers (t_old), Lagrange aggregation, group key invariant
//! - DKG: all n participants deal, direct summation, group key derived fresh
//!
//! # Protocol
//!
//! 1. Each participant i generates random polynomial f_i of degree t-1
//! 2. Each broadcasts a [`Round1Package`]: the commitment
//!    C_i = [g^{f_i(0)}, g^{f_i(1)}, ...] and a Schnorr proof of knowledge of
//!    the constant term (Komlo–Goldberg SAC 2020 §5.1). Recipients verify the
//!    proof before recording the commitment.
//! 3. Each sends sub-share f_i(j) to participant j — **confidentially**; with
//!    the `sealed` feature, [`crate::sealed`] does this, and without it the
//!    caller must, because n-1 evaluations of a degree-(t-1) polynomial on the
//!    wire reconstruct it outright
//! 4. Participant j verifies each sub-share against commitments
//! 5. A failure in step 2 or 4 is a complaint naming the dealer
//!    ([`OsstError::InvalidProofOfKnowledge`], [`OsstError::InvalidSubShare`]);
//!    every participant applies it with [`DkgState::disqualify`], or they
//!    derive different keys
//! 6. Participant j's final share: s_j = sum_i(f_i(j)) over the qualified set
//! 7. Group public key: Y = sum_i(C_{i,0}) over the qualified set

use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;

use crate::curve::{OsstPoint, OsstScalar};
use crate::error::OsstError;
use crate::reshare::{DealerCommitment, SubShare};

// ============================================================================
// Proof of knowledge of the constant term (Komlo–Goldberg SAC 2020, §5.1)
// ============================================================================

/// Domain tag for the DKG proof of knowledge.
pub const DKG_POK_DOMAIN: &[u8] = b"osst/dkg-pok/v1";

/// Schnorr proof of knowledge of a dealer's constant term `a_0`.
///
/// Komlo–Goldberg (SAC 2020) KeyGen Round 1 step 2 requires every dealer to
/// prove knowledge of the secret behind `C_0 = g^{a_0}`; ZF `frost-core` puts
/// the same proof in its `round1::Package`. Without it a dealer can publish a
/// constant-term commitment it did not choose — a rogue-key setup — and a
/// recipient has nothing to check before the (much later) sub-share round.
///
/// `e = H(DKG_POK_DOMAIN ‖ dealer_index ‖ epoch ‖ C_0 ‖ R)`, `z = k + e·a_0`,
/// verified as `z·G == R + e·C_0`. The epoch is in the challenge so a proof
/// cannot be replayed from one ceremony into another.
#[derive(Clone, Debug, PartialEq)]
pub struct ProofOfKnowledge<P: OsstPoint> {
    /// R = g^k
    pub r: P,
    /// z = k + e·a_0
    pub z: P::Scalar,
}

impl<P: OsstPoint> ProofOfKnowledge<P> {
    fn challenge(dealer_index: u32, epoch: u64, constant_commitment: &P, r: &P) -> P::Scalar {
        use sha2::{Digest, Sha512};
        let mut h = Sha512::new();
        h.update(DKG_POK_DOMAIN);
        h.update(dealer_index.to_le_bytes());
        h.update(epoch.to_le_bytes());
        h.update(constant_commitment.compress());
        h.update(r.compress());
        let hash: [u8; 64] = h.finalize().into();
        P::Scalar::from_bytes_wide(&hash)
    }

    /// Prove knowledge of `a_0`.
    pub fn prove<R: rand_core::RngCore + rand_core::CryptoRng>(
        dealer_index: u32,
        epoch: u64,
        a_0: &P::Scalar,
        rng: &mut R,
    ) -> Self {
        let k = P::Scalar::random(rng);
        let r = P::generator().mul_scalar(&k);
        let constant_commitment = P::generator().mul_scalar(a_0);
        let e = Self::challenge(dealer_index, epoch, &constant_commitment, &r);
        Self {
            z: k.add(&e.mul(a_0)),
            r,
        }
    }

    /// Verify against a dealer's constant-term commitment.
    pub fn verify(&self, dealer_index: u32, epoch: u64, constant_commitment: &P) -> bool {
        let e = Self::challenge(dealer_index, epoch, constant_commitment, &self.r);
        P::generator().mul_scalar(&self.z) == self.r.add(&constant_commitment.mul_scalar(&e))
    }
}

/// What a dealer broadcasts in round 1: its Feldman commitment and its proof
/// of knowledge of the constant term.
///
/// Recipients verify the proof before accepting the commitment
/// ([`DkgState::submit_commitment`]); a failure is a complaint naming the
/// dealer, not a silent drop.
#[derive(Clone, Debug)]
pub struct Round1Package<P: OsstPoint> {
    pub commitment: DealerCommitment<P>,
    pub proof_of_knowledge: ProofOfKnowledge<P>,
}

impl<P: OsstPoint> Round1Package<P> {
    #[inline]
    pub fn dealer_index(&self) -> u32 {
        self.commitment.dealer_index
    }

    /// Verify the proof of knowledge against the package's own commitment.
    ///
    /// # Errors
    ///
    /// [`OsstError::InvalidProofOfKnowledge`] naming the dealer.
    pub fn verify(&self, epoch: u64) -> Result<(), OsstError> {
        let idx = self.commitment.dealer_index;
        if self
            .proof_of_knowledge
            .verify(idx, epoch, self.commitment.share_commitment())
        {
            Ok(())
        } else {
            Err(OsstError::InvalidProofOfKnowledge(idx))
        }
    }
}

// ============================================================================
// Dealer
// ============================================================================

/// DKG dealer: generates random polynomial and sub-shares.
///
/// Unlike reshare::Dealer, the constant term is random (not an existing share).
pub struct Dealer<P: OsstPoint> {
    index: u32,
    polynomial: Vec<P::Scalar>,
    commitment: DealerCommitment<P>,
}

impl<P: OsstPoint> Drop for Dealer<P> {
    fn drop(&mut self) {
        for coeff in &mut self.polynomial {
            coeff.zeroize();
        }
    }
}

impl<P: OsstPoint> Dealer<P> {
    /// Create a new DKG dealer with a random secret.
    pub fn new<R: rand_core::RngCore + rand_core::CryptoRng>(
        index: u32,
        threshold: u32,
        rng: &mut R,
    ) -> Result<Self, OsstError> {
        if index == 0 {
            return Err(OsstError::InvalidIndex);
        }
        if threshold == 0 {
            return Err(OsstError::ThresholdMismatch { expected: 1, got: 0 });
        }

        let mut polynomial = Vec::with_capacity(threshold as usize);
        for _ in 0..threshold {
            polynomial.push(P::Scalar::random(rng));
        }

        let commitment = DealerCommitment::from_polynomial(index, &polynomial)?;

        Ok(Self {
            index,
            polynomial,
            commitment,
        })
    }

    #[inline]
    pub fn index(&self) -> u32 {
        self.index
    }

    #[inline]
    pub fn commitment(&self) -> &DealerCommitment<P> {
        &self.commitment
    }

    /// This dealer's round-1 broadcast: Feldman commitment plus a Schnorr
    /// proof of knowledge of the constant term (Komlo–Goldberg §5.1).
    ///
    /// `epoch` binds the proof to one ceremony; pass the same value the
    /// recipients' [`DkgState`] carries.
    pub fn round1_package<R: rand_core::RngCore + rand_core::CryptoRng>(
        &self,
        epoch: u64,
        rng: &mut R,
    ) -> Round1Package<P> {
        Round1Package {
            commitment: self.commitment.clone(),
            proof_of_knowledge: ProofOfKnowledge::prove::<R>(
                self.index,
                epoch,
                &self.polynomial[0],
                rng,
            ),
        }
    }

    /// Generate sub-share for player j: f_i(j)
    pub fn generate_subshare(&self, player_index: u32) -> Result<SubShare<P::Scalar>, OsstError> {
        if player_index == 0 {
            return Err(OsstError::InvalidIndex);
        }

        let j = P::Scalar::from_u32(player_index);

        // Horner's method
        let mut result = P::Scalar::zero();
        for coeff in self.polynomial.iter().rev() {
            result = result.mul(&j);
            result = result.add(coeff);
        }

        SubShare::new(self.index, player_index, result)
    }

    /// Generate sub-shares for all players 1..=n
    pub fn generate_subshares(
        &self,
        num_players: u32,
    ) -> Result<Vec<SubShare<P::Scalar>>, OsstError> {
        (1..=num_players).map(|j| self.generate_subshare(j)).collect()
    }
}

impl<P: OsstPoint> core::fmt::Debug for Dealer<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("dkg::Dealer")
            .field("index", &self.index)
            .field("polynomial", &"[REDACTED]")
            .field("commitment", &self.commitment)
            .finish()
    }
}

// ============================================================================
// Aggregator
// ============================================================================

/// DKG aggregator: collects sub-shares from a **fixed** dealer set, sums directly.
///
/// Unlike reshare::Aggregator, no Lagrange coefficients needed —
/// every dealer's contribution is simply summed. But the dealer set still
/// has to be agreed up front: a player that sums one dealer more (or fewer)
/// than its peers derives a different group key and an incompatible share.
/// With a subset of participants dealing (narsild style), `dealer_set` is
/// the set fixed when round 1 closes, and it must be the same on every node.
pub struct Aggregator<P: OsstPoint> {
    player_index: u32,
    /// Agreed dealer set, sorted ascending, no duplicates
    dealer_set: Vec<u32>,
    /// Verified sub-share values keyed by dealer index
    subshares: Vec<(u32, P::Scalar)>,
    /// Constant-term commitments for group key derivation
    constant_commitments: Vec<P>,
    _marker: PhantomData<P>,
}

impl<P: OsstPoint> Aggregator<P> {
    /// Create an aggregator for `player_index` summing exactly `dealer_set`.
    pub fn new(player_index: u32, dealer_set: &[u32]) -> Result<Self, OsstError> {
        if player_index == 0 {
            return Err(OsstError::InvalidIndex);
        }
        if dealer_set.is_empty() {
            return Err(OsstError::EmptyContributions);
        }
        let mut sorted = dealer_set.to_vec();
        sorted.sort_unstable();
        for w in sorted.windows(2) {
            if w[0] == w[1] {
                return Err(OsstError::DuplicateIndex(w[0]));
            }
        }
        if sorted[0] == 0 {
            return Err(OsstError::InvalidIndex);
        }
        Ok(Self {
            player_index,
            dealer_set: sorted,
            subshares: Vec::new(),
            constant_commitments: Vec::new(),
            _marker: PhantomData,
        })
    }

    /// Aggregator over all dealers `1..=n` (the classic everyone-deals DKG).
    pub fn all_dealers(player_index: u32, n: u32) -> Result<Self, OsstError> {
        let set: alloc::vec::Vec<u32> = (1..=n).collect();
        Self::new(player_index, &set)
    }

    /// Aggregator whose dealer set is the one the echo round agreed on (M-5).
    ///
    /// Prefer this to [`new`](Self::new): the dealer set is the single value
    /// every player has to agree on — sum one dealer more or fewer than your
    /// peers and you derive a different group key and an incompatible share —
    /// and taking it from a confirmed [`AgreedRound1`] is what makes that
    /// agreement explicit rather than a convention.
    pub fn from_agreed(
        player_index: u32,
        agreed: &AgreedRound1<P>,
    ) -> Result<Self, OsstError> {
        Self::new(player_index, &agreed.dealer_set())
    }

    #[inline]
    pub fn player_index(&self) -> u32 {
        self.player_index
    }

    #[inline]
    pub fn dealer_set(&self) -> &[u32] {
        &self.dealer_set
    }

    #[inline]
    pub fn count(&self) -> usize {
        self.subshares.len()
    }

    #[inline]
    pub fn is_complete(&self) -> bool {
        self.subshares.len() == self.dealer_set.len()
    }

    /// Dealers in the set whose sub-share has not arrived yet
    pub fn missing_dealers(&self) -> Vec<u32> {
        self.dealer_set
            .iter()
            .copied()
            .filter(|d| !self.subshares.iter().any(|(i, _)| i == d))
            .collect()
    }

    /// Add a verified sub-share. Returns Ok(true) if added, Ok(false) if
    /// duplicate, Err if invalid or from a dealer outside the set.
    pub fn add_subshare(
        &mut self,
        subshare: SubShare<P::Scalar>,
        commitment: &DealerCommitment<P>,
    ) -> Result<bool, OsstError> {
        if subshare.player_index != self.player_index {
            return Err(OsstError::InvalidIndex);
        }
        if subshare.dealer_index != commitment.dealer_index {
            return Err(OsstError::InvalidIndex);
        }
        if subshare.dealer_index == 0 {
            return Err(OsstError::InvalidIndex);
        }
        if self.dealer_set.binary_search(&subshare.dealer_index).is_err() {
            return Err(OsstError::UnexpectedDealer(subshare.dealer_index));
        }

        // duplicate check
        if self
            .subshares
            .iter()
            .any(|(idx, _)| *idx == subshare.dealer_index)
        {
            return Ok(false);
        }

        // verify sub-share against commitment. A failure is a complaint: it
        // names the dealer, so the caller can broadcast it and disqualify.
        if !commitment.verify_subshare(self.player_index, subshare.value()) {
            return Err(OsstError::InvalidSubShare(subshare.dealer_index));
        }

        self.subshares
            .push((subshare.dealer_index, subshare.value().clone()));
        self.constant_commitments
            .push(commitment.share_commitment().clone());

        Ok(true)
    }

    /// Derive group public key: Y = sum(C_{i,0}) over the dealer set.
    /// Errors until every dealer in the set has delivered.
    pub fn derive_group_key(&self) -> Result<P, OsstError> {
        self.require_complete()?;
        let mut key = P::identity();
        for c0 in &self.constant_commitments {
            key = key.add(c0);
        }
        Ok(key)
    }

    fn require_complete(&self) -> Result<(), OsstError> {
        if !self.is_complete() {
            return Err(OsstError::InsufficientContributions {
                got: self.subshares.len(),
                need: self.dealer_set.len(),
            });
        }
        Ok(())
    }

    /// Aggregate final share: s_j = sum_{i in S} f_i(j)
    pub fn finalize(&self) -> Result<P::Scalar, OsstError> {
        self.require_complete()?;
        let mut share = P::Scalar::zero();
        for (_, value) in &self.subshares {
            share = share.add(value);
        }
        Ok(share)
    }
}

impl<P: OsstPoint> core::fmt::Debug for Aggregator<P> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("dkg::Aggregator")
            .field("player_index", &self.player_index)
            .field("dealer_set", &self.dealer_set)
            .field("count", &self.subshares.len())
            .finish()
    }
}

// ============================================================================
// On-chain coordination
// ============================================================================

/// DKG round state for on-chain coordination.
///
/// Tracks commitments from all participants. Once all n commitments are in,
/// players can verify sub-shares and derive their final shares.
#[derive(Clone, Debug)]
pub struct DkgState<P: OsstPoint> {
    /// Epoch being generated
    pub epoch: u64,
    /// Threshold for the new key
    pub threshold: u32,
    /// Total number of participants (all are dealers)
    pub num_participants: u32,
    /// Collected commitments (indexed by dealer_index - 1)
    pub commitments: Vec<Option<DealerCommitment<P>>>,
    /// Dealers disqualified by a complaint, sorted ascending.
    disqualified: Vec<u32>,
}

impl<P: OsstPoint> DkgState<P> {
    pub fn new(epoch: u64, threshold: u32, num_participants: u32) -> Self {
        Self {
            epoch,
            threshold,
            num_participants,
            commitments: vec![None; num_participants as usize],
            disqualified: Vec::new(),
        }
    }

    /// Submit a dealer's round-1 package. Returns true if new, false if
    /// duplicate.
    ///
    /// The proof of knowledge is verified here, before the commitment is
    /// recorded (K-1): a dealer that cannot prove knowledge of its constant
    /// term never enters the ceremony.
    ///
    /// # Errors
    ///
    /// [`OsstError::InvalidProofOfKnowledge`] naming the dealer;
    /// [`OsstError::InvalidIndex`] for an out-of-range index;
    /// [`OsstError::InvalidCommitment`] on a threshold mismatch;
    /// [`OsstError::UnexpectedDealer`] if the dealer is disqualified.
    pub fn submit_commitment(&mut self, package: Round1Package<P>) -> Result<bool, OsstError> {
        package.verify(self.epoch)?;
        let commitment = package.commitment;
        if self.disqualified.contains(&commitment.dealer_index) {
            return Err(OsstError::UnexpectedDealer(commitment.dealer_index));
        }
        let idx = commitment
            .dealer_index
            .checked_sub(1)
            .ok_or(OsstError::InvalidIndex)? as usize;

        if idx >= self.commitments.len() {
            return Err(OsstError::InvalidIndex);
        }

        if commitment.threshold() != self.threshold {
            return Err(OsstError::InvalidCommitment);
        }

        if self.commitments[idx].is_some() {
            return Ok(false);
        }

        self.commitments[idx] = Some(commitment);
        Ok(true)
    }

    /// Number of commitments received
    pub fn commitment_count(&self) -> usize {
        self.commitments.iter().filter(|c| c.is_some()).count()
    }

    /// True when every participant that has not been disqualified has
    /// submitted a commitment.
    pub fn is_complete(&self) -> bool {
        self.commitment_count() + self.disqualified.len() == self.num_participants as usize
    }

    /// Dealers disqualified by a complaint.
    #[inline]
    pub fn disqualified(&self) -> &[u32] {
        &self.disqualified
    }

    /// Dealers still in the ceremony, in ascending order.
    pub fn qualified_dealers(&self) -> Vec<u32> {
        self.commitments
            .iter()
            .flatten()
            .map(|c| c.dealer_index)
            .collect()
    }

    /// Disqualify a dealer named by a complaint — an invalid proof of
    /// knowledge ([`OsstError::InvalidProofOfKnowledge`]) or an invalid
    /// sub-share ([`OsstError::InvalidSubShare`]), both of which carry the
    /// index to pass here.
    ///
    /// The dealer's commitment is dropped, so it contributes nothing to the
    /// group key or to any verification share, and further submissions from it
    /// are refused.
    ///
    /// # This is a local mutation, and osst provides no agreement (M-6)
    ///
    /// Every participant must apply the same complaints or they derive
    /// different keys — and nothing in this crate makes that true. The 0.4.0
    /// doc said the first half and not the second, which reads as if the
    /// library were handling it.
    ///
    /// What osst does provide is [`Complaint`]: signed by the accuser's roster
    /// identity, bound to `(epoch, session_id, round)`, carrying evidence a
    /// third party re-runs, with a verdict that distinguishes a real offence
    /// from a false accusation. What it does not and cannot provide is
    /// reliable broadcast — so a caller without one must not run this
    /// protocol, because the two policies left are "believe every packet",
    /// which lets one unauthenticated message abort the ceremony, and "believe
    /// none", which makes K-1 undetectable again.
    ///
    /// Verify a [`Complaint`] and act only on
    /// [`ComplaintVerdict::Upheld`]; re-broadcast it; and for
    /// [`ComplaintEvidence::BadSubShare`], which is checkable but not
    /// attributable, require `t` independent complaints against the same
    /// dealer — [`ComplaintTally`] is that rule.
    ///
    /// # Errors
    ///
    /// [`OsstError::InvalidIndex`] for an out-of-range index;
    /// [`OsstError::DkgAborted`] when fewer than `threshold` dealers remain —
    /// the ceremony cannot produce a usable key and must be restarted.
    pub fn disqualify(&mut self, dealer_index: u32) -> Result<(), OsstError> {
        let idx = dealer_index.checked_sub(1).ok_or(OsstError::InvalidIndex)? as usize;
        if idx >= self.commitments.len() {
            return Err(OsstError::InvalidIndex);
        }
        self.commitments[idx] = None;
        if !self.disqualified.contains(&dealer_index) {
            self.disqualified.push(dealer_index);
            self.disqualified.sort_unstable();
        }

        let remaining = self.num_participants as usize - self.disqualified.len();
        if remaining < self.threshold as usize {
            return Err(OsstError::DkgAborted {
                qualified: remaining,
                need: self.threshold as usize,
            });
        }
        Ok(())
    }

    /// Derive group public key from the qualified commitments: Y = sum(C_{i,0})
    ///
    /// # Warning
    ///
    /// This sums commitments; it does **not** witness the sub-share round. A
    /// deployment that fixes the group key from on-chain commitments before
    /// round 2 completes lets a dealer that never delivers valid sub-shares
    /// still move `Y` — disqualify it and re-derive, or wait for
    /// [`Aggregator::is_complete`].
    ///
    /// Note also the standard Pedersen-DKG caveat (GJKR99): commitments are
    /// accepted in any order with no commit–reveal, so the last dealer to
    /// publish sees every other `C_{i,0}` before choosing its own and an
    /// abort-and-retry strategy can bias the distribution of `Y`. For Schnorr
    /// signatures this is known and tolerated.
    pub fn derive_group_key(&self) -> Result<P, OsstError> {
        if !self.is_complete() {
            return Err(OsstError::InsufficientContributions {
                got: self.commitment_count(),
                need: self.num_participants as usize - self.disqualified.len(),
            });
        }

        let mut key = P::identity();
        for commitment in self.commitments.iter().flatten() {
            key = key.add(commitment.share_commitment());
        }

        Ok(key)
    }

    /// Derive public verification share for player j.
    ///
    /// Y_j = g^{s_j} = Σ_i C_i.evaluate_at(j).expect("index is 1-indexed by construction")
    ///
    /// These are needed for FROST share verification — detecting which
    /// signer produced a bad signature share without revealing secrets.
    pub fn derive_verification_share(&self, player_index: u32) -> Result<P, OsstError> {
        if player_index == 0 {
            return Err(OsstError::InvalidIndex);
        }
        if !self.is_complete() {
            return Err(OsstError::InsufficientContributions {
                got: self.commitment_count(),
                need: self.num_participants as usize - self.disqualified.len(),
            });
        }

        let mut vshare = P::identity();
        for commitment in self.commitments.iter().flatten() {
            vshare = vshare.add(&commitment.evaluate_at(player_index).expect("index is 1-indexed by construction"));
        }

        Ok(vshare)
    }

    /// Derive all verification shares for players 1..=num_participants.
    ///
    /// Returns a BTreeMap suitable for passing to [`crate::frost::aggregate`].
    pub fn derive_all_verification_shares(
        &self,
    ) -> Result<alloc::collections::BTreeMap<u32, P>, OsstError> {
        let mut map = alloc::collections::BTreeMap::new();
        for j in 1..=self.num_participants {
            map.insert(j, self.derive_verification_share(j)?);
        }
        Ok(map)
    }

    /// Get all submitted commitments
    pub fn get_commitments(&self) -> Vec<&DealerCommitment<P>> {
        self.commitments.iter().filter_map(|c| c.as_ref()).collect()
    }
}



// ============================================================================
// Justified complaints (M-6)
// ============================================================================

/// Domain tag for the complaint signature message.
pub const COMPLAINT_SIG_DOMAIN: &[u8] = b"osst/dkg-complaint/v1";

/// Domain tag for the commitment digest carried in a sealed package and named
/// by [`BadSubShareEvidence::agreed_digest`].
///
/// It lives here rather than in [`crate::sealed`] — which re-exports it — so
/// that a complaint verifier compiled without the `sealed` feature can still
/// recompute it.
pub const COMMITMENT_DIGEST_DOMAIN: &[u8] = b"osst/sealed/commitment/v1";

/// Digest of a dealer's Feldman commitment: `SHA-512(domain ‖ bytes)[..32]`.
///
/// Two things name a commitment by this digest. [`crate::sealed`] puts it
/// inside the sealed plaintext so a sub-share and the commitment it is checked
/// against cannot be sourced separately (D-2), and
/// [`BadSubShareEvidence::agreed_digest`] uses it so a complaint says *which*
/// commitment it is a complaint about — which a verifier then insists is the
/// one in its own [`AgreedRound1`].
pub fn commitment_digest<P: OsstPoint>(commitment: &DealerCommitment<P>) -> [u8; 32] {
    use sha2::{Digest, Sha512};
    let mut h = Sha512::new();
    h.update(COMMITMENT_DIGEST_DOMAIN);
    h.update(commitment.to_bytes());
    let full: [u8; 64] = h.finalize().into();
    let mut out = [0u8; 32];
    out.copy_from_slice(&full[..32]);
    out
}

/// A sub-share a recipient decrypted and which fails the Feldman check against
/// the dealer's **agreed** commitment.
///
/// Produced by
/// [`sealed::open_subshare_agreed_with_evidence`](crate::sealed::open_subshare_agreed_with_evidence)
/// and carried by [`ComplaintEvidence::BadSubShare`].
///
/// # What a verifier can and cannot conclude
///
/// Everything here is checkable by a third party *except* provenance. Given
/// this struct and its own [`AgreedRound1`], any participant recomputes
/// `g^{s} == Π C_j^{i^j}` and learns, with certainty and without trusting the
/// accuser, that **this scalar is not a valid sub-share of that commitment for
/// that recipient**.
///
/// It does not learn that the dealer sent it. Noise_K authenticates the sender
/// *to the recipient* and nothing more: the recipient holds a key that can
/// produce any plaintext it likes, so an accuser can fabricate a scalar that
/// fails the check just as easily as it can report one. `sealed_digest` pins
/// the accusation to one delivered ciphertext, which stops an accusation in
/// the abstract, but a verifier cannot open that ciphertext either.
///
/// **Therefore a single upheld complaint of this kind must never disqualify a
/// dealer.** Use [`ComplaintTally`], which requires `t` distinct accusers
/// against the same dealer. See [`ComplaintEvidence`] for the residual that
/// remains even then.
///
/// # Why revealing the scalar is acceptable
///
/// `subshare` is one evaluation, at one recipient's index, of one dealer's
/// polynomial for one coefficient — secret-ish material, and publishing it is
/// a real disclosure that deserves an argument rather than a shrug.
///
/// The argument is that the scalar being published is, by the verdict's own
/// definition, *not* an evaluation of the agreed polynomial. An `Upheld`
/// verdict says exactly `g^{s} != Π C_j^{i^j}`: the value discloses nothing
/// about the dealer's agreed polynomial, nothing about the group key derived
/// from the agreed commitments, and nothing about the recipient's real share,
/// because it is not a point on the curve's polynomial at all. An `Unfounded`
/// verdict is the case where a genuine sub-share *was* published — and there
/// the accuser has burned one of its own share components to make a false
/// accusation, which is a cost to the accuser and, at one point of a
/// degree-`t-1` polynomial, not a break.
///
/// The disclosure that is *not* covered by that argument is a dealer's own
/// honest sub-share to a recipient that then complains falsely: that is the
/// `Unfounded` case above, it is bounded at `t-1` such points before the
/// polynomial is reconstructible, and every one of them names its accuser.
///
/// The type still [zeroizes on drop](zeroize::ZeroizeOnDrop) and redacts the
/// scalar from its `Debug`, because "acceptable to publish deliberately" is
/// not the same as "fine to leave in a core dump".
#[derive(Clone, PartialEq, Eq, zeroize::Zeroize, zeroize::ZeroizeOnDrop)]
pub struct BadSubShareEvidence {
    /// The accused dealer's index.
    pub dealer_index: u32,
    /// The complaining recipient's index — the `i` the Feldman check is
    /// evaluated at.
    pub recipient_index: u32,
    /// The ceremony's session id, as in the sealed roster's prologue.
    pub session_id: [u8; 32],
    /// The round the package was delivered in.
    pub round: u8,
    /// The decrypted sub-share scalar, canonical bytes. Secret-ish; see above.
    pub subshare: [u8; 32],
    /// [`commitment_digest`] of the dealer's commitment **in the agreed
    /// round-1 set**. A verifier recomputes this from its own
    /// [`AgreedRound1`] and refuses the complaint if it differs, so the
    /// accuser cannot choose the commitment its evidence is checked against.
    pub agreed_digest: [u8; 32],
    /// [`sealed::sealed_ciphertext_digest`](crate::sealed::sealed_ciphertext_digest)
    /// of the package as delivered.
    pub sealed_digest: [u8; 32],
}

impl core::fmt::Debug for BadSubShareEvidence {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("BadSubShareEvidence")
            .field("dealer_index", &self.dealer_index)
            .field("recipient_index", &self.recipient_index)
            .field("round", &self.round)
            .field("subshare", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}

impl BadSubShareEvidence {
    /// The bytes the complaint signature covers, length-prefixed throughout.
    fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(109);
        out.extend_from_slice(&self.dealer_index.to_le_bytes());
        out.extend_from_slice(&self.recipient_index.to_le_bytes());
        out.extend_from_slice(&self.session_id);
        out.push(self.round);
        out.extend_from_slice(&self.subshare);
        out.extend_from_slice(&self.agreed_digest);
        out.extend_from_slice(&self.sealed_digest);
        out
    }
}

/// What a complaint accuses a dealer of, and the evidence for it.
///
/// # How verifiable each kind is
///
/// The two kinds are **not** equally strong, and pretending otherwise is how a
/// complaint mechanism becomes a denial-of-service channel.
///
/// - [`ForgedProofOfKnowledge`](Self::ForgedProofOfKnowledge) is fully
///   self-contained. The round-1 package is public and signed by nothing, so a
///   third party re-runs [`Round1Package::verify`] and reaches the same
///   verdict with no trust in the accuser at all. A false accusation of this
///   kind is detected immediately, because the evidence simply verifies.
///
/// - [`BadSubShare`](Self::BadSubShare) is weaker, and the limit is a property
///   of Noise_K rather than of this API. The accuser reveals the sub-share
///   scalar it decrypted, and names the dealer's commitment by the digest of
///   the entry in the **agreed** round-1 set; any third party then re-runs the
///   Feldman check `g^{s} == Π C_j^{i^j}` against the commitment in *its own*
///   [`AgreedRound1`] and confirms, with no trust in the accuser, that this
///   scalar is not a valid sub-share of that commitment for that recipient.
///
///   What nobody but the recipient can confirm is that the dealer actually
///   sent it. Noise_K gives the recipient authentication, not transferability:
///   the recipient holds a key that would have produced any plaintext, so it
///   can fabricate one. The sealed ciphertext digest pins the accusation to
///   one delivered package, and a future extension in which the accuser also
///   reveals its ephemeral/session key could upgrade this to a transferable
///   proof — but as it stands the verdict means *"this scalar is not a valid
///   sub-share for that commitment"*, not *"the dealer sent it"*.
///
/// # The consequence: never act on one `BadSubShare` complaint
///
/// Because a fabricated scalar fails the Feldman check exactly as a genuinely
/// bad one does, `Upheld` and `Unfounded` **cannot** distinguish an honest
/// recipient from a lying one. `Unfounded` only ever appears when an accuser
/// complains about a sub-share that is in fact valid — a mistake, not the
/// attack.
///
/// The gate is therefore quorum, not adjudication: require `t` **distinct**
/// accusers with `Upheld` verdicts against the same dealer before
/// disqualifying it. [`ComplaintTally`] is that rule, and
/// [`Complaint::verify`] deliberately returns a verdict rather than an action
/// so a caller cannot skip it.
///
/// # The residual the tally itself leaves (GJKR dealer defence)
///
/// `t`-gating trades one problem for a smaller one. A dealer that sends bad
/// sub-shares to at most `t-1` recipients is never disqualified, and those
/// recipients hold no usable share from it — so they must not finalize a key
/// package, while the rest can. That is exclusion, not a split key, and it is
/// detectable (the excluded nodes say so) but not attributable.
///
/// Closing it needs the round this crate does not have: the GJKR dealer
/// defence, in which an accused dealer publishes `f_i(j)` for each complainant
/// and everyone checks it, which makes provenance public and removes the need
/// for a tally at all. It needs a reliable broadcast and a timeout, neither of
/// which a `no_std` library can provide, so it is documented here and left to
/// the protocol layer.
///
/// # Revealing the sub-share
///
/// See [`BadSubShareEvidence`] for why publishing the scalar is acceptable —
/// in short, an `Upheld` verdict is a proof that the published value is *not*
/// a point on the agreed polynomial, so it discloses nothing about the agreed
/// commitments, the group key, or the recipient's real share.
#[derive(Clone, Debug)]
pub enum ComplaintEvidence<P: OsstPoint> {
    /// The dealer's round-1 package, whose proof of knowledge does not verify.
    /// Publicly checkable by anyone (K-1).
    ForgedProofOfKnowledge { package: Round1Package<P> },
    /// A scalar the accuser says it decrypted from the dealer's sealed round-2
    /// package, which fails the Feldman check against the dealer's entry in
    /// the agreed round-1 set.
    ///
    /// The commitment is *not* carried: it is named by
    /// [`BadSubShareEvidence::agreed_digest`] and supplied by the verifier
    /// from its own [`AgreedRound1`], so an accuser cannot choose what its
    /// evidence is checked against. Checkable by anyone; attributable to the
    /// dealer by nobody — see above.
    BadSubShare { evidence: BadSubShareEvidence },
}

impl<P: OsstPoint> ComplaintEvidence<P> {
    /// The dealer this evidence is about.
    pub fn accused_index(&self) -> u32 {
        match self {
            Self::ForgedProofOfKnowledge { package } => package.dealer_index(),
            Self::BadSubShare { evidence } => evidence.dealer_index,
        }
    }

    fn encode_into(&self, out: &mut Vec<u8>) {
        fn field(out: &mut Vec<u8>, bytes: &[u8]) {
            out.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
            out.extend_from_slice(bytes);
        }
        match self {
            Self::ForgedProofOfKnowledge { package } => {
                out.push(1);
                field(out, &package.commitment.to_bytes());
                field(out, package.proof_of_knowledge.r.compress().as_ref());
                field(out, &package.proof_of_knowledge.z.to_bytes());
            }
            Self::BadSubShare { evidence } => {
                out.push(2);
                field(out, &evidence.encode());
            }
        }
    }
}

/// What a verifier concluded about a complaint whose signature checked out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ComplaintVerdict {
    /// The evidence holds: the accused dealer really did misbehave, as far as
    /// this evidence can show (see [`ComplaintEvidence`] for how far that is).
    /// Disqualify it.
    Upheld,
    /// The complaint is authentic — the accuser really signed it — but the
    /// evidence does not show what it claims: the proof of knowledge verifies,
    /// or the revealed sub-share is a correct evaluation of the commitment.
    /// The accuser, not the accused, is the problem.
    Unfounded,
}

/// A signed, ceremony-bound, justified complaint against a dealer.
///
/// # Why this exists (M-6)
///
/// `DkgState::disqualify` is a local mutation whose correctness needs every
/// participant to apply the same complaints, and through 0.4.x osst provided
/// nothing to make that true. A complaint was not a value at all, let alone a
/// verifiable one, so the only two policies available to a caller were
/// "believe everyone" — one packet aborts the ceremony — and "believe no-one",
/// which makes K-1 undetectable again. narsild chose the first.
///
/// A complaint here is signed by the accuser's **roster identity key** and
/// bound to `(epoch, session_id, round)`, so it cannot be forged, cannot be
/// replayed into a later ceremony, and names who to blame if it turns out to
/// be [`Unfounded`](ComplaintVerdict::Unfounded).
///
/// # Why a Schnorr key on the curve, and not the roster's X25519 key
///
/// The options were: reuse the X25519 static key from
/// [`SealedRoster`](crate::sealed::SealedRoster) via an XEdDSA-style
/// conversion; add an ed25519 identity and a dependency; or sign with a
/// Schnorr key on the curve the ceremony already uses.
///
/// The third is what this does. The accuser's *verification share* is not
/// available — a complaint is raised during the DKG that produces it — so the
/// key has to be a long-term identity key either way, and once a new key is
/// needed, the cheapest sound one is a scalar on `P`: it reuses the curve
/// backend already compiled in, works in `no_std` with no new dependency, and
/// the Schnorr verification is the same equation the crate already implements
/// three times. XEdDSA over the X25519 static key was rejected as the
/// clamping and sign-bit handling are easy to get subtly wrong and this is not
/// the place to hand-roll it.
///
/// **The roster must therefore bind an identity public key per participant.**
/// osst does not own the roster — the caller does — so this API verifies
/// against a public key the caller supplies. What that means for a deployment
/// is written out in the crate README and repeated here: the identity keys
/// must be part of the same signed roster/manifest whose hash is the ceremony
/// id, or an attacker supplies the key as well as the complaint.
///
/// # What a caller (narsild) still has to do
///
/// osst provides the value, the binding and the verifier. Agreement is not
/// something a library can provide:
///
/// 1. Re-broadcast every complaint on receipt. A complaint delivered to one
///    node aborts that node while the rest finalize — the split-group outcome
///    the broadcast exists to prevent.
/// 2. Verify with [`verify`](Self::verify) against the accuser's roster
///    identity key before acting, and drop anything that does not check —
///    including [`Unfounded`](ComplaintVerdict::Unfounded), which should
///    count against the *accuser*.
/// 3. Apply the same set of upheld complaints on every node, in the same
///    ceremony, before deriving a key. [`DkgState::disqualify`] mutates local
///    state only.
/// 4. For [`BadSubShare`](ComplaintEvidence::BadSubShare), which is not
///    transferable (see [`ComplaintEvidence`]), require `t` independent
///    complaints against the same dealer before disqualifying, rather than
///    acting on one.
/// 5. Bound the complaint intake: a complaint is attacker-supplied input, and
///    there is no `reason: String` here precisely so there is nothing
///    unbounded to log.
#[derive(Clone, Debug)]
pub struct Complaint<P: OsstPoint> {
    /// The ceremony this complaint belongs to.
    pub epoch: u64,
    /// The ceremony's session id — the roster/manifest hash, as used for the
    /// sealed prologue.
    pub session_id: [u8; 32],
    /// Which round the offence was observed in (1 or 2).
    pub round: u8,
    /// The complainant's roster index.
    pub accuser_index: u32,
    /// The accused dealer's index. Must agree with the evidence.
    pub accused_index: u32,
    /// What the dealer is accused of, and the proof.
    pub evidence: ComplaintEvidence<P>,
    /// Schnorr signature by the accuser's identity key: `R = k·G`,
    /// `s = k + e·x`, `e = H(domain ‖ R ‖ Y_accuser ‖ body)`.
    pub r: P,
    /// The signature scalar.
    pub s: P::Scalar,
}

impl<P: OsstPoint> Complaint<P> {
    /// The signed body: everything but the signature, length-prefixed
    /// throughout so the encoding is injective.
    fn body(
        epoch: u64,
        session_id: &[u8; 32],
        round: u8,
        accuser_index: u32,
        accused_index: u32,
        evidence: &ComplaintEvidence<P>,
    ) -> Vec<u8> {
        let mut out = Vec::new();
        out.extend_from_slice(&(COMPLAINT_SIG_DOMAIN.len() as u64).to_le_bytes());
        out.extend_from_slice(COMPLAINT_SIG_DOMAIN);
        out.extend_from_slice(&epoch.to_le_bytes());
        out.extend_from_slice(session_id);
        out.push(round);
        out.extend_from_slice(&accuser_index.to_le_bytes());
        out.extend_from_slice(&accused_index.to_le_bytes());
        evidence.encode_into(&mut out);
        out
    }

    fn challenge(r: &P, accuser_pubkey: &P, body: &[u8]) -> P::Scalar {
        use sha2::{Digest, Sha512};
        let mut h = Sha512::new();
        h.update(COMPLAINT_SIG_DOMAIN);
        h.update(r.compress());
        h.update(accuser_pubkey.compress());
        h.update((body.len() as u64).to_le_bytes());
        h.update(body);
        let hash: [u8; 64] = h.finalize().into();
        P::Scalar::from_bytes_wide(&hash)
    }

    /// Raise a complaint, signed by the accuser's long-term identity key.
    ///
    /// `accused_index` is taken from the evidence, so a complaint cannot name
    /// one dealer and carry another's package.
    pub fn sign<R: rand_core::RngCore + rand_core::CryptoRng>(
        epoch: u64,
        session_id: [u8; 32],
        round: u8,
        accuser_index: u32,
        evidence: ComplaintEvidence<P>,
        accuser_identity_secret: &P::Scalar,
        rng: &mut R,
    ) -> Result<Self, OsstError> {
        if accuser_index == 0 {
            return Err(OsstError::InvalidIndex);
        }
        let accused_index = evidence.accused_index();
        let body = Self::body(
            epoch,
            &session_id,
            round,
            accuser_index,
            accused_index,
            &evidence,
        );
        let accuser_pubkey = P::generator().mul_scalar(accuser_identity_secret);

        let k = P::Scalar::random(rng);
        let r = P::generator().mul_scalar(&k);
        let e = Self::challenge(&r, &accuser_pubkey, &body);
        let s = k.add(&e.mul(accuser_identity_secret));

        Ok(Self {
            epoch,
            session_id,
            round,
            accuser_index,
            accused_index,
            evidence,
            r,
            s,
        })
    }

    /// Verify a complaint that any third party received.
    ///
    /// Checks, in order: that it belongs to this ceremony; that the accused
    /// index agrees with the evidence; that the signature verifies under the
    /// accuser's identity key; and finally whether the evidence actually shows
    /// what it claims.
    ///
    /// `accuser_identity_pubkey` must come from the ceremony's signed roster.
    /// Passing a key the complaint itself supplied verifies nothing.
    ///
    /// `agreed` is **this verifier's own** confirmed round-1 set, and it is
    /// what makes a [`BadSubShare`](ComplaintEvidence::BadSubShare) complaint
    /// checkable: the Feldman equation is recomputed against the commitment
    /// found there, never against anything the complaint carried. `None` is
    /// accepted for a round-1 complaint, which is self-contained and can be
    /// adjudicated before any agreed set exists; a `BadSubShare` complaint
    /// with `None` is [`OsstError::InvalidComplaint`], because there is
    /// nothing sound to check it against.
    ///
    /// An `Ok(`[`ComplaintVerdict::Upheld`]`)` for `BadSubShare` is **not** a
    /// licence to disqualify — see [`ComplaintEvidence`] and
    /// [`ComplaintTally`].
    ///
    /// # Errors
    ///
    /// [`OsstError::InvalidComplaint`] for the wrong ceremony, an index or a
    /// binding that disagrees with the evidence, a signature that does not
    /// verify, a `BadSubShare` complaint whose `agreed_digest` is not the
    /// digest of the dealer's commitment in `agreed`, or one whose scalar is
    /// not a canonical field element;
    /// [`OsstError::UnexpectedDealer`] when `agreed` holds no commitment for
    /// the accused. A complaint that is authentic but wrong returns
    /// `Ok(`[`ComplaintVerdict::Unfounded`]`)`, not an error: the distinction
    /// matters, because one is a forgery and the other is a named participant
    /// making a false accusation.
    pub fn verify(
        &self,
        epoch: u64,
        session_id: &[u8; 32],
        accuser_identity_pubkey: &P,
        agreed: Option<&AgreedRound1<P>>,
    ) -> Result<ComplaintVerdict, OsstError> {
        if self.epoch != epoch || &self.session_id != session_id {
            return Err(OsstError::InvalidComplaint);
        }
        if self.accuser_index == 0
            || self.accused_index == 0
            || self.accused_index != self.evidence.accused_index()
        {
            return Err(OsstError::InvalidComplaint);
        }

        let body = Self::body(
            self.epoch,
            &self.session_id,
            self.round,
            self.accuser_index,
            self.accused_index,
            &self.evidence,
        );
        let e = Self::challenge(&self.r, accuser_identity_pubkey, &body);
        // s·G == R + e·Y
        if P::generator().mul_scalar(&self.s)
            != self.r.add(&accuser_identity_pubkey.mul_scalar(&e))
        {
            return Err(OsstError::InvalidComplaint);
        }

        self.adjudicate(agreed)
    }

    /// Re-run the evidence, without checking the signature.
    ///
    /// Exposed because it is the half a verifier can run with no roster at all
    /// — useful for logging and triage — but a caller must not act on it:
    /// without [`verify`](Self::verify) there is nothing tying the complaint
    /// to a participant, and anyone can manufacture one.
    ///
    /// `agreed` is the verifier's own confirmed round-1 set; see
    /// [`verify`](Self::verify) for why a
    /// [`BadSubShare`](ComplaintEvidence::BadSubShare) complaint cannot be
    /// adjudicated without one.
    ///
    /// # Errors
    ///
    /// As [`verify`](Self::verify), minus the signature and ceremony checks.
    pub fn adjudicate(
        &self,
        agreed: Option<&AgreedRound1<P>>,
    ) -> Result<ComplaintVerdict, OsstError> {
        match &self.evidence {
            ComplaintEvidence::ForgedProofOfKnowledge { package } => {
                if package.dealer_index() != self.accused_index {
                    return Ok(ComplaintVerdict::Unfounded);
                }
                // upheld exactly when the proof does NOT verify
                Ok(match package.verify(self.epoch) {
                    Ok(()) => ComplaintVerdict::Unfounded,
                    Err(_) => ComplaintVerdict::Upheld,
                })
            }
            ComplaintEvidence::BadSubShare { evidence } => {
                // The evidence repeats the complaint's own binding. If the two
                // ever disagree the binding is decorative, so insist.
                if evidence.dealer_index != self.accused_index
                    || evidence.recipient_index != self.accuser_index
                    || evidence.session_id != self.session_id
                    || evidence.round != self.round
                {
                    return Err(OsstError::InvalidComplaint);
                }
                let agreed = agreed.ok_or(OsstError::InvalidComplaint)?;
                if agreed.epoch() != self.epoch {
                    return Err(OsstError::InvalidComplaint);
                }
                // The commitment comes from the verifier's agreed set, and the
                // accuser only gets to *name* it. A digest that does not match
                // means the two are not looking at the same ceremony — which
                // is never an offence by the accused.
                let commitment = agreed.commitment(evidence.dealer_index)?;
                if commitment_digest(commitment) != evidence.agreed_digest {
                    return Err(OsstError::InvalidComplaint);
                }
                // A non-canonical scalar never came out of `decode_plaintext`,
                // so the evidence is malformed rather than damning.
                let scalar = P::Scalar::from_canonical_bytes(&evidence.subshare)
                    .ok_or(OsstError::InvalidComplaint)?;

                // g^{s} == Π C_j^{i^j}
                Ok(
                    if commitment.verify_subshare(evidence.recipient_index, &scalar) {
                        ComplaintVerdict::Unfounded
                    } else {
                        ComplaintVerdict::Upheld
                    },
                )
            }
        }
    }
}

// ============================================================================
// Quorum over non-transferable complaints (M-6 residual)
// ============================================================================

/// Counts distinct accusers per accused dealer, and gates disqualification on
/// `t` of them.
///
/// # Why a library type and not a caller's `HashMap`
///
/// [`ComplaintEvidence::BadSubShare`] is checkable but not attributable: an
/// `Upheld` verdict proves a scalar is not a valid sub-share for a commitment,
/// and cannot prove the dealer produced it. A fabricated scalar is `Upheld`
/// too. So the only sound disqualification rule is a quorum — `t` distinct
/// accusers against the same dealer, where `t` is the ceremony threshold, so
/// that no coalition small enough to be tolerated can frame an honest dealer.
///
/// That rule has three ways to get it wrong quietly (counting one accuser
/// twice, counting self-accusations, comparing against `n` rather than `t`),
/// and it is the rule a caller is most tempted to skip. It is therefore a type
/// here rather than a sentence in a doc comment.
///
/// A [`ForgedProofOfKnowledge`](ComplaintEvidence::ForgedProofOfKnowledge)
/// verdict needs no tally — it is fully transferable and one is enough — but
/// recording it here anyway is harmless and keeps one accounting of the
/// ceremony's accusations.
///
/// # What it does not do
///
/// It does not verify anything. Feed it only verdicts from
/// [`Complaint::verify`], and only once per `(accuser, accused)` pair —
/// duplicates are idempotent, so a re-broadcast complaint seen twice does not
/// count twice, but a caller must still not feed it an unverified complaint.
///
/// See [`ComplaintEvidence`] for the residual the tally leaves: a dealer that
/// cheats at most `t-1` recipients is never disqualified, and those recipients
/// must decline to finalize rather than proceed.
///
/// # Example
///
/// ```text
/// let mut tally = ComplaintTally::new(threshold);
/// for c in verified_complaints {
///     tally.record(c.accuser_index, c.accused_index, verdict)?;
/// }
/// for dealer in tally.disqualifiable() {
///     state.disqualify(dealer)?;
/// }
/// ```
#[derive(Clone, Debug)]
pub struct ComplaintTally {
    threshold: u32,
    /// accused -> distinct accusers with an `Upheld` verdict
    upheld: BTreeMap<u32, BTreeSet<u32>>,
    /// accusers whose complaint was authentic but `Unfounded`
    flagged: BTreeSet<u32>,
}

impl ComplaintTally {
    /// A tally gated on the ceremony threshold `t`.
    pub fn new(threshold: u32) -> Self {
        Self {
            threshold,
            upheld: BTreeMap::new(),
            flagged: BTreeSet::new(),
        }
    }

    /// The threshold a dealer's accuser count must reach.
    #[inline]
    pub fn threshold(&self) -> u32 {
        self.threshold
    }

    /// Record one **verified** complaint's verdict.
    ///
    /// Recording the same `(accuser, accused)` pair again changes nothing, so
    /// a re-broadcast complaint cannot inflate a count.
    ///
    /// # Errors
    ///
    /// [`OsstError::InvalidIndex`] for a zero index or a self-accusation — a
    /// participant accusing itself is either a bug or an attempt to buy a
    /// vote, and neither should reach a count.
    pub fn record(
        &mut self,
        accuser: u32,
        accused: u32,
        verdict: ComplaintVerdict,
    ) -> Result<(), OsstError> {
        if accuser == 0 || accused == 0 || accuser == accused {
            return Err(OsstError::InvalidIndex);
        }
        match verdict {
            ComplaintVerdict::Upheld => {
                self.upheld.entry(accused).or_default().insert(accuser);
            }
            ComplaintVerdict::Unfounded => {
                self.flagged.insert(accuser);
            }
        }
        Ok(())
    }

    /// How many distinct accusers hold an upheld complaint against `accused`.
    pub fn count(&self, accused: u32) -> usize {
        self.upheld.get(&accused).map_or(0, |s| s.len())
    }

    /// The accusers of `accused`, ascending.
    pub fn accusers(&self, accused: u32) -> Vec<u32> {
        self.upheld
            .get(&accused)
            .map(|s| s.iter().copied().collect())
            .unwrap_or_default()
    }

    /// Whether `accused` has reached the threshold and may be disqualified.
    pub fn reached(&self, accused: u32) -> bool {
        self.count(accused) >= self.threshold as usize
    }

    /// Every dealer that has reached the threshold, ascending.
    pub fn disqualifiable(&self) -> Vec<u32> {
        self.upheld
            .keys()
            .copied()
            .filter(|d| self.reached(*d))
            .collect()
    }

    /// Dealers with at least one upheld complaint but fewer than `t`, with
    /// their accusers — the exclusion residual, for the end-of-ceremony log.
    pub fn below_threshold(&self) -> Vec<(u32, Vec<u32>)> {
        self.upheld
            .iter()
            .filter(|(d, _)| !self.reached(**d))
            .map(|(d, a)| (*d, a.iter().copied().collect()))
            .collect()
    }

    /// Accusers that made an authentic but unfounded accusation, ascending.
    pub fn flagged_accusers(&self) -> Vec<u32> {
        self.flagged.iter().copied().collect()
    }
}

// ============================================================================
// Echo round over the round-1 set (M-5)
// ============================================================================

/// Domain tag for the round-1 echo digest.
pub const ECHO_DIGEST_DOMAIN: &[u8] = b"osst/dkg-round1-echo/v1";

/// A participant's view of the whole round-1 commitment set, as one hash.
///
/// # What this is for (M-5)
///
/// [`crate::sealed`] binds a sub-share to the commitment it is verified
/// against, as that commitment was *delivered to this recipient* (D-2). That
/// stops a man-in-the-middle substituting a matched pair. It does not stop the
/// **dealer**, which is the stronger and more relevant adversary: a malicious
/// dealer sends `(C_A, f_A(a))` to Alice and `(C_B, f_B(b))` to Bob, each pair
/// internally consistent, each passing its Feldman check and its digest check.
/// Alice and Bob derive different group keys and neither can tell.
///
/// Nothing in a point-to-point protocol can detect that, because the two
/// honest parties never compare notes. The standard construction is an echo
/// round: after round 1 closes, every participant publishes a digest of the
/// **full** commitment set it saw and refuses to enter round 2 until it holds
/// `n` matching digests. osst cannot provide the broadcast — that is the
/// caller's job, and a caller without a reliable one must not run this
/// protocol — but it can make sure every participant computes the digest the
/// same way, which is what this type is.
///
/// # What is hashed
///
/// ```text
/// SHA-512(
///     ECHO_DIGEST_DOMAIN ‖ epoch:8 ‖ threshold:4 ‖ num_participants:4 ‖ count:4
///     ‖ for each dealer, ascending by index:
///         dealer_index:4 ‖ len(commitment):8 ‖ commitment.to_bytes()
/// )[..32]
/// ```
///
/// Truncated to 32 bytes, as [`crate::sealed::commitment_digest`] is.
///
/// The ceremony parameters are inside the hash, not assumed: without them a
/// digest from one ceremony matches a digest from another with the same
/// commitments, and the epoch is precisely what the K-1 proof-of-knowledge
/// fix uses to stop cross-ceremony replay.
///
/// **The proofs of knowledge are not hashed, only the commitments.** That is
/// deliberate and sufficient: the group key, every verification share and
/// every Feldman check are functions of the commitments alone, so two
/// participants that agree on the commitment set agree on everything the
/// ceremony produces. A proof of knowledge is verified on arrival
/// ([`DkgState::submit_commitment`]) and a dealer whose proof fails never
/// enters the set, so a disagreement about a proof is already a disagreement
/// about the set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EchoDigest(pub [u8; 32]);

impl EchoDigest {
    #[inline]
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl core::fmt::Display for EchoDigest {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        for b in &self.0 {
            write!(f, "{:02x}", b)?;
        }
        Ok(())
    }
}

/// A round-1 commitment set that every participant has agreed on.
///
/// Obtained from [`DkgState::agreed_round1`] once round 1 is complete, then
/// confirmed against the peers' [`EchoDigest`]s with [`confirm`](Self::confirm)
/// or [`confirm_all`](Self::confirm_all) before round 2 begins. It is the
/// handle the rest of the round-2 API takes, so that "which commitment is
/// dealer `i`'s" is answered from the agreed set rather than from whatever
/// arrived alongside a sub-share:
///
/// - [`Aggregator::from_agreed`] fixes the dealer set from it;
/// - [`crate::sealed::open_subshare_agreed`] looks the dealer's commitment up
///   in it instead of accepting a loose one from the caller.
///
/// Holding one of these is not by itself proof of agreement — you must call
/// `confirm_all` with what the peers echoed. It is a place to put the result.
#[derive(Clone, Debug)]
pub struct AgreedRound1<P: OsstPoint> {
    epoch: u64,
    threshold: u32,
    digest: EchoDigest,
    /// ascending by dealer index
    commitments: Vec<DealerCommitment<P>>,
}

impl<P: OsstPoint> AgreedRound1<P> {
    /// This participant's digest of the set, for broadcast.
    #[inline]
    pub fn digest(&self) -> EchoDigest {
        self.digest
    }

    #[inline]
    pub fn epoch(&self) -> u64 {
        self.epoch
    }

    #[inline]
    pub fn threshold(&self) -> u32 {
        self.threshold
    }

    /// The agreed dealer set, ascending.
    pub fn dealer_set(&self) -> Vec<u32> {
        self.commitments.iter().map(|c| c.dealer_index).collect()
    }

    /// The commitments, ascending by dealer index.
    #[inline]
    pub fn commitments(&self) -> &[DealerCommitment<P>] {
        &self.commitments
    }

    /// Dealer `index`'s commitment, from the agreed set.
    pub fn commitment(&self, dealer_index: u32) -> Result<&DealerCommitment<P>, OsstError> {
        self.commitments
            .iter()
            .find(|c| c.dealer_index == dealer_index)
            .ok_or(OsstError::UnexpectedDealer(dealer_index))
    }

    /// Compare one peer's echoed digest against this one.
    ///
    /// # Errors
    ///
    /// [`OsstError::EchoMismatch`] — a dealer equivocated, or the broadcast
    /// is not reliable. Either way round 2 must not start. Which of the two it
    /// is cannot be told apart from inside this crate, and the remedy is the
    /// same: abort the ceremony.
    pub fn confirm(&self, peer: &EchoDigest) -> Result<(), OsstError> {
        // public values; the accumulating compare is habit, not necessity
        let mut diff = 0u8;
        for (a, b) in self.digest.0.iter().zip(peer.0.iter()) {
            diff |= a ^ b;
        }
        if diff == 0 {
            Ok(())
        } else {
            Err(OsstError::EchoMismatch)
        }
    }

    /// Confirm every peer's echo, and that there are enough of them.
    ///
    /// `expected` is how many echoes the caller requires — `n`, for the
    /// standard construction, counting this participant's own.
    ///
    /// # Errors
    ///
    /// [`OsstError::InsufficientContributions`] if fewer than `expected`
    /// echoes were supplied; [`OsstError::EchoMismatch`] if any disagrees.
    pub fn confirm_all(&self, peers: &[EchoDigest], expected: usize) -> Result<(), OsstError> {
        if peers.len() < expected {
            return Err(OsstError::InsufficientContributions {
                got: peers.len(),
                need: expected,
            });
        }
        for p in peers {
            self.confirm(p)?;
        }
        Ok(())
    }
}

impl<P: OsstPoint> DkgState<P> {
    /// The agreed round-1 set and this participant's echo digest over it.
    ///
    /// Broadcast [`AgreedRound1::digest`], collect the peers' digests, and
    /// call [`AgreedRound1::confirm_all`] before any round-2 message is sent
    /// or opened (M-5).
    ///
    /// # Errors
    ///
    /// [`OsstError::InsufficientContributions`] unless round 1 is complete —
    /// echoing a partial set agrees on nothing, because a participant that
    /// has not yet received dealer `i`'s commitment would echo a different
    /// digest for an entirely honest reason.
    pub fn agreed_round1(&self) -> Result<AgreedRound1<P>, OsstError> {
        if !self.is_complete() {
            return Err(OsstError::InsufficientContributions {
                got: self.commitment_count(),
                need: self.num_participants as usize - self.disqualified.len(),
            });
        }
        let mut commitments: Vec<DealerCommitment<P>> =
            self.commitments.iter().flatten().cloned().collect();
        commitments.sort_by_key(|c| c.dealer_index);

        let digest = round1_echo_digest::<P>(
            self.epoch,
            self.threshold,
            self.num_participants,
            &commitments,
        );

        Ok(AgreedRound1 {
            epoch: self.epoch,
            threshold: self.threshold,
            digest,
            commitments,
        })
    }
}

/// The canonical round-1 echo digest, for callers that hold the commitment set
/// outside a [`DkgState`].
///
/// `commitments` is sorted by dealer index here, so the caller's ordering does
/// not change the result. See [`EchoDigest`] for what goes in and why.
pub fn round1_echo_digest<P: OsstPoint>(
    epoch: u64,
    threshold: u32,
    num_participants: u32,
    commitments: &[DealerCommitment<P>],
) -> EchoDigest {
    use sha2::{Digest, Sha512};

    let mut sorted: Vec<&DealerCommitment<P>> = commitments.iter().collect();
    sorted.sort_by_key(|c| c.dealer_index);

    let mut h = Sha512::new();
    h.update(ECHO_DIGEST_DOMAIN);
    h.update(epoch.to_le_bytes());
    h.update(threshold.to_le_bytes());
    h.update(num_participants.to_le_bytes());
    h.update((sorted.len() as u32).to_le_bytes());
    for c in sorted {
        let bytes = c.to_bytes();
        h.update(c.dealer_index.to_le_bytes());
        h.update((bytes.len() as u64).to_le_bytes());
        h.update(&bytes);
    }
    let full: [u8; 64] = h.finalize().into();
    let mut out = [0u8; 32];
    out.copy_from_slice(&full[..32]);
    EchoDigest(out)
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(all(test, feature = "ristretto255"))]
mod tests {
    use super::*;
    use crate::{verify, Contribution, SecretShare};
    use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
    use rand::rngs::OsRng;

    // ── M-6: justified, ceremony-bound, signed complaints ─────────────────

    const CSESSION: [u8; 32] = [0x5Au8; 32];

    /// A forged proof of knowledge is fully transferable evidence: a third
    /// party with the roster and nothing else reaches the same verdict.
    #[test]
    fn a_forged_proof_of_knowledge_is_publicly_adjudicable() {
        let mut rng = OsRng;
        let epoch = 3u64;
        let honest: Dealer<RistrettoPoint> = Dealer::new(2, 2, &mut rng).unwrap();

        // dealer 2 publishes a commitment with someone else's proof attached
        let other: Dealer<RistrettoPoint> = Dealer::new(2, 2, &mut rng).unwrap();
        let mut forged = honest.round1_package(epoch, &mut rng);
        forged.proof_of_knowledge = other.round1_package(epoch, &mut rng).proof_of_knowledge;
        assert!(forged.verify(epoch).is_err());

        let accuser_secret = Scalar::random(&mut rng);
        let accuser_pk: RistrettoPoint =
            <RistrettoPoint as OsstPoint>::generator().mul_scalar(&accuser_secret);

        let complaint = Complaint::<RistrettoPoint>::sign(
            epoch,
            CSESSION,
            1,
            1,
            ComplaintEvidence::ForgedProofOfKnowledge { package: forged },
            &accuser_secret,
            &mut rng,
        )
        .unwrap();

        assert_eq!(complaint.accused_index, 2);
        assert_eq!(
            complaint
                .verify(epoch, &CSESSION, &accuser_pk, None)
                .unwrap(),
            ComplaintVerdict::Upheld,
        );

        // a complaint against an honest package is authentic but unfounded
        let unfounded = Complaint::<RistrettoPoint>::sign(
            epoch,
            CSESSION,
            1,
            1,
            ComplaintEvidence::ForgedProofOfKnowledge {
                package: honest.round1_package(epoch, &mut rng),
            },
            &accuser_secret,
            &mut rng,
        )
        .unwrap();
        assert_eq!(
            unfounded
                .verify(epoch, &CSESSION, &accuser_pk, None)
                .unwrap(),
            ComplaintVerdict::Unfounded,
            "the accuser, not the accused, is the problem here"
        );
    }

    /// Build the confirmed round-1 set every verifier of a `BadSubShare`
    /// complaint checks against.
    fn agreed_of(
        dealers: &[Dealer<RistrettoPoint>],
        t: u32,
        n: u32,
        epoch: u64,
        rng: &mut OsRng,
    ) -> AgreedRound1<RistrettoPoint> {
        let mut state = DkgState::<RistrettoPoint>::new(epoch, t, n);
        for d in dealers {
            state.submit_commitment(d.round1_package(epoch, rng)).unwrap();
        }
        state.agreed_round1().unwrap()
    }

    fn bad_subshare_evidence(
        dealer_index: u32,
        recipient_index: u32,
        round: u8,
        scalar: &Scalar,
        agreed: &AgreedRound1<RistrettoPoint>,
    ) -> BadSubShareEvidence {
        BadSubShareEvidence {
            dealer_index,
            recipient_index,
            session_id: CSESSION,
            round,
            subshare: <Scalar as OsstScalar>::to_bytes(scalar),
            agreed_digest: commitment_digest(agreed.commitment(dealer_index).unwrap()),
            sealed_digest: [9u8; 32],
        }
    }

    /// A bad sub-share is checkable by anyone — against the commitment in the
    /// *verifier's own* agreed set, never one the accuser supplied — and the
    /// complaint is bound to the accuser, the ceremony and the round.
    #[test]
    fn a_bad_subshare_complaint_is_checked_against_the_agreed_commitment() {
        let mut rng = OsRng;
        let epoch = 11u64;
        let dealers: Vec<Dealer<RistrettoPoint>> = (1..=2)
            .map(|i| Dealer::new(i, 2, &mut rng).unwrap())
            .collect();
        let agreed = agreed_of(&dealers, 2, 2, epoch, &mut rng);

        let accuser_secret = Scalar::random(&mut rng);
        let accuser_pk: RistrettoPoint =
            <RistrettoPoint as OsstPoint>::generator().mul_scalar(&accuser_secret);

        // a scalar that is not f_2(1)
        let bogus = Scalar::random(&mut rng);
        let complaint = Complaint::<RistrettoPoint>::sign(
            epoch,
            CSESSION,
            2,
            1,
            ComplaintEvidence::BadSubShare {
                evidence: bad_subshare_evidence(2, 1, 2, &bogus, &agreed),
            },
            &accuser_secret,
            &mut rng,
        )
        .unwrap();
        assert_eq!(
            complaint
                .verify(epoch, &CSESSION, &accuser_pk, Some(&agreed))
                .unwrap(),
            ComplaintVerdict::Upheld
        );

        // the real share is a correct evaluation of the agreed commitment
        let good = dealers[1].generate_subshare(1).unwrap();
        let honest_claim = Complaint::<RistrettoPoint>::sign(
            epoch,
            CSESSION,
            2,
            1,
            ComplaintEvidence::BadSubShare {
                evidence: bad_subshare_evidence(2, 1, 2, good.value(), &agreed),
            },
            &accuser_secret,
            &mut rng,
        )
        .unwrap();
        assert_eq!(
            honest_claim
                .verify(epoch, &CSESSION, &accuser_pk, Some(&agreed))
                .unwrap(),
            ComplaintVerdict::Unfounded,
            "an accuser complaining about a valid share names itself"
        );

        // no agreed set: nothing sound to check it against
        assert_eq!(
            complaint.verify(epoch, &CSESSION, &accuser_pk, None),
            Err(OsstError::InvalidComplaint),
            "a round-2 complaint cannot be adjudicated without the agreed set"
        );

        // an accuser that names a commitment other than the agreed one
        let other: Dealer<RistrettoPoint> = Dealer::new(2, 2, &mut rng).unwrap();
        let mut ev = bad_subshare_evidence(2, 1, 2, &bogus, &agreed);
        ev.agreed_digest = commitment_digest(other.commitment());
        let substituted = Complaint::<RistrettoPoint>::sign(
            epoch,
            CSESSION,
            2,
            1,
            ComplaintEvidence::BadSubShare { evidence: ev },
            &accuser_secret,
            &mut rng,
        )
        .unwrap();
        assert_eq!(
            substituted.verify(epoch, &CSESSION, &accuser_pk, Some(&agreed)),
            Err(OsstError::InvalidComplaint),
            "the evidence is checked against the verifier's commitment, not the accuser's"
        );

        // wrong ceremony, wrong session, wrong key: all rejected outright
        assert_eq!(
            complaint.verify(epoch + 1, &CSESSION, &accuser_pk, Some(&agreed)),
            Err(OsstError::InvalidComplaint)
        );
        assert_eq!(
            complaint.verify(epoch, &[0u8; 32], &accuser_pk, Some(&agreed)),
            Err(OsstError::InvalidComplaint)
        );
        let impostor: RistrettoPoint =
            <RistrettoPoint as OsstPoint>::generator().mul_scalar(&Scalar::random(&mut rng));
        assert_eq!(
            complaint.verify(epoch, &CSESSION, &impostor, Some(&agreed)),
            Err(OsstError::InvalidComplaint)
        );
    }

    /// The residual M-6 leaves: a fabricated complaint against a wholly honest
    /// dealer is `Upheld` too, because the fabricated scalar fails the Feldman
    /// check exactly as a real bad one does. The verdict is therefore not a
    /// licence to disqualify, and the quorum is.
    #[test]
    fn a_fabricated_complaint_is_upheld_too_so_one_complaint_decides_nothing() {
        let mut rng = OsRng;
        let (n, t, epoch) = (3u32, 2u32, 42u64);
        let dealers: Vec<Dealer<RistrettoPoint>> = (1..=n)
            .map(|i| Dealer::new(i, t, &mut rng).unwrap())
            .collect();
        let agreed = agreed_of(&dealers, t, n, epoch, &mut rng);

        // Dealer 3 is honest: every sub-share it produced verifies.
        for j in 1..=n {
            let s = dealers[2].generate_subshare(j).unwrap();
            assert!(agreed
                .commitment(3)
                .unwrap()
                .verify_subshare(j, s.value()));
        }

        // Member 1 makes one up anyway.
        let liar_secret = Scalar::random(&mut rng);
        let liar_pk: RistrettoPoint =
            <RistrettoPoint as OsstPoint>::generator().mul_scalar(&liar_secret);
        let fabricated = Complaint::<RistrettoPoint>::sign(
            epoch,
            CSESSION,
            2,
            1,
            ComplaintEvidence::BadSubShare {
                evidence: bad_subshare_evidence(3, 1, 2, &Scalar::random(&mut rng), &agreed),
            },
            &liar_secret,
            &mut rng,
        )
        .unwrap();

        let verdict = fabricated
            .verify(epoch, &CSESSION, &liar_pk, Some(&agreed))
            .unwrap();
        assert_eq!(
            verdict,
            ComplaintVerdict::Upheld,
            "Upheld and Unfounded cannot tell an honest recipient from a lying one"
        );

        // Which is why the verdict alone must not disqualify dealer 3.
        let mut tally = ComplaintTally::new(t);
        tally.record(1, 3, verdict).unwrap();
        assert_eq!(tally.count(3), 1);
        assert!(
            !tally.reached(3),
            "one accuser is below t: an honest dealer survives a lone liar"
        );
        assert!(tally.disqualifiable().is_empty());
        assert_eq!(tally.below_threshold(), alloc::vec![(3, alloc::vec![1])]);

        // A second, independent accuser reaches t and the dealer goes.
        tally.record(2, 3, ComplaintVerdict::Upheld).unwrap();
        assert!(tally.reached(3));
        assert_eq!(tally.disqualifiable(), alloc::vec![3]);
    }

    /// The tally counts accusers, not complaints.
    #[test]
    fn the_tally_counts_distinct_accusers_and_gates_on_the_threshold() {
        let mut tally = ComplaintTally::new(3);
        assert_eq!(tally.threshold(), 3);

        // the same accuser re-broadcast does not count twice
        for _ in 0..5 {
            tally.record(1, 4, ComplaintVerdict::Upheld).unwrap();
        }
        assert_eq!(tally.count(4), 1);
        assert!(!tally.reached(4));

        tally.record(2, 4, ComplaintVerdict::Upheld).unwrap();
        assert!(!tally.reached(4), "two of three is not a quorum");
        tally.record(5, 4, ComplaintVerdict::Upheld).unwrap();
        assert!(tally.reached(4));
        assert_eq!(tally.accusers(4), alloc::vec![1, 2, 5]);
        assert_eq!(tally.disqualifiable(), alloc::vec![4]);
        assert!(tally.below_threshold().is_empty());

        // an unfounded verdict counts against the accuser and adds no weight
        tally.record(6, 7, ComplaintVerdict::Unfounded).unwrap();
        assert_eq!(tally.count(7), 0);
        assert_eq!(tally.flagged_accusers(), alloc::vec![6]);

        // self-accusation and zero indices are refused outright
        assert_eq!(
            tally.record(2, 2, ComplaintVerdict::Upheld),
            Err(OsstError::InvalidIndex)
        );
        assert_eq!(
            tally.record(0, 2, ComplaintVerdict::Upheld),
            Err(OsstError::InvalidIndex)
        );
        assert_eq!(
            tally.record(2, 0, ComplaintVerdict::Upheld),
            Err(OsstError::InvalidIndex)
        );
    }

    /// The evidence fixes who is accused: a complaint cannot name one dealer
    /// and carry another's, and tampering with the body breaks the signature.
    #[test]
    fn a_complaint_cannot_be_relabelled() {
        let mut rng = OsRng;
        let epoch = 2u64;
        let dealers: Vec<Dealer<RistrettoPoint>> = (1..=2)
            .map(|i| Dealer::new(i, 2, &mut rng).unwrap())
            .collect();
        let agreed = agreed_of(&dealers, 2, 2, epoch, &mut rng);
        let accuser_secret = Scalar::random(&mut rng);
        let accuser_pk: RistrettoPoint =
            <RistrettoPoint as OsstPoint>::generator().mul_scalar(&accuser_secret);

        let bogus = Scalar::random(&mut rng);
        let mut complaint = Complaint::<RistrettoPoint>::sign(
            epoch,
            CSESSION,
            2,
            1,
            ComplaintEvidence::BadSubShare {
                evidence: bad_subshare_evidence(2, 1, 2, &bogus, &agreed),
            },
            &accuser_secret,
            &mut rng,
        )
        .unwrap();

        complaint.accused_index = 3;
        assert_eq!(
            complaint.verify(epoch, &CSESSION, &accuser_pk, Some(&agreed)),
            Err(OsstError::InvalidComplaint),
            "the named dealer must agree with the evidence"
        );

        complaint.accused_index = 2;
        complaint.accuser_index = 9;
        assert_eq!(
            complaint.verify(epoch, &CSESSION, &accuser_pk, Some(&agreed)),
            Err(OsstError::InvalidComplaint),
            "the accuser is inside the signed body"
        );

        // and the evidence's own copy of the binding must agree too
        let mut drifted = Complaint::<RistrettoPoint>::sign(
            epoch,
            CSESSION,
            2,
            1,
            ComplaintEvidence::BadSubShare {
                evidence: bad_subshare_evidence(2, 1, 2, &bogus, &agreed),
            },
            &accuser_secret,
            &mut rng,
        )
        .unwrap();
        if let ComplaintEvidence::BadSubShare { evidence } = &mut drifted.evidence {
            evidence.round = 7;
        }
        assert_eq!(
            drifted.verify(epoch, &CSESSION, &accuser_pk, Some(&agreed)),
            Err(OsstError::InvalidComplaint),
            "the evidence's binding is not decorative"
        );
    }

    // ── M-5: dealer equivocation is caught by the echo round ──────────────

    /// Two honest participants that saw the same round-1 set agree, and the
    /// digest is order-independent and ceremony-bound.
    #[test]
    fn honest_participants_echo_the_same_round1_digest() {
        let mut rng = OsRng;
        let (n, t, epoch) = (4u32, 3u32, 77u64);
        let dealers: Vec<Dealer<RistrettoPoint>> = (1..=n)
            .map(|i| Dealer::new(i, t, &mut rng).unwrap())
            .collect();
        let packages: Vec<_> = dealers
            .iter()
            .map(|d| d.round1_package(epoch, &mut rng))
            .collect();

        // alice receives them in order, bob in reverse
        let mut alice = DkgState::<RistrettoPoint>::new(epoch, t, n);
        let mut bob = DkgState::<RistrettoPoint>::new(epoch, t, n);
        for p in &packages {
            alice.submit_commitment(p.clone()).unwrap();
        }
        for p in packages.iter().rev() {
            bob.submit_commitment(p.clone()).unwrap();
        }

        let a = alice.agreed_round1().unwrap();
        let b = bob.agreed_round1().unwrap();
        assert_eq!(a.digest(), b.digest(), "delivery order must not matter");
        a.confirm(&b.digest()).unwrap();
        a.confirm_all(&[a.digest(), b.digest()], 2).unwrap();
        assert_eq!(a.dealer_set(), (1..=n).collect::<Vec<_>>());

        // the same commitments under a different epoch are a different set
        let mut other_epoch = DkgState::<RistrettoPoint>::new(epoch + 1, t, n);
        for d in &dealers {
            other_epoch
                .submit_commitment(d.round1_package(epoch + 1, &mut rng))
                .unwrap();
        }
        assert_ne!(
            a.digest(),
            other_epoch.agreed_round1().unwrap().digest(),
            "the digest must bind the ceremony, not just the commitments"
        );
    }

    /// M-5, the finding itself: a dealer that commits to one polynomial toward
    /// Alice and another toward Bob splits the group, and nothing in the
    /// point-to-point protocol notices — each pair is internally consistent
    /// and passes its Feldman check and its D-2 commitment-digest check. The
    /// echo round is what catches it.
    #[test]
    fn an_equivocating_dealer_is_caught_by_the_echo_round() {
        let mut rng = OsRng;
        let (n, t, epoch) = (3u32, 2u32, 9u64);

        // dealers 2 and 3 are honest
        let honest: Vec<Dealer<RistrettoPoint>> = (2..=n)
            .map(|i| Dealer::new(i, t, &mut rng).unwrap())
            .collect();
        let honest_packages: Vec<_> = honest
            .iter()
            .map(|d| d.round1_package(epoch, &mut rng))
            .collect();

        // dealer 1 runs two polynomials and shows a different one to each peer
        let evil_a: Dealer<RistrettoPoint> = Dealer::new(1, t, &mut rng).unwrap();
        let evil_b: Dealer<RistrettoPoint> = Dealer::new(1, t, &mut rng).unwrap();
        let pkg_a = evil_a.round1_package(epoch, &mut rng);
        let pkg_b = evil_b.round1_package(epoch, &mut rng);
        assert_ne!(pkg_a.commitment.to_bytes(), pkg_b.commitment.to_bytes());

        // both packages are perfectly valid in isolation: the proof of
        // knowledge verifies for each, so K-1 does not see this
        pkg_a.verify(epoch).unwrap();
        pkg_b.verify(epoch).unwrap();

        let mut alice = DkgState::<RistrettoPoint>::new(epoch, t, n);
        let mut bob = DkgState::<RistrettoPoint>::new(epoch, t, n);
        alice.submit_commitment(pkg_a).unwrap();
        bob.submit_commitment(pkg_b).unwrap();
        for p in &honest_packages {
            alice.submit_commitment(p.clone()).unwrap();
            bob.submit_commitment(p.clone()).unwrap();
        }

        // each derives a group key, and they are different — this is the split
        let a = alice.agreed_round1().unwrap();
        let b = bob.agreed_round1().unwrap();
        assert_ne!(
            alice.derive_group_key().unwrap(),
            bob.derive_group_key().unwrap(),
            "the equivocation really does split the group key"
        );

        // and the echo round refuses to enter round 2
        assert_eq!(a.confirm(&b.digest()), Err(OsstError::EchoMismatch));
        assert_eq!(b.confirm(&a.digest()), Err(OsstError::EchoMismatch));
        assert_eq!(
            a.confirm_all(&[a.digest(), b.digest()], 2),
            Err(OsstError::EchoMismatch)
        );
    }

    /// Echoing a partial set agrees on nothing: a participant that has not yet
    /// received a commitment would echo a different digest for an entirely
    /// honest reason, so the digest is refused until round 1 closes.
    #[test]
    fn a_partial_round1_set_has_no_echo_digest() {
        let mut rng = OsRng;
        let (n, t, epoch) = (3u32, 2u32, 1u64);
        let mut st = DkgState::<RistrettoPoint>::new(epoch, t, n);
        let d: Dealer<RistrettoPoint> = Dealer::new(1, t, &mut rng).unwrap();
        st.submit_commitment(d.round1_package(epoch, &mut rng)).unwrap();
        assert_eq!(
            st.agreed_round1().unwrap_err(),
            OsstError::InsufficientContributions { got: 1, need: 3 }
        );
    }

    /// The agreed set is where round 2 looks up a dealer's commitment, so the
    /// aggregator's dealer set comes from it rather than from a convention.
    #[test]
    fn the_agreed_set_drives_the_aggregator_and_the_lookup() {
        let mut rng = OsRng;
        let (n, t, epoch) = (3u32, 2u32, 5u64);
        let dealers: Vec<Dealer<RistrettoPoint>> = (1..=n)
            .map(|i| Dealer::new(i, t, &mut rng).unwrap())
            .collect();
        let mut st = DkgState::<RistrettoPoint>::new(epoch, t, n);
        for d in &dealers {
            st.submit_commitment(d.round1_package(epoch, &mut rng)).unwrap();
        }
        let agreed = st.agreed_round1().unwrap();

        let mut agg = Aggregator::<RistrettoPoint>::from_agreed(2, &agreed).unwrap();
        assert_eq!(agg.dealer_set(), &[1, 2, 3]);
        for d in &dealers {
            let sub = d.generate_subshare(2).unwrap();
            let c = agreed.commitment(d.index()).unwrap();
            assert!(agg.add_subshare(sub, c).unwrap());
        }
        assert!(agg.is_complete());
        assert_eq!(agg.derive_group_key().unwrap(), st.derive_group_key().unwrap());

        assert_eq!(
            agreed.commitment(9).unwrap_err(),
            OsstError::UnexpectedDealer(9)
        );
    }

    #[test]
    fn test_basic_dkg() {
        let mut rng = OsRng;
        let n = 5u32;
        let t = 3u32;

        // phase 1: each participant creates a dealer
        let dealers: Vec<Dealer<RistrettoPoint>> =
            (1..=n).map(|i| Dealer::new(i, t, &mut rng).expect("index is 1-indexed by construction")).collect();

        // phase 2: collect commitments
        let commitments: Vec<&DealerCommitment<RistrettoPoint>> =
            dealers.iter().map(|d| d.commitment()).collect();

        // phase 3: each player collects sub-shares from all dealers
        let mut shares = Vec::new();
        for j in 1..=n {
            let mut agg: Aggregator<RistrettoPoint> = Aggregator::all_dealers(j, n).unwrap();
            for dealer in &dealers {
                let subshare = dealer.generate_subshare(j).expect("index is 1-indexed by construction");
                agg.add_subshare(subshare, commitments[(dealer.index() - 1) as usize])
                    .unwrap();
            }
            let share = agg.finalize().unwrap();
            let group_key = agg.derive_group_key().unwrap();
            shares.push((share, group_key));
        }

        // all players should derive the same group key
        let group_key = shares[0].1;
        for (_, gk) in &shares {
            assert_eq!(*gk, group_key);
        }

        // verify: t shares should produce valid OSST proof
        let secret_shares: Vec<SecretShare<Scalar>> = shares
            .iter()
            .enumerate()
            .map(|(i, (s, _))| SecretShare::new((i + 1) as u32, *s).expect("index is 1-indexed by construction"))
            .collect();

        let payload = b"dkg test verification";
        let contributions: Vec<Contribution<RistrettoPoint>> = secret_shares[0..t as usize]
            .iter()
            .map(|s| s.contribute(&mut rng, payload))
            .collect();

        let valid = verify(&group_key, &contributions, t, payload).unwrap();
        assert!(valid, "OSST verification with DKG shares should succeed");
    }

    #[test]
    fn test_dkg_state() {
        let mut rng = OsRng;
        let n = 5u32;
        let t = 3u32;

        let dealers: Vec<Dealer<RistrettoPoint>> =
            (1..=n).map(|i| Dealer::new(i, t, &mut rng).expect("index is 1-indexed by construction")).collect();

        let mut state: DkgState<RistrettoPoint> = DkgState::new(1, t, n);

        assert!(!state.is_complete());

        for dealer in &dealers {
            state
                .submit_commitment(dealer.round1_package(1, &mut rng))
                .unwrap();
        }

        assert!(state.is_complete());
        assert_eq!(state.commitment_count(), n as usize);

        // derive group key from state
        let state_key = state.derive_group_key().unwrap();

        // derive group key from aggregator
        let mut agg: Aggregator<RistrettoPoint> = Aggregator::all_dealers(1, n).unwrap();
        for dealer in &dealers {
            let subshare = dealer.generate_subshare(1).expect("index is 1-indexed by construction");
            agg.add_subshare(subshare, dealer.commitment()).unwrap();
        }
        let agg_key = agg.derive_group_key().unwrap();

        assert_eq!(state_key, agg_key);
    }

    #[test]
    fn test_dkg_bad_subshare_rejected() {
        let mut rng = OsRng;
        let n = 3u32;
        let t = 2u32;

        let dealers: Vec<Dealer<RistrettoPoint>> =
            (1..=n).map(|i| Dealer::new(i, t, &mut rng).expect("index is 1-indexed by construction")).collect();

        let mut agg: Aggregator<RistrettoPoint> = Aggregator::all_dealers(1, n).unwrap();

        // good sub-share
        let subshare = dealers[0].generate_subshare(1).expect("index is 1-indexed by construction");
        assert!(agg.add_subshare(subshare, dealers[0].commitment()).is_ok());

        // tampered sub-share (wrong value)
        let bad = SubShare::new(2, 1, Scalar::random(&mut rng)).expect("index is 1-indexed by construction");
        let result = agg.add_subshare(bad, dealers[1].commitment());
        assert!(matches!(result, Err(OsstError::InvalidSubShare(_))));
    }

    #[test]
    fn test_dkg_duplicate_rejected() {
        let mut rng = OsRng;
        let dealer: Dealer<RistrettoPoint> = Dealer::new(1, 2, &mut rng).expect("index is 1-indexed by construction");

        let mut agg: Aggregator<RistrettoPoint> = Aggregator::new(1, &[1]).unwrap();
        let subshare = dealer.generate_subshare(1).expect("index is 1-indexed by construction");
        assert!(agg.add_subshare(subshare, dealer.commitment()).unwrap());

        let subshare2 = dealer.generate_subshare(1).expect("index is 1-indexed by construction");
        assert!(!agg.add_subshare(subshare2, dealer.commitment()).unwrap());
    }

    #[test]
    fn test_dkg_non_consecutive_subset_verifies() {
        let mut rng = OsRng;
        let n = 7u32;
        let t = 4u32;

        let dealers: Vec<Dealer<RistrettoPoint>> =
            (1..=n).map(|i| Dealer::new(i, t, &mut rng).expect("index is 1-indexed by construction")).collect();

        let commitments: Vec<&DealerCommitment<RistrettoPoint>> =
            dealers.iter().map(|d| d.commitment()).collect();

        // collect shares for all players
        let mut secret_shares = Vec::new();
        let mut group_key = None;
        for j in 1..=n {
            let mut agg: Aggregator<RistrettoPoint> = Aggregator::all_dealers(j, n).unwrap();
            for dealer in &dealers {
                let subshare = dealer.generate_subshare(j).expect("index is 1-indexed by construction");
                agg.add_subshare(subshare, commitments[(dealer.index() - 1) as usize])
                    .unwrap();
            }
            if group_key.is_none() {
                group_key = Some(agg.derive_group_key().unwrap());
            }
            secret_shares.push(SecretShare::new(j, agg.finalize().unwrap()).expect("index is 1-indexed by construction"));
        }

        let group_key = group_key.unwrap();
        let payload = b"non-consecutive subset test";

        // use shares 1, 3, 5, 7 (non-consecutive, at threshold)
        let contributions: Vec<Contribution<RistrettoPoint>> = [0, 2, 4, 6]
            .iter()
            .map(|&i| secret_shares[i].contribute(&mut rng, payload))
            .collect();

        assert!(verify(&group_key, &contributions, t, payload).unwrap());
    }
    /// Subset DKG (narsild style): the dealer set must be agreed. A node
    /// that sums one dealer more than its peers gets a different key.
    #[test]
    fn test_dkg_subset_dealer_set_enforced() {
        let mut rng = OsRng;
        let n = 5u32;
        let t = 3u32;
        let dealers: Vec<Dealer<RistrettoPoint>> =
            (1..=n).map(|i| Dealer::new(i, t, &mut rng).expect("index is 1-indexed by construction")).collect();

        let set = [1u32, 3, 4];
        let mut agg: Aggregator<RistrettoPoint> = Aggregator::new(2, &set).unwrap();
        // dealer 5 committed too, but is not in the agreed set
        assert_eq!(
            agg.add_subshare(dealers[4].generate_subshare(2).expect("index is 1-indexed by construction"), dealers[4].commitment()),
            Err(OsstError::UnexpectedDealer(5))
        );
        for &i in &set {
            let d = &dealers[(i - 1) as usize];
            agg.add_subshare(d.generate_subshare(2).expect("index is 1-indexed by construction"), d.commitment()).unwrap();
        }
        assert!(agg.is_complete());

        // Group key is the sum over exactly the set
        let mut expected = RistrettoPoint::identity();
        for &i in &set {
            expected = expected.add(dealers[(i - 1) as usize].commitment().share_commitment());
        }
        assert_eq!(agg.derive_group_key().unwrap(), expected);

        // An incomplete aggregator refuses to finalize
        let mut partial: Aggregator<RistrettoPoint> = Aggregator::new(2, &set).unwrap();
        partial
            .add_subshare(dealers[0].generate_subshare(2).expect("index is 1-indexed by construction"), dealers[0].commitment())
            .unwrap();
        assert_eq!(partial.missing_dealers(), vec![3, 4]);
        assert!(matches!(
            partial.finalize(),
            Err(OsstError::InsufficientContributions { got: 1, need: 3 })
        ));
    }

    // ========================================================================
    // K-1: proof of knowledge of the constant term
    // ========================================================================

    #[test]
    fn pok_verifies_for_an_honest_dealer() {
        let mut rng = OsRng;
        let dealer: Dealer<RistrettoPoint> = Dealer::new(2, 3, &mut rng).expect("index is 1-indexed by construction");
        let pkg = dealer.round1_package(7, &mut rng);
        assert!(pkg.verify(7).is_ok());
    }

    #[test]
    fn pok_is_bound_to_the_dealer_index_the_epoch_and_the_commitment() {
        let mut rng = OsRng;
        let dealer: Dealer<RistrettoPoint> = Dealer::new(2, 3, &mut rng).expect("index is 1-indexed by construction");
        let pkg = dealer.round1_package(7, &mut rng);

        // another epoch
        assert_eq!(pkg.verify(8), Err(OsstError::InvalidProofOfKnowledge(2)));

        // another dealer index: replaying dealer 2's proof as dealer 3
        let mut stolen = pkg.clone();
        stolen.commitment.dealer_index = 3;
        assert_eq!(stolen.verify(7), Err(OsstError::InvalidProofOfKnowledge(3)));

        // another constant term: the rogue-key shape. The attacker publishes a
        // C_0 it did not choose and cannot prove knowledge of.
        let other: Dealer<RistrettoPoint> = Dealer::new(2, 3, &mut rng).expect("index is 1-indexed by construction");
        let mut rogue = pkg.clone();
        rogue.commitment = other.commitment().clone();
        assert_eq!(rogue.verify(7), Err(OsstError::InvalidProofOfKnowledge(2)));
    }

    #[test]
    fn dkg_state_rejects_a_dealer_that_cannot_prove_knowledge() {
        let mut rng = OsRng;
        let honest: Dealer<RistrettoPoint> = Dealer::new(1, 2, &mut rng).expect("index is 1-indexed by construction");
        let other: Dealer<RistrettoPoint> = Dealer::new(2, 2, &mut rng).expect("index is 1-indexed by construction");

        let mut state: DkgState<RistrettoPoint> = DkgState::new(1, 2, 3);

        // dealer 2 publishes dealer-1-style proof over someone else's C_0
        let mut forged = other.round1_package(1, &mut rng);
        forged.commitment = honest.commitment().clone();
        forged.commitment.dealer_index = 2;
        assert_eq!(
            state.submit_commitment(forged),
            Err(OsstError::InvalidProofOfKnowledge(2))
        );
        assert_eq!(state.commitment_count(), 0, "nothing was recorded");

        // and the honest package is accepted
        assert!(state
            .submit_commitment(honest.round1_package(1, &mut rng))
            .unwrap());
    }

    #[test]
    fn a_complaint_disqualifies_a_dealer_and_moves_the_group_key() {
        let mut rng = OsRng;
        let n = 3u32;
        let t = 2u32;
        let dealers: Vec<Dealer<RistrettoPoint>> =
            (1..=n).map(|i| Dealer::new(i, t, &mut rng).expect("index is 1-indexed by construction")).collect();

        let mut state: DkgState<RistrettoPoint> = DkgState::new(9, t, n);
        for d in &dealers {
            state.submit_commitment(d.round1_package(9, &mut rng)).unwrap();
        }
        let key_all = state.derive_group_key().unwrap();

        // Player 1 finds dealer 3's sub-share invalid. The error names the
        // dealer: that is the complaint.
        let mut agg: Aggregator<RistrettoPoint> = Aggregator::all_dealers(1, n).unwrap();
        let bad = SubShare::new(3, 1, Scalar::random(&mut rng)).expect("index is 1-indexed by construction");
        assert_eq!(
            agg.add_subshare(bad, dealers[2].commitment()),
            Err(OsstError::InvalidSubShare(3))
        );

        // Everyone applies it.
        state.disqualify(3).unwrap();
        assert_eq!(state.disqualified(), &[3]);
        assert_eq!(state.qualified_dealers(), vec![1, 2]);
        assert!(state.is_complete(), "complete over the surviving dealers");

        let key_qualified = state.derive_group_key().unwrap();
        assert_ne!(key_all, key_qualified);
        assert_eq!(
            key_qualified,
            dealers[0]
                .commitment()
                .share_commitment()
                .add(dealers[1].commitment().share_commitment())
        );

        // A disqualified dealer cannot re-enter.
        assert_eq!(
            state.submit_commitment(dealers[2].round1_package(9, &mut rng)),
            Err(OsstError::UnexpectedDealer(3))
        );
    }

    #[test]
    fn disqualifying_below_threshold_aborts_the_ceremony() {
        let mut rng = OsRng;
        let dealers: Vec<Dealer<RistrettoPoint>> =
            (1..=3).map(|i| Dealer::new(i, 3, &mut rng).expect("index is 1-indexed by construction")).collect();
        let mut state: DkgState<RistrettoPoint> = DkgState::new(1, 3, 3);
        for d in &dealers {
            state.submit_commitment(d.round1_package(1, &mut rng)).unwrap();
        }
        assert_eq!(
            state.disqualify(2),
            Err(OsstError::DkgAborted {
                qualified: 2,
                need: 3
            })
        );
    }
}

#[cfg(all(test, feature = "pallas"))]
mod pallas_tests {
    use super::*;
    use crate::{verify, Contribution, SecretShare};
    use pasta_curves::pallas::Point;
    use rand::rngs::OsRng;

    #[test]
    fn test_pallas_dkg() {
        let mut rng = OsRng;
        let n = 5u32;
        let t = 3u32;

        let dealers: Vec<Dealer<Point>> =
            (1..=n).map(|i| Dealer::new(i, t, &mut rng).expect("index is 1-indexed by construction")).collect();

        let commitments: Vec<&DealerCommitment<Point>> =
            dealers.iter().map(|d| d.commitment()).collect();

        let mut shares = Vec::new();
        let mut group_key = None;
        for j in 1..=n {
            let mut agg: Aggregator<Point> = Aggregator::all_dealers(j, n).unwrap();
            for dealer in &dealers {
                let subshare = dealer.generate_subshare(j).expect("index is 1-indexed by construction");
                agg.add_subshare(subshare, commitments[(dealer.index() - 1) as usize])
                    .unwrap();
            }
            if group_key.is_none() {
                group_key = Some(agg.derive_group_key().unwrap());
            }
            shares.push(SecretShare::new(j, agg.finalize().unwrap()).expect("index is 1-indexed by construction"));
        }

        let group_key = group_key.unwrap();
        let payload = b"pallas dkg test";

        let contributions: Vec<Contribution<Point>> = shares[0..t as usize]
            .iter()
            .map(|s| s.contribute(&mut rng, payload))
            .collect();

        assert!(verify(&group_key, &contributions, t, payload).unwrap());
    }
}
