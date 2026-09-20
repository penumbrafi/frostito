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
    ) -> Self {
        assert!(index > 0, "index must be 1-indexed");
        assert!(threshold > 0, "threshold must be positive");

        let mut polynomial = Vec::with_capacity(threshold as usize);
        for _ in 0..threshold {
            polynomial.push(P::Scalar::random(rng));
        }

        let commitment = DealerCommitment::from_polynomial(index, &polynomial);

        Self {
            index,
            polynomial,
            commitment,
        }
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
    pub fn generate_subshare(&self, player_index: u32) -> SubShare<P::Scalar> {
        assert!(player_index > 0, "player_index must be 1-indexed");

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
    pub fn generate_subshares(&self, num_players: u32) -> Vec<SubShare<P::Scalar>> {
        (1..=num_players)
            .map(|j| self.generate_subshare(j))
            .collect()
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
    /// are refused. Every participant must apply the same complaints, or they
    /// derive different keys.
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
    /// Y_j = g^{s_j} = Σ_i C_i.evaluate_at(j)
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
            vshare = vshare.add(&commitment.evaluate_at(player_index));
        }

        Ok(vshare)
    }

    /// Derive all verification shares for players 1..=num_participants.
    ///
    /// Returns a BTreeMap suitable for passing to [`frost::aggregate`].
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
// Tests
// ============================================================================

#[cfg(all(test, feature = "ristretto255"))]
mod tests {
    use super::*;
    use crate::{verify, Contribution, SecretShare};
    use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
    use rand::rngs::OsRng;

    #[test]
    fn test_basic_dkg() {
        let mut rng = OsRng;
        let n = 5u32;
        let t = 3u32;

        // phase 1: each participant creates a dealer
        let dealers: Vec<Dealer<RistrettoPoint>> =
            (1..=n).map(|i| Dealer::new(i, t, &mut rng)).collect();

        // phase 2: collect commitments
        let commitments: Vec<&DealerCommitment<RistrettoPoint>> =
            dealers.iter().map(|d| d.commitment()).collect();

        // phase 3: each player collects sub-shares from all dealers
        let mut shares = Vec::new();
        for j in 1..=n {
            let mut agg: Aggregator<RistrettoPoint> = Aggregator::all_dealers(j, n).unwrap();
            for dealer in &dealers {
                let subshare = dealer.generate_subshare(j);
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
            .map(|(i, (s, _))| SecretShare::new((i + 1) as u32, *s))
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
            (1..=n).map(|i| Dealer::new(i, t, &mut rng)).collect();

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
            let subshare = dealer.generate_subshare(1);
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
            (1..=n).map(|i| Dealer::new(i, t, &mut rng)).collect();

        let mut agg: Aggregator<RistrettoPoint> = Aggregator::all_dealers(1, n).unwrap();

        // good sub-share
        let subshare = dealers[0].generate_subshare(1);
        assert!(agg.add_subshare(subshare, dealers[0].commitment()).is_ok());

        // tampered sub-share (wrong value)
        let bad = SubShare::new(2, 1, Scalar::random(&mut rng));
        let result = agg.add_subshare(bad, dealers[1].commitment());
        assert!(matches!(result, Err(OsstError::InvalidSubShare(_))));
    }

    #[test]
    fn test_dkg_duplicate_rejected() {
        let mut rng = OsRng;
        let dealer: Dealer<RistrettoPoint> = Dealer::new(1, 2, &mut rng);

        let mut agg: Aggregator<RistrettoPoint> = Aggregator::new(1, &[1]).unwrap();
        let subshare = dealer.generate_subshare(1);
        assert!(agg.add_subshare(subshare, dealer.commitment()).unwrap());

        let subshare2 = dealer.generate_subshare(1);
        assert!(!agg.add_subshare(subshare2, dealer.commitment()).unwrap());
    }

    #[test]
    fn test_dkg_non_consecutive_subset_verifies() {
        let mut rng = OsRng;
        let n = 7u32;
        let t = 4u32;

        let dealers: Vec<Dealer<RistrettoPoint>> =
            (1..=n).map(|i| Dealer::new(i, t, &mut rng)).collect();

        let commitments: Vec<&DealerCommitment<RistrettoPoint>> =
            dealers.iter().map(|d| d.commitment()).collect();

        // collect shares for all players
        let mut secret_shares = Vec::new();
        let mut group_key = None;
        for j in 1..=n {
            let mut agg: Aggregator<RistrettoPoint> = Aggregator::all_dealers(j, n).unwrap();
            for dealer in &dealers {
                let subshare = dealer.generate_subshare(j);
                agg.add_subshare(subshare, commitments[(dealer.index() - 1) as usize])
                    .unwrap();
            }
            if group_key.is_none() {
                group_key = Some(agg.derive_group_key().unwrap());
            }
            secret_shares.push(SecretShare::new(j, agg.finalize().unwrap()));
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
            (1..=n).map(|i| Dealer::new(i, t, &mut rng)).collect();

        let set = [1u32, 3, 4];
        let mut agg: Aggregator<RistrettoPoint> = Aggregator::new(2, &set).unwrap();
        // dealer 5 committed too, but is not in the agreed set
        assert_eq!(
            agg.add_subshare(dealers[4].generate_subshare(2), dealers[4].commitment()),
            Err(OsstError::UnexpectedDealer(5))
        );
        for &i in &set {
            let d = &dealers[(i - 1) as usize];
            agg.add_subshare(d.generate_subshare(2), d.commitment()).unwrap();
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
            .add_subshare(dealers[0].generate_subshare(2), dealers[0].commitment())
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
        let dealer: Dealer<RistrettoPoint> = Dealer::new(2, 3, &mut rng);
        let pkg = dealer.round1_package(7, &mut rng);
        assert!(pkg.verify(7).is_ok());
    }

    #[test]
    fn pok_is_bound_to_the_dealer_index_the_epoch_and_the_commitment() {
        let mut rng = OsRng;
        let dealer: Dealer<RistrettoPoint> = Dealer::new(2, 3, &mut rng);
        let pkg = dealer.round1_package(7, &mut rng);

        // another epoch
        assert_eq!(pkg.verify(8), Err(OsstError::InvalidProofOfKnowledge(2)));

        // another dealer index: replaying dealer 2's proof as dealer 3
        let mut stolen = pkg.clone();
        stolen.commitment.dealer_index = 3;
        assert_eq!(stolen.verify(7), Err(OsstError::InvalidProofOfKnowledge(3)));

        // another constant term: the rogue-key shape. The attacker publishes a
        // C_0 it did not choose and cannot prove knowledge of.
        let other: Dealer<RistrettoPoint> = Dealer::new(2, 3, &mut rng);
        let mut rogue = pkg.clone();
        rogue.commitment = other.commitment().clone();
        assert_eq!(rogue.verify(7), Err(OsstError::InvalidProofOfKnowledge(2)));
    }

    #[test]
    fn dkg_state_rejects_a_dealer_that_cannot_prove_knowledge() {
        let mut rng = OsRng;
        let honest: Dealer<RistrettoPoint> = Dealer::new(1, 2, &mut rng);
        let other: Dealer<RistrettoPoint> = Dealer::new(2, 2, &mut rng);

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
            (1..=n).map(|i| Dealer::new(i, t, &mut rng)).collect();

        let mut state: DkgState<RistrettoPoint> = DkgState::new(9, t, n);
        for d in &dealers {
            state.submit_commitment(d.round1_package(9, &mut rng)).unwrap();
        }
        let key_all = state.derive_group_key().unwrap();

        // Player 1 finds dealer 3's sub-share invalid. The error names the
        // dealer: that is the complaint.
        let mut agg: Aggregator<RistrettoPoint> = Aggregator::all_dealers(1, n).unwrap();
        let bad = SubShare::new(3, 1, Scalar::random(&mut rng));
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
            (1..=3).map(|i| Dealer::new(i, 3, &mut rng)).collect();
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
            (1..=n).map(|i| Dealer::new(i, t, &mut rng)).collect();

        let commitments: Vec<&DealerCommitment<Point>> =
            dealers.iter().map(|d| d.commitment()).collect();

        let mut shares = Vec::new();
        let mut group_key = None;
        for j in 1..=n {
            let mut agg: Aggregator<Point> = Aggregator::all_dealers(j, n).unwrap();
            for dealer in &dealers {
                let subshare = dealer.generate_subshare(j);
                agg.add_subshare(subshare, commitments[(dealer.index() - 1) as usize])
                    .unwrap();
            }
            if group_key.is_none() {
                group_key = Some(agg.derive_group_key().unwrap());
            }
            shares.push(SecretShare::new(j, agg.finalize().unwrap()));
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
