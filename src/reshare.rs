//! Proactive secret sharing reshare protocol
//!
//! Allows transitioning threshold shares from one custodian set to another
//! without revealing the secret or changing the group public key.
//!
//! # Security Model
//!
//! - Assumes honest majority among dealers (t_old honest of n_old)
//! - Sub-shares must be encrypted in transit (not handled here)
//! - Commitments provide public verifiability
//! - Group public key Y = g^s is an invariant across reshares
//!
//! # Scalability
//!
//! Designed for O(1000) participants:
//! - Commitments: O(t) points per dealer, posted to chain
//! - Sub-shares: Encrypted, can be batched or posted to chain
//! - Verification: Batched for efficiency
//! - Aggregation: O(t) operations per player, parallelizable
//!
//! # Protocol Phases
//!
//! 1. **Dealing**: Dealers create polynomials, publish commitments
//! 2. **Distribution**: Sub-shares sent (encrypted) to players
//! 3. **Verification**: Players verify against commitments
//! 4. **Aggregation**: Players combine t_old sub-shares into new share

use alloc::vec;
use alloc::vec::Vec;
use core::marker::PhantomData;

use crate::curve::{CurvePoint, CurveScalar};
use crate::error::Error;
use crate::lagrange::compute_lagrange_coefficients;

// ============================================================================
// Core Types
// ============================================================================

/// Compressed dealer commitment for on-chain storage
///
/// Only stores the commitment points, index derived from position.
/// Size: 32 * threshold bytes per dealer
#[derive(Clone, Debug)]
pub struct DealerCommitment<P: CurvePoint> {
 /// Dealer's index in the old custodian set (1-indexed)
 pub dealer_index: u32,
 /// Polynomial commitments [g^{a_0}, g^{a_1}, ..., g^{a_{t-1}}]
 /// where a_0 = dealer's share
 pub coefficients: Vec<P>,
}

impl<P: CurvePoint> DealerCommitment<P> {
 /// Create commitment from polynomial coefficients
 pub fn from_polynomial(
 dealer_index: u32,
 coefficients: &[P::Scalar],
 ) -> Result<Self, Error> {
 if dealer_index == 0 {
 return Err(Error::InvalidIndex);
 }
 if coefficients.is_empty() {
 return Err(Error::EmptyContributions);
 }

 let committed: Vec<P> = coefficients
 .iter()
 .map(|a| P::generator().mul_scalar(a))
 .collect();

 Ok(Self {
 dealer_index,
 coefficients: committed,
 })
 }

 /// Threshold (degree + 1) of the committed polynomial
 #[inline]
 pub fn threshold(&self) -> u32 {
 self.coefficients.len() as u32
 }

 /// Commitment to dealer's share: C_0 = g^{s_i}
 #[inline]
 pub fn share_commitment(&self) -> &P {
 &self.coefficients[0]
 }

 /// Evaluate commitment at player index j
 ///
 /// Returns g^{f(j)} = Π_{k=0}^{t-1} C_k^{j^k}
 ///
 /// Uses Horner's method for efficiency: O(t) scalar muls
 pub fn evaluate_at(&self, player_index: u32) -> Result<P, Error> {
 if player_index == 0 {
 return Err(Error::InvalidIndex);
 }

 let j = P::Scalar::from_u32(player_index);

 // Horner's method: ((C_{t-1} * j + C_{t-2}) * j + ...) * j + C_0
 let mut result = P::identity();
 for coeff in self.coefficients.iter().rev() {
 result = result.mul_scalar(&j);
 result = result.add(coeff);
 }
 Ok(result)
 }

 /// Verify a sub-share against this commitment
 ///
 /// Checks: g^{sub_share} == g^{f(j)}
 #[inline]
 pub fn verify_subshare(&self, player_index: u32, sub_share: &P::Scalar) -> bool {
 if player_index == 0 {
 return false;
 }

 let expected = match self.evaluate_at(player_index) {
 Ok(e) => e,
 Err(_) => return false,
 };
 let actual = P::generator().mul_scalar(sub_share);

 // Constant-time comparison via point equality
 actual == expected
 }

 /// Compressed byte size
 #[inline]
 pub fn byte_size(&self) -> usize {
 4 + self.coefficients.len() * P::COMPRESSED_SIZE
 }

 /// Serialize to bytes (for on-chain storage)
 pub fn to_bytes(&self) -> Vec<u8> {
 let mut buf = Vec::with_capacity(self.byte_size());
 buf.extend_from_slice(&self.dealer_index.to_le_bytes());
 for c in &self.coefficients {
 buf.extend_from_slice(c.compress().as_ref());
 }
 buf
 }

 /// Deserialize from bytes
 pub fn from_bytes(bytes: &[u8], threshold: u32) -> Result<Self, Error> {
 let expected_len = 4 + (threshold as usize) * P::COMPRESSED_SIZE;
 if bytes.len() != expected_len {
 return Err(Error::InvalidCommitment);
 }

 let dealer_index = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
 if dealer_index == 0 {
 return Err(Error::InvalidIndex);
 }

 let mut coefficients = Vec::with_capacity(threshold as usize);
 for i in 0..threshold as usize {
 let offset = 4 + i * P::COMPRESSED_SIZE;
 let point = P::decompress(&bytes[offset..offset + P::COMPRESSED_SIZE])
 .ok_or(Error::InvalidCommitment)?;
 coefficients.push(point);
 }

 Ok(Self {
 dealer_index,
 coefficients,
 })
 }
}

/// Sub-share from dealer to player
///
/// Should be encrypted before transmission. Size: 40 bytes
///
/// # Security
///
/// This struct holds secret key material. It implements `ZeroizeOnDrop`
/// to ensure the value is zeroed when the sub-share goes out of scope.
#[derive(Clone)]
pub struct SubShare<S: CurveScalar> {
 pub dealer_index: u32,
 pub player_index: u32,
 value: S,
}

impl<S: CurveScalar> SubShare<S> {
 #[inline]
 pub fn new(dealer_index: u32, player_index: u32, value: S) -> Result<Self, Error> {
 if dealer_index == 0 || player_index == 0 {
 return Err(Error::InvalidIndex);
 }
 Ok(Self {
 dealer_index,
 player_index,
 value,
 })
 }

 /// Access the secret value (use sparingly)
 #[inline]
 pub fn value(&self) -> &S {
 &self.value
 }

 /// `dealer_index:4 ‖ player_index:4 ‖ value:32` — the secret scalar in
 /// the clear.
 ///
 /// Crate-internal: [`sealed::seal_subshare`](crate::sealed::seal_subshare)
 /// is the only caller, and it hands the result straight to Noise. See
 /// [`to_bytes`](Self::to_bytes) for why there is no unguarded public
 /// serializer.
 #[cfg_attr(
 not(feature = "sealed"),
 allow(dead_code)
 )]
 pub(crate) fn encode_plaintext(&self) -> [u8; 40] {
 let mut buf = [0u8; 40];
 buf[0..4].copy_from_slice(&self.dealer_index.to_le_bytes());
 buf[4..8].copy_from_slice(&self.player_index.to_le_bytes());
 buf[8..40].copy_from_slice(&self.value.to_bytes());
 buf
 }

 /// Inverse of [`encode_plaintext`](Self::encode_plaintext); crate-internal
 /// for the same reason.
 #[cfg_attr(
 not(feature = "sealed"),
 allow(dead_code)
 )]
 pub(crate) fn decode_plaintext(bytes: &[u8; 40]) -> Result<Self, Error> {
 let dealer_index = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
 let player_index = u32::from_le_bytes(bytes[4..8].try_into().unwrap());

 if dealer_index == 0 || player_index == 0 {
 return Err(Error::InvalidIndex);
 }

 let value_bytes: [u8; 32] = bytes[8..40].try_into().unwrap();
 let value = S::from_canonical_bytes(&value_bytes).ok_or(Error::InvalidResponse)?;

 Ok(Self {
 dealer_index,
 player_index,
 value,
 })
 }


}

impl<S: CurveScalar> Drop for SubShare<S> {
 fn drop(&mut self) {
 self.value.zeroize();
 }
}

impl<S: CurveScalar> core::fmt::Debug for SubShare<S> {
 fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
 f.debug_struct("SubShare")
 .field("dealer_index", &self.dealer_index)
 .field("player_index", &self.player_index)
 .field("value", &"[REDACTED]")
 .finish()
 }
}

// ============================================================================
// Dealer (Old Custodian)
// ============================================================================

/// Dealer generates sub-shares for new custodians
///
/// Holds secret polynomial coefficients.
///
/// # Security
///
/// This struct holds secret key material. It implements `ZeroizeOnDrop`
/// to ensure the polynomial coefficients are zeroed when the dealer
/// goes out of scope.
pub struct Dealer<P: CurvePoint> {
 index: u32,
 /// Polynomial coefficients [a_0=share, a_1, ..., a_{t-1}]
 polynomial: Vec<P::Scalar>,
 /// Cached commitment
 commitment: DealerCommitment<P>,
}

impl<P: CurvePoint> Drop for Dealer<P> {
 fn drop(&mut self) {
 for coeff in &mut self.polynomial {
 coeff.zeroize();
 }
 }
}

impl<P: CurvePoint> Dealer<P> {
 /// Create dealer from existing share
 ///
 /// Generates random polynomial with share as constant term.
 pub fn new<R: rand_core::RngCore + rand_core::CryptoRng>(
 index: u32,
 share: P::Scalar,
 new_threshold: u32,
 rng: &mut R,
 ) -> Result<Self, Error> {
 if index == 0 {
 return Err(Error::InvalidIndex);
 }
 if new_threshold == 0 {
 return Err(Error::ThresholdMismatch { expected: 1, got: 0 });
 }

 let mut polynomial = Vec::with_capacity(new_threshold as usize);
 polynomial.push(share);

 for _ in 1..new_threshold {
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

 /// Generate sub-share for a specific player
 ///
 /// Evaluates polynomial at player's index using Horner's method.
 pub fn generate_subshare(&self, player_index: u32) -> Result<SubShare<P::Scalar>, Error> {
 if player_index == 0 {
 return Err(Error::InvalidIndex);
 }

 let j = P::Scalar::from_u32(player_index);

 // Horner's method for polynomial evaluation
 let mut result = P::Scalar::zero();
 for coeff in self.polynomial.iter().rev() {
 result = result.mul(&j);
 result = result.add(coeff);
 }

 SubShare::new(self.index, player_index, result)
 }

 /// Generate all sub-shares for a player range
 ///
 /// Returns sub-shares for players 1..=num_players
 pub fn generate_subshares(&self, num_players: u32) -> Vec<SubShare<P::Scalar>> {
 (1..=num_players)
 .map(|j| self.generate_subshare(j).expect("index is 1-indexed by construction"))
 .collect()
 }
}

// Prevent Debug from leaking polynomial
impl<P: CurvePoint> core::fmt::Debug for Dealer<P> {
 fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
 f.debug_struct("Dealer")
 .field("index", &self.index)
 .field("polynomial", &"[REDACTED]")
 .field("commitment", &self.commitment)
 .finish()
 }
}

// ============================================================================
// Reshared polynomial (public key package for the new epoch)
// ============================================================================

/// The reshared polynomial in the exponent: `F' = Σ_{i∈S} λ_i^S · C_i`,
/// summed coefficient-wise over the agreed dealer set `S`.
///
/// `F'(0)` is the (invariant) group key and `F'(j)` is the verifying share of
/// new player `j`. Every new player derives the same `F'` because `S` is fixed
/// before aggregation, so this is the epoch's public key package: what a FROST
/// coordinator needs to verify partial signatures and identify a faulty
/// signer by index.
#[derive(Clone, Debug, PartialEq)]
pub struct SharePolynomial<P: CurvePoint> {
 coefficients: Vec<P>,
}

impl<P: CurvePoint> SharePolynomial<P> {
 /// Threshold (degree + 1) of the reshared polynomial
 #[inline]
 pub fn threshold(&self) -> u32 {
 self.coefficients.len() as u32
 }

 #[inline]
 pub fn coefficients(&self) -> &[P] {
 &self.coefficients
 }

 /// Group public key `Y = F'(0)`
 #[inline]
 pub fn group_key(&self) -> &P {
 &self.coefficients[0]
 }

 /// Evaluate `F'(index)` with Horner's method
 pub fn evaluate_at(&self, index: u32) -> Result<P, Error> {
 if index == 0 {
 return Err(Error::InvalidIndex);
 }
 let x = P::Scalar::from_u32(index);
 let mut result = P::identity();
 for coeff in self.coefficients.iter().rev() {
 result = result.mul_scalar(&x);
 result = result.add(coeff);
 }
 Ok(result)
 }

 /// Verifying share of player `j`: `Y_j = F'(j) = g^{s'_j}`
 #[inline]
 pub fn verifying_share(&self, player_index: u32) -> P {
 self.evaluate_at(player_index).expect("index is 1-indexed by construction")
 }

 /// Check that `share` is player `j`'s share on this polynomial
 pub fn verify_share(&self, player_index: u32, share: &P::Scalar) -> bool {
 if player_index == 0 {
 return false;
 }
 P::generator().mul_scalar(share) == self.evaluate_at(player_index).expect("index is 1-indexed by construction")
 }

 /// Serialize as concatenated compressed points
 pub fn to_bytes(&self) -> Vec<u8> {
 let mut buf = Vec::with_capacity(P::COMPRESSED_SIZE * self.coefficients.len());
 for c in &self.coefficients {
 buf.extend_from_slice(c.compress().as_ref());
 }
 buf
 }

 pub fn from_bytes(bytes: &[u8], threshold: u32) -> Result<Self, Error> {
 let expected = P::COMPRESSED_SIZE * threshold as usize;
 if threshold == 0 || bytes.len() != expected {
 return Err(Error::InvalidCommitment);
 }
 let mut coefficients = Vec::with_capacity(threshold as usize);
 for chunk in bytes.chunks_exact(P::COMPRESSED_SIZE) {
 coefficients.push(P::decompress(chunk).ok_or(Error::InvalidCommitment)?);
 }
 Ok(Self { coefficients })
 }
}

// ============================================================================
// Aggregator (New Custodian)
// ============================================================================

/// Verified sub-share with its commitment reference
struct VerifiedSubShare<S: CurveScalar> {
 dealer_index: u32,
 value: S,
}

/// Aggregator collects and combines sub-shares from a **fixed** dealer set.
///
/// The dealer set `S` must be agreed by every new player before anyone
/// aggregates (for example by a signed epoch manifest). Two players who
/// combine sub-shares from different dealer subsets end up on different
/// polynomials with the same constant term: the group-key check passes for
/// each of them and signing later fails with nobody to blame. Making `S` an
/// input rather than an observation is what prevents that.
///
/// Sub-shares can still arrive in any order; the aggregator only refuses
/// dealers outside `S` and refuses to finalize until all of `S` has arrived.
pub struct Aggregator<P: CurvePoint> {
 player_index: u32,
 /// Agreed dealer set, sorted ascending, no duplicates
 dealer_set: Vec<u32>,
 /// Verified sub-shares from dealers in `dealer_set`
 subshares: Vec<VerifiedSubShare<P::Scalar>>,
 /// Dealer commitments (for polynomial / group key derivation)
 commitments: Vec<DealerCommitment<P>>,
 _marker: PhantomData<P>,
}

impl<P: CurvePoint> Aggregator<P> {
 /// Create an aggregator for `player_index` that will combine sub-shares
 /// from exactly the dealers in `dealer_set`.
 ///
 /// `dealer_set` is normally the `t_old` dealers named by the epoch
 /// manifest. Any size ≥ `t_old` is mathematically fine as long as every
 /// player uses the same set.
 pub fn new(player_index: u32, dealer_set: &[u32]) -> Result<Self, Error> {
 if player_index == 0 {
 return Err(Error::InvalidIndex);
 }
 if dealer_set.is_empty() {
 return Err(Error::EmptyContributions);
 }
 let mut sorted = dealer_set.to_vec();
 sorted.sort_unstable();
 for w in sorted.windows(2) {
 if w[0] == w[1] {
 return Err(Error::DuplicateIndex(w[0]));
 }
 }
 if sorted[0] == 0 {
 return Err(Error::InvalidIndex);
 }
 Ok(Self {
 player_index,
 dealer_set: sorted,
 subshares: Vec::new(),
 commitments: Vec::new(),
 _marker: PhantomData,
 })
 }

 #[inline]
 pub fn player_index(&self) -> u32 {
 self.player_index
 }

 /// The agreed dealer set (sorted)
 #[inline]
 pub fn dealer_set(&self) -> &[u32] {
 &self.dealer_set
 }

 /// Number of verified sub-shares collected
 #[inline]
 pub fn count(&self) -> usize {
 self.subshares.len()
 }

 /// True once a verified sub-share has arrived from every dealer in the set
 #[inline]
 pub fn is_complete(&self) -> bool {
 self.subshares.len() == self.dealer_set.len()
 }

 /// Dealers in the set whose sub-share has not arrived yet
 pub fn missing_dealers(&self) -> Vec<u32> {
 self.dealer_set
 .iter()
 .copied()
 .filter(|d| !self.subshares.iter().any(|s| s.dealer_index == *d))
 .collect()
 }

 /// Add a sub-share with verification
 ///
 /// Returns Ok(true) if added, Ok(false) if duplicate, Err if invalid or
 /// from a dealer outside the agreed set.
 pub fn add_subshare(
 &mut self,
 subshare: SubShare<P::Scalar>,
 commitment: DealerCommitment<P>,
 ) -> Result<bool, Error> {
 // Validate indices
 if subshare.player_index != self.player_index {
 return Err(Error::InvalidIndex);
 }
 if subshare.dealer_index != commitment.dealer_index {
 return Err(Error::InvalidIndex);
 }
 if subshare.dealer_index == 0 {
 return Err(Error::InvalidIndex);
 }

 // Dealer must be in the agreed set
 if self.dealer_set.binary_search(&subshare.dealer_index).is_err() {
 return Err(Error::UnexpectedDealer(subshare.dealer_index));
 }

 // All dealers must have committed to the same new threshold
 if let Some(first) = self.commitments.first() {
 if first.threshold() != commitment.threshold() {
 return Err(Error::ThresholdMismatch {
 expected: first.threshold(),
 got: commitment.threshold(),
 });
 }
 }

 // Check for duplicate
 if self
 .subshares
 .iter()
 .any(|s| s.dealer_index == subshare.dealer_index)
 {
 return Ok(false);
 }

 // Verify sub-share against commitment
 if !commitment.verify_subshare(self.player_index, subshare.value()) {
 return Err(Error::InvalidResponse);
 }

 // Store
 self.subshares.push(VerifiedSubShare {
 dealer_index: subshare.dealer_index,
 value: subshare.value().clone(),
 });
 self.commitments.push(commitment);

 Ok(true)
 }

 /// Batch add sub-shares (more efficient for multiple)
 ///
 /// Verifies all, adds only valid ones from dealers in the set. Returns
 /// count of added.
 pub fn add_subshares_batch(
 &mut self,
 subshares: Vec<SubShare<P::Scalar>>,
 commitments: Vec<DealerCommitment<P>>,
 ) -> usize {
 let mut added = 0;
 for (subshare, commitment) in subshares.into_iter().zip(commitments) {
 if let Ok(true) = self.add_subshare(subshare, commitment) {
 added += 1;
 }
 }
 added
 }

 /// Lagrange coefficients over the agreed dealer set, in `dealer_set` order.
 /// Errors until every dealer in the set has delivered.
 fn lagrange(&self) -> Result<Vec<P::Scalar>, Error> {
 if !self.is_complete() {
 return Err(Error::InsufficientContributions {
 got: self.subshares.len(),
 need: self.dealer_set.len(),
 });
 }
 compute_lagrange_coefficients::<P::Scalar>(&self.dealer_set)
 }

 fn subshare_of(&self, dealer_index: u32) -> &VerifiedSubShare<P::Scalar> {
 self.subshares
 .iter()
 .find(|s| s.dealer_index == dealer_index)
 .expect("complete aggregator has every dealer")
 }

 fn commitment_of(&self, dealer_index: u32) -> &DealerCommitment<P> {
 self.commitments
 .iter()
 .find(|c| c.dealer_index == dealer_index)
 .expect("complete aggregator has every dealer")
 }

 /// Aggregate sub-shares into the new secret share
 ///
 /// Computes: s'_j = Σ_{i∈S} λ_i^S · σ_{i,j}
 pub fn aggregate(&self) -> Result<P::Scalar, Error> {
 let lagrange = self.lagrange()?;
 let mut new_share = P::Scalar::zero();
 for (dealer, lambda) in self.dealer_set.iter().zip(lagrange.iter()) {
 let term = lambda.mul(&self.subshare_of(*dealer).value);
 new_share = new_share.add(&term);
 }
 Ok(new_share)
 }

 /// The reshared polynomial in the exponent: F' = Σ_{i∈S} λ_i^S · C_i
 ///
 /// Identical for every player using the same dealer set. Publish it as
 /// the epoch's public key package.
 pub fn polynomial(&self) -> Result<SharePolynomial<P>, Error> {
 let lagrange = self.lagrange()?;
 let threshold = self.commitments[0].threshold() as usize;
 let mut coefficients = vec![P::identity(); threshold];
 for (dealer, lambda) in self.dealer_set.iter().zip(lagrange.iter()) {
 let commitment = self.commitment_of(*dealer);
 for (k, c) in commitment.coefficients.iter().enumerate() {
 coefficients[k] = coefficients[k].add(&c.mul_scalar(lambda));
 }
 }
 Ok(SharePolynomial { coefficients })
 }

 /// Derive group public key from dealer commitments: Y = F'(0)
 ///
 /// This must equal the original group key (invariant check).
 pub fn derive_group_key(&self) -> Result<P, Error> {
 Ok(self.polynomial()?.group_key().clone())
 }

 /// Finalize reshare: derive the polynomial, verify the group-key
 /// invariant, aggregate the share, and verify the share lies on the
 /// polynomial.
 ///
 /// Returns `(new_share, polynomial)`. The polynomial's `verifying_share(j)`
 /// gives every new member's public share.
 pub fn finalize(
 &self,
 expected_group_key: &P,
 ) -> Result<(P::Scalar, SharePolynomial<P>), Error> {
 let polynomial = self.polynomial()?;
 if polynomial.group_key() != expected_group_key {
 return Err(Error::InvalidCommitment);
 }
 let share = self.aggregate()?;
 if !polynomial.verify_share(self.player_index, &share) {
 return Err(Error::InvalidResponse);
 }
 Ok((share, polynomial))
 }
}

impl<P: CurvePoint> core::fmt::Debug for Aggregator<P> {
 fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
 f.debug_struct("Aggregator")
 .field("player_index", &self.player_index)
 .field("dealer_set", &self.dealer_set)
 .field("count", &self.subshares.len())
 .finish()
 }
}

// ============================================================================
// On-Chain Coordination Types
// ============================================================================

/// Reshare epoch state for on-chain storage
///
/// Tracks the progress of a reshare round.
#[derive(Clone, Debug)]
pub struct ReshareState<P: CurvePoint> {
 /// Epoch number being reshared into
 pub target_epoch: u64,
 /// Old threshold (required dealers)
 pub old_threshold: u32,
 /// New threshold (for new shares)
 pub new_threshold: u32,
 /// Number of new players
 pub new_player_count: u32,
 /// Collected dealer commitments (indexed by dealer_index - 1)
 pub commitments: Vec<Option<DealerCommitment<P>>>,
 /// Expected group public key (invariant)
 pub group_key: P,
}

impl<P: CurvePoint> ReshareState<P> {
 pub fn new(
 target_epoch: u64,
 old_dealer_count: u32,
 old_threshold: u32,
 new_threshold: u32,
 new_player_count: u32,
 group_key: P,
 ) -> Self {
 Self {
 target_epoch,
 old_threshold,
 new_threshold,
 new_player_count,
 commitments: vec![None; old_dealer_count as usize],
 group_key,
 }
 }

 /// Submit a dealer's commitment
 ///
 /// Returns true if this is a new commitment, false if duplicate.
 pub fn submit_commitment(
 &mut self,
 commitment: DealerCommitment<P>,
 ) -> Result<bool, Error> {
 let idx = commitment
 .dealer_index
 .checked_sub(1)
 .ok_or(Error::InvalidIndex)? as usize;

 if idx >= self.commitments.len() {
 return Err(Error::InvalidIndex);
 }

 if commitment.threshold() != self.new_threshold {
 return Err(Error::InvalidCommitment);
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

 /// Check if we have enough commitments to proceed
 pub fn has_quorum(&self) -> bool {
 self.commitment_count() >= self.old_threshold as usize
 }

 /// Get all submitted commitments
 pub fn get_commitments(&self) -> Vec<&DealerCommitment<P>> {
 self.commitments.iter().filter_map(|c| c.as_ref()).collect()
 }

 /// The deterministic dealer set for this round: the `old_threshold`
 /// lowest dealer indices that have committed. `None` until quorum.
 ///
 /// Every player must aggregate over exactly this set; put it in the
 /// signed epoch manifest and pass it to [`Aggregator::new`].
 pub fn dealer_set(&self) -> Option<Vec<u32>> {
 if !self.has_quorum() {
 return None;
 }
 Some(
 self.commitments
 .iter()
 .filter_map(|c| c.as_ref().map(|c| c.dealer_index))
 .take(self.old_threshold as usize)
 .collect(),
 )
 }

 /// Verify group key from the deterministic dealer set's commitments
 pub fn verify_group_key(&self) -> Result<bool, Error> {
 let dealer_indices = self.dealer_set().ok_or(Error::InsufficientContributions {
 got: self.commitment_count(),
 need: self.old_threshold as usize,
 })?;
 let lagrange = compute_lagrange_coefficients::<P::Scalar>(&dealer_indices)?;

 let mut derived_key = P::identity();
 for (idx, lambda) in dealer_indices.iter().zip(lagrange.iter()) {
 let commitment = self.commitments[(*idx - 1) as usize]
 .as_ref()
 .expect("dealer_set only names committed dealers");
 let term = commitment.share_commitment().mul_scalar(lambda);
 derived_key = derived_key.add(&term);
 }

 Ok(derived_key == self.group_key)
 }
}

// ============================================================================
// Batch Operations (for efficiency)
// ============================================================================

/// Batch verify multiple sub-shares against their commitments
///
/// More efficient than individual verification when verifying many.
/// Uses randomized linear combination for batch verification — independent
/// random weights per sub-share, so a single bad share is caught with
/// overwhelming probability.
///
/// Sub-shares are paired with commitments by `dealer_index`, not by position
///: the previous version zipped the two slices, so misaligned inputs
/// verified the wrong pairs and reported success.
pub fn batch_verify_subshares<P: CurvePoint, R: rand_core::RngCore + rand_core::CryptoRng>(
 player_index: u32,
 subshares: &[SubShare<P::Scalar>],
 commitments: &[DealerCommitment<P>],
 rng: &mut R,
) -> bool {
 if subshares.len() != commitments.len() || subshares.is_empty() {
 return false;
 }

 // Generate random weights for linear combination
 let weights: Vec<P::Scalar> = (0..subshares.len())
 .map(|_| P::Scalar::random(rng))
 .collect();

 // LHS: g^{Σ w_i * σ_i} RHS: Σ w_i * C_i(j), paired by dealer index.
 let mut lhs_exponent = P::Scalar::zero();
 let mut rhs = P::identity();
 for (subshare, w) in subshares.iter().zip(weights.iter()) {
 if subshare.player_index != player_index {
 return false;
 }
 let commitment = match commitments
 .iter()
 .find(|c| c.dealer_index == subshare.dealer_index)
 {
 Some(c) => c,
 None => return false,
 };
 let eval = match commitment.evaluate_at(player_index) {
 Ok(e) => e,
 Err(_) => return false,
 };
 lhs_exponent = lhs_exponent.add(&w.mul(subshare.value()));
 rhs = rhs.add(&eval.mul_scalar(w));
 }
 let lhs = P::generator().mul_scalar(&lhs_exponent);

 lhs == rhs
}

// ============================================================================
// Tests
// ============================================================================

#[cfg(all(test, feature = "ristretto255"))]
mod tests {
 use super::*;
 use crate::SecretShare;
 use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
 use rand::rngs::OsRng;

 fn shamir_split(secret: &Scalar, n: u32, t: u32) -> Vec<SecretShare<Scalar>> {
 let mut rng = OsRng;
 let mut coeffs = vec![*secret];
 for _ in 1..t {
 coeffs.push(Scalar::random(&mut rng));
 }

 (1..=n)
 .map(|i| {
 let x = Scalar::from(i);
 let mut y = Scalar::ZERO;
 let mut x_pow = Scalar::ONE;
 for coeff in &coeffs {
 y += coeff * x_pow;
 x_pow *= x;
 }
 SecretShare::new(i, y).expect("index is 1-indexed by construction")
 })
 .collect()
 }

 /// Old-set members holding `old_shares`, re-dealing to `new_n` players
 /// with new threshold `new_t`. Returns dealers keyed by index.
 fn make_dealers(
 old_shares: &[SecretShare<Scalar>],
 new_t: u32,
 ) -> Vec<Dealer<RistrettoPoint>> {
 let mut rng = OsRng;
 old_shares
 .iter()
 .map(|s| Dealer::new(s.index, *s.scalar(), new_t, &mut rng).expect("index is 1-indexed by construction"))
 .collect()
 }

 fn dealer_by_index(dealers: &[Dealer<RistrettoPoint>], idx: u32) -> &Dealer<RistrettoPoint> {
 dealers.iter().find(|d| d.index() == idx).unwrap()
 }

 /// Run a full reshare for players `1..=new_n` over dealer set `set`.
 fn reshare_all(
 dealers: &[Dealer<RistrettoPoint>],
 set: &[u32],
 new_n: u32,
 group_pubkey: &RistrettoPoint,
 ) -> Vec<(Scalar, SharePolynomial<RistrettoPoint>)> {
 (1..=new_n)
 .map(|j| {
 let mut agg: Aggregator<RistrettoPoint> = Aggregator::new(j, set).unwrap();
 for &i in set {
 let d = dealer_by_index(dealers, i);
 assert!(agg
 .add_subshare(d.generate_subshare(j).expect("index is 1-indexed by construction"), d.commitment().clone())
 .unwrap());
 }
 assert!(agg.is_complete());
 agg.finalize(group_pubkey).unwrap()
 })
 .collect()
 }

 fn reconstruct(shares: &[(u32, Scalar)]) -> Scalar {
 let indices: Vec<u32> = shares.iter().map(|(i, _)| *i).collect();
 let lagrange = compute_lagrange_coefficients::<Scalar>(&indices).unwrap();
 let mut acc = Scalar::ZERO;
 for ((_, s), l) in shares.iter().zip(lagrange.iter()) {
 acc += l * s;
 }
 acc
 }

 #[test]
 fn test_basic_reshare() {
 let mut rng = OsRng;

 let secret = Scalar::random(&mut rng);
 let group_pubkey: RistrettoPoint = RistrettoPoint::generator().mul_scalar(&secret);

 // Old: 5/3, New: 7/5. Dealer set = all five (any size ≥ t_old works
 // as long as every player uses the same set).
 let old_shares = shamir_split(&secret, 5, 3);
 let dealers = make_dealers(&old_shares, 5);
 let set = [1, 2, 3, 4, 5];

 let out = reshare_all(&dealers, &set, 7, &group_pubkey);

 // Any 5 of the 7 new shares reconstruct the secret
 let five: Vec<(u32, Scalar)> = [1u32, 3, 4, 6, 7]
 .iter()
 .map(|&j| (j, out[(j - 1) as usize].0))
 .collect();
 assert_eq!(reconstruct(&five), secret);
 }

 #[test]
 fn test_threshold_subset_dealers() {
 let mut rng = OsRng;

 let secret = Scalar::random(&mut rng);
 let group_pubkey: RistrettoPoint = RistrettoPoint::generator().mul_scalar(&secret);

 // Only 3 of 5 old members deal: S = {1, 3, 5}
 let old_shares = shamir_split(&secret, 5, 3);
 let dealers = make_dealers(&old_shares, 3);
 let set = [1, 3, 5];

 let out = reshare_all(&dealers, &set, 5, &group_pubkey);
 assert_eq!(*out[0].1.group_key(), group_pubkey);

 let three: Vec<(u32, Scalar)> = [2u32, 4, 5]
 .iter()
 .map(|&j| (j, out[(j - 1) as usize].0))
 .collect();
 assert_eq!(reconstruct(&three), secret);
 }

 #[test]
 fn test_polynomial_and_verifying_shares_consistent_across_players() {
 let mut rng = OsRng;
 let secret = Scalar::random(&mut rng);
 let group_pubkey: RistrettoPoint = RistrettoPoint::generator().mul_scalar(&secret);

 let old_shares = shamir_split(&secret, 5, 3);
 let dealers = make_dealers(&old_shares, 4);
 let set = [2, 3, 5];
 let out = reshare_all(&dealers, &set, 6, &group_pubkey);

 // Every player derived the same polynomial = the epoch's public key package
 let poly = &out[0].1;
 assert_eq!(poly.threshold(), 4);
 assert_eq!(*poly.group_key(), group_pubkey);
 for (_, p) in &out {
 assert_eq!(p, poly);
 }

 // Each player's share sits on it: g^{s'_j} == F'(j)
 for (j, (share, _)) in out.iter().enumerate() {
 let j = j as u32 + 1;
 assert!(poly.verify_share(j, share));
 assert_eq!(
 poly.verifying_share(j),
 RistrettoPoint::generator().mul_scalar(share)
 );
 // and not on a neighbour's slot
 assert!(!poly.verify_share(j % 6 + 1, share));
 }

 // Round-trips
 let bytes = poly.to_bytes();
 let back = SharePolynomial::<RistrettoPoint>::from_bytes(&bytes, 4).unwrap();
 assert_eq!(&back, poly);
 }

 /// The failure the fixed dealer set exists to prevent.
 ///
 /// Players who aggregate over different dealer subsets each pass the
 /// group-key invariant, but their shares lie on different polynomials and
 /// do not combine. The public polynomials differ, which is how a
 /// coordinator would now detect it.
 #[test]
 fn test_split_dealer_sets_are_incompatible_and_detectable() {
 let mut rng = OsRng;
 let secret = Scalar::random(&mut rng);
 let group_pubkey: RistrettoPoint = RistrettoPoint::generator().mul_scalar(&secret);

 let old_shares = shamir_split(&secret, 5, 3);
 let dealers = make_dealers(&old_shares, 3);

 // Players 1..3 saw S1, players 4..5 saw S2
 let s1 = [1, 2, 3];
 let s2 = [1, 2, 4];
 let group_a = reshare_all(&dealers, &s1, 3, &group_pubkey);
 let group_b: Vec<_> = (4..=5u32)
 .map(|j| {
 let mut agg: Aggregator<RistrettoPoint> = Aggregator::new(j, &s2).unwrap();
 for &i in &s2 {
 let d = dealer_by_index(&dealers, i);
 agg.add_subshare(d.generate_subshare(j).expect("index is 1-indexed by construction"), d.commitment().clone())
 .unwrap();
 }
 agg.finalize(&group_pubkey).unwrap()
 })
 .collect();

 // Both groups pass the invariant individually...
 assert_eq!(*group_a[0].1.group_key(), group_pubkey);
 assert_eq!(*group_b[0].1.group_key(), group_pubkey);
 // ...but hold different polynomials
 assert_ne!(group_a[0].1, group_b[0].1);

 // Homogeneous quorums reconstruct
 assert_eq!(
 reconstruct(&[(1, group_a[0].0), (2, group_a[1].0), (3, group_a[2].0)]),
 secret
 );
 // A mixed quorum does not
 assert_ne!(
 reconstruct(&[(1, group_a[0].0), (2, group_a[1].0), (4, group_b[0].0)]),
 secret
 );
 // and the stray member fails verification against group A's package
 assert!(!group_a[0].1.verify_share(4, &group_b[0].0));
 }

 #[test]
 fn test_unexpected_dealer_rejected_even_if_valid() {
 let mut rng = OsRng;
 let secret = Scalar::random(&mut rng);
 let old_shares = shamir_split(&secret, 5, 3);
 let dealers = make_dealers(&old_shares, 3);

 let mut agg: Aggregator<RistrettoPoint> = Aggregator::new(1, &[1, 2, 3]).unwrap();
 let d4 = dealer_by_index(&dealers, 4);
 // Perfectly valid sub-share from dealer 4, but 4 is not in S
 assert_eq!(
 agg.add_subshare(d4.generate_subshare(1).expect("index is 1-indexed by construction"), d4.commitment().clone()),
 Err(Error::UnexpectedDealer(4))
 );
 assert_eq!(agg.count(), 0);
 }

 #[test]
 fn test_incomplete_dealer_set_cannot_finalize() {
 let mut rng = OsRng;
 let secret = Scalar::random(&mut rng);
 let group_pubkey: RistrettoPoint = RistrettoPoint::generator().mul_scalar(&secret);
 let old_shares = shamir_split(&secret, 5, 3);
 let dealers = make_dealers(&old_shares, 3);

 let mut agg: Aggregator<RistrettoPoint> = Aggregator::new(2, &[1, 2, 3]).unwrap();
 for &i in &[1u32, 3] {
 let d = dealer_by_index(&dealers, i);
 agg.add_subshare(d.generate_subshare(2).expect("index is 1-indexed by construction"), d.commitment().clone())
 .unwrap();
 }
 assert!(!agg.is_complete());
 assert_eq!(agg.missing_dealers(), vec![2]);
 // Two of three arrived. Old code would have interpolated over {1,3}
 // with the wrong Lagrange set; now it refuses.
 assert_eq!(
 agg.finalize(&group_pubkey),
 Err(Error::InsufficientContributions { got: 2, need: 3 })
 );
 }

 #[test]
 fn test_threshold_mismatch_rejected() {
 let mut rng = OsRng;
 let secret = Scalar::random(&mut rng);
 let old_shares = shamir_split(&secret, 5, 3);

 let d1: Dealer<RistrettoPoint> =
 Dealer::new(1, *old_shares[0].scalar(), 3, &mut rng).expect("index is 1-indexed by construction");
 let d2: Dealer<RistrettoPoint> =
 Dealer::new(2, *old_shares[1].scalar(), 4, &mut rng).expect("index is 1-indexed by construction");

 let mut agg: Aggregator<RistrettoPoint> = Aggregator::new(1, &[1, 2, 3]).unwrap();
 agg.add_subshare(d1.generate_subshare(1).expect("index is 1-indexed by construction"), d1.commitment().clone())
 .unwrap();
 assert_eq!(
 agg.add_subshare(d2.generate_subshare(1).expect("index is 1-indexed by construction"), d2.commitment().clone()),
 Err(Error::ThresholdMismatch { expected: 3, got: 4 })
 );
 }

 #[test]
 fn test_aggregator_dealer_set_validation() {
 assert_eq!(
 Aggregator::<RistrettoPoint>::new(0, &[1]).err(),
 Some(Error::InvalidIndex)
 );
 assert_eq!(
 Aggregator::<RistrettoPoint>::new(1, &[]).err(),
 Some(Error::EmptyContributions)
 );
 assert_eq!(
 Aggregator::<RistrettoPoint>::new(1, &[3, 1, 3]).err(),
 Some(Error::DuplicateIndex(3))
 );
 assert_eq!(
 Aggregator::<RistrettoPoint>::new(1, &[0, 2]).err(),
 Some(Error::InvalidIndex)
 );
 let agg = Aggregator::<RistrettoPoint>::new(1, &[5, 2, 9]).unwrap();
 assert_eq!(agg.dealer_set(), &[2, 5, 9]);
 }

 /// sub-shares are paired with commitments by dealer index, not by
 /// position, so a caller that passes the two slices in different orders
 /// still verifies the right pairs — and a sub-share whose dealer has no
 /// commitment is rejected rather than checked against someone else's.
 #[test]
 fn batch_verification_pairs_by_dealer_index() {
 let mut rng = OsRng;
 let secret = Scalar::random(&mut rng);
 let old_shares = shamir_split(&secret, 3, 3);
 let dealers: Vec<Dealer<RistrettoPoint>> = old_shares
 .iter()
 .map(|s| Dealer::new(s.index, *s.scalar(), 3, &mut rng).unwrap())
 .collect();

 let player_index = 1u32;
 let subshares: Vec<SubShare<Scalar>> = dealers
 .iter()
 .map(|d| d.generate_subshare(player_index).unwrap())
 .collect();
 let mut commitments: Vec<DealerCommitment<RistrettoPoint>> =
 dealers.iter().map(|d| d.commitment().clone()).collect();

 // shuffled commitments: positional zipping would verify the wrong pairs
 commitments.reverse();
 assert!(batch_verify_subshares(
 player_index,
 &subshares,
 &commitments,
 &mut rng
 ));

 // a sub-share from a dealer the commitment set does not name
 let orphan = vec![SubShare::new(9, player_index, Scalar::random(&mut rng)).unwrap()];
 assert!(!batch_verify_subshares(
 player_index,
 &orphan,
 &commitments[..1],
 &mut rng
 ));
 }

 #[test]
 fn test_batch_verification() {
 let mut rng = OsRng;

 let secret = Scalar::random(&mut rng);
 let old_shares = shamir_split(&secret, 5, 3);

 let dealers: Vec<Dealer<RistrettoPoint>> = old_shares
 .iter()
 .map(|s| Dealer::new(s.index, *s.scalar(), 3, &mut rng).expect("index is 1-indexed by construction"))
 .collect();

 let player_index = 1u32;
 let subshares: Vec<SubShare<Scalar>> = dealers
 .iter()
 .map(|d| d.generate_subshare(player_index).expect("index is 1-indexed by construction"))
 .collect();
 let commitments: Vec<DealerCommitment<RistrettoPoint>> =
 dealers.iter().map(|d| d.commitment().clone()).collect();

 // Batch verify should succeed
 assert!(batch_verify_subshares(
 player_index,
 &subshares,
 &commitments,
 &mut rng
 ));

 // Tamper with one sub-share
 let mut bad_subshares = subshares.clone();
 bad_subshares[0] = SubShare::new(1, 1, Scalar::random(&mut rng)).expect("index is 1-indexed by construction");

 // Should fail
 assert!(!batch_verify_subshares(
 player_index,
 &bad_subshares,
 &commitments,
 &mut rng
 ));
 }

 #[test]
 fn test_reshare_state() {
 let mut rng = OsRng;

 let secret = Scalar::random(&mut rng);
 let group_pubkey: RistrettoPoint = RistrettoPoint::generator().mul_scalar(&secret);

 let old_shares = shamir_split(&secret, 5, 3);

 let mut state: ReshareState<RistrettoPoint> = ReshareState::new(
 1, // epoch
 5, // old dealers
 3, // old threshold
 3, // new threshold
 5, // new players
 group_pubkey,
 );

 // Submit commitments
 for share in &old_shares {
 let dealer: Dealer<RistrettoPoint> =
 Dealer::new(share.index, *share.scalar(), 3, &mut rng).expect("index is 1-indexed by construction");
 state
 .submit_commitment(dealer.commitment().clone())
 .unwrap();
 }

 assert!(state.has_quorum());
 assert_eq!(state.dealer_set(), Some(vec![1, 2, 3]));
 assert!(state.verify_group_key().unwrap());

 // Only dealers 2, 4, 5 commit: the set is the three lowest committed
 let mut partial: ReshareState<RistrettoPoint> =
 ReshareState::new(2, 5, 3, 3, 5, group_pubkey);
 assert_eq!(partial.dealer_set(), None);
 for &i in &[5usize, 2, 4] {
 let share = &old_shares[i - 1];
 let dealer: Dealer<RistrettoPoint> =
 Dealer::new(share.index, *share.scalar(), 3, &mut rng).expect("index is 1-indexed by construction");
 partial.submit_commitment(dealer.commitment().clone()).unwrap();
 }
 assert_eq!(partial.dealer_set(), Some(vec![2, 4, 5]));
 assert!(partial.verify_group_key().unwrap());
 }

 #[test]
 fn test_commitment_serialization() {
 let mut rng = OsRng;
 let dealer: Dealer<RistrettoPoint> = Dealer::new(1, Scalar::random(&mut rng), 3, &mut rng).expect("index is 1-indexed by construction");

 let original = dealer.commitment().clone();
 let bytes = original.to_bytes();
 let recovered = DealerCommitment::<RistrettoPoint>::from_bytes(&bytes, 3).unwrap();

 assert_eq!(original.dealer_index, recovered.dealer_index);
 assert_eq!(original.coefficients.len(), recovered.coefficients.len());
 for (a, b) in original
 .coefficients
 .iter()
 .zip(recovered.coefficients.iter())
 {
 assert_eq!(a, b);
 }
 }

 #[test]
 fn test_horner_evaluation() {
 let mut rng = OsRng;
 let dealer: Dealer<RistrettoPoint> = Dealer::new(1, Scalar::random(&mut rng), 5, &mut rng).expect("index is 1-indexed by construction");

 // Verify commitment evaluation matches sub-share
 for j in 1..=10u32 {
 let subshare = dealer.generate_subshare(j).expect("index is 1-indexed by construction");
 let eval = dealer.commitment().evaluate_at(j).expect("index is 1-indexed by construction");
 let expected: RistrettoPoint = RistrettoPoint::generator().mul_scalar(subshare.value());
 assert_eq!(eval, expected);
 }
 }
}
