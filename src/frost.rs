//! FROST: Flexible Round-Optimized Schnorr Threshold signatures
//!
//! Two-round threshold signing protocol producing standard Schnorr
//! signatures verifiable with the group public key alone.
//!
//! Reference: Komlo & Goldberg, "FROST: Flexible Round-Optimized Schnorr
//! Threshold Signatures" (SAC 2020). Standardized as RFC 9591.
//!
//! # Why FROST (not OSST)
//!
//! OSST produces a *threshold identification proof* — it proves that t-of-n
//! parties cooperated, but the output is not a standard Schnorr signature.
//! FROST produces a standard (R, z) Schnorr signature indistinguishable from
//! a single-signer signature. This matters when the signature must be verified
//! by an external system (e.g., the zcash network verifying a spend
//! authorization) that only understands standard Schnorr.
//!
//! # Protocol
//!
//! ```text
//! Round 1 (commitment):
//! Each signer i samples nonces (d_i, e_i), broadcasts (D_i, E_i).
//!
//! Round 2 (signing):
//! Given message m and commitment list B:
//! ρ_i = H_bind(i, m, B) (binding factor)
//! R = Σ (D_i + ρ_i · E_i) (group commitment)
//! c = H_sig(R, Y, m) (Schnorr challenge)
//! z_i = d_i + ρ_i · e_i + λ_i · c · s_i (signature share)
//!
//! Aggregation:
//! z = Σ z_i
//! σ = (R, z)
//!
//! Verification:
//! g^z == R + c · Y
//! ```
//!
//! # Security
//!
//! - **Nonce reuse is catastrophic.** Reusing a nonce pair across different
//!   messages leaks the signer's long-term secret. The [`Nonces`] type is
//!   consumed by [`sign`], preventing reuse at the type level.
//!
//! - **Binding factors** prevent a malicious signer from choosing their
//!   commitment adaptively after seeing others' commitments. Each signer's
//!   binding nonce is mixed with the full commitment list.
//!
//! - **Share verification** allows detecting a misbehaving signer before
//!   aggregation, given their public verification share `Y_i = g^{s_i}`.
//!
//! # Ciphersuite
//!
//! This module uses SHA-512 with domain separation for the binding factor
//! and challenge computations. For zcash RedPallas compatibility, a
//! ciphersuite adapter would override the challenge hash to match zcash's
//! BLAKE2b-based construction.

use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use sha2::{Digest, Sha512};

use crate::curve::{CurvePoint, CurveScalar};
use crate::error::Error;
use crate::lagrange::compute_lagrange_coefficients;
use crate::SecretShare;

// ============================================================================
// Types
// ============================================================================

/// Secret nonce pair for a single signing session.
///
/// # Security
///
/// Each `Nonces` value MUST be used for exactly one call to [`sign`].
/// `sign()` takes ownership, preventing reuse. Nonces are zeroized on drop.
///
/// Nonce reuse across different messages leaks the signer's long-term
/// secret key: given two signatures (R, z) and (R, z') on messages m, m'
/// with the same R, an attacker recovers s_i from z - z'.
pub struct Nonces<S: CurveScalar> {
 hiding: S,
 binding: S,
}

impl<S: CurveScalar> Nonces<S> {
 /// Build nonces from scalars a caller already holds.
 ///
 /// [`commit`] is the way to obtain nonces in a deployment: it samples
 /// them, and a FROST nonce that is chosen rather than sampled — or reused
 /// across sessions — gives up the share. This exists so the differential
 /// tests can drive this implementation and ZF `frost-core` from one set of
 /// nonces and compare the outputs, which needs both sides to start from
 /// the same scalars.
 #[cfg(any(test, feature = "zf"))]
 pub fn from_scalars(hiding: S, binding: S) -> Self {
 Self { hiding, binding }
 }

 /// Compute FROST Round 2 response: z_i = d_i + (rho_i * e_i) + (lambda_i * c * s_i)
 pub fn compute_response(
 self,
 rho: &S,
 lambda: &S,
 challenge: &S,
 secret: &S,
 ) -> S {
 // z_i = d_i + rho_i * e_i + lambda_i * c * s_i
 let rho_e = rho.mul(&self.binding);
 let lcs = lambda.mul(&challenge.mul(secret));
 self.hiding.add(&rho_e).add(&lcs)
 }
}

impl<S: CurveScalar> Drop for Nonces<S> {
 fn drop(&mut self) {
 self.hiding.zeroize();
 self.binding.zeroize();
 }
}

impl<S: CurveScalar> core::fmt::Debug for Nonces<S> {
 fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
 f.write_str("Nonces([REDACTED])")
 }
}

/// Public nonce commitments broadcast in Round 1.
///
/// Safe to transmit in the clear. Each signer broadcasts exactly one
/// `SigningCommitments` per signing session.
#[derive(Clone, Debug)]
pub struct SigningCommitments<P: CurvePoint> {
 /// Signer index (1-indexed, matching [`SecretShare`]).
 pub index: u32,
 /// Hiding commitment: D_i = g^{d_i}
 pub hiding: P,
 /// Binding commitment: E_i = g^{e_i}
 pub binding: P,
}

impl<P: CurvePoint> SigningCommitments<P> {
 /// Byte length of the serialized form.
 #[inline]
 pub fn byte_size() -> usize {
 4 + 2 * P::COMPRESSED_SIZE
 }

 /// Serialize: `index:4 || D || E`, the points in this curve's canonical
 /// compressed encoding (32 bytes each, 33 on secp256k1).
 pub fn to_bytes(&self) -> Vec<u8> {
 let mut buf = Vec::with_capacity(Self::byte_size());
 buf.extend_from_slice(&self.index.to_le_bytes());
 buf.extend_from_slice(self.hiding.compress().as_ref());
 buf.extend_from_slice(self.binding.compress().as_ref());
 buf
 }

 /// Deserialize from bytes.
 pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
 if bytes.len() != Self::byte_size() {
 return Err(Error::InvalidCommitment);
 }
 let index = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
 if index == 0 {
 return Err(Error::InvalidIndex);
 }
 let n = P::COMPRESSED_SIZE;
 let hiding = P::decompress(&bytes[4..4 + n]).ok_or(Error::InvalidCommitment)?;
 let binding =
 P::decompress(&bytes[4 + n..4 + 2 * n]).ok_or(Error::InvalidCommitment)?;
 Ok(Self {
 index,
 hiding,
 binding,
 })
 }
}

/// Collected commitments and message, distributed to signers for Round 2.
///
/// Constructed by any participant after collecting commitments from at
/// least t signers. The commitment ordering is deterministic (sorted by
/// index) to ensure all signers compute identical binding factors.
pub struct SigningPackage<P: CurvePoint> {
 message: Vec<u8>,
 commitments: BTreeMap<u32, SigningCommitments<P>>,
 /// cached encoded commitments for binding factor computation
 encoded_commitments: Vec<u8>,
}

impl<P: CurvePoint> SigningPackage<P> {
 /// Construct a signing package from a message and collected commitments.
 ///
 /// Commitments are stored sorted by index. Duplicate indices are rejected.
 pub fn new(
 message: Vec<u8>,
 commitments: Vec<SigningCommitments<P>>,
 ) -> Result<Self, Error> {
 let mut map = BTreeMap::new();
 for c in commitments {
 if c.index == 0 {
 return Err(Error::InvalidIndex);
 }
 if map.contains_key(&c.index) {
 return Err(Error::DuplicateIndex(c.index));
 }
 map.insert(c.index, c);
 }
 if map.is_empty() {
 return Err(Error::EmptyContributions);
 }

 let encoded = encode_commitments(&map);

 Ok(Self {
 message,
 commitments: map,
 encoded_commitments: encoded,
 })
 }

 /// The message being signed.
 #[inline]
 pub fn message(&self) -> &[u8] {
 &self.message
 }

 /// Number of signers in this session.
 #[inline]
 pub fn num_signers(&self) -> usize {
 self.commitments.len()
 }

 /// Signer indices in sorted order.
 pub fn signer_indices(&self) -> Vec<u32> {
 self.commitments.keys().copied().collect()
 }

 /// Get a signer's commitments by index.
 pub fn get_commitments(&self, index: u32) -> Option<&SigningCommitments<P>> {
 self.commitments.get(&index)
 }

 /// Compute the binding factor for signer i.
 ///
 /// `ρ_i = H("frost-binding-v2" ‖ Y ‖ len(m) ‖ m ‖ len(B) ‖ B ‖ index)` —
 /// see the `compute_binding_factor` source for why the group public key is in
 /// there and why it is a parameter rather than a field of this
 /// type.
 ///
 /// Public so a nested (hierarchical) position can obtain the SAME outer
 /// binding factor the flat protocol would apply to it — see
 /// `nested::inner_sign_v2`. Exposing it is what lets the inner group bind
 /// its nonces to the full outer commitment set.
 ///
 /// # `group_pubkey` is caller-anchored
 ///
 /// It is deliberately NOT stored in the package. A `SigningPackage` is
 /// coordinator-shaped data — a signer typically receives one — and a group
 /// key read out of it would be the coordinator's assertion, which is
 /// precisely the trap. Pass `Y` from your own key material.
 pub fn binding_factor(&self, index: u32, group_pubkey: &P) -> P::Scalar {
 compute_binding_factor::<P>(
 index,
 group_pubkey,
 &self.message,
 &self.encoded_commitments,
 )
 }

 /// Compute the group commitment R = Σ (D_i + ρ_i · E_i).
 /// Public so a nested position's inner holders can INDEPENDENTLY recompute
 /// the outer context (R_outer) from public data instead of trusting the
 /// coordinator's word for it.
 ///
 /// `group_pubkey` must come from the caller's own key material — see
 /// [`binding_factor`](Self::binding_factor).
 pub fn group_commitment(&self, group_pubkey: &P) -> P {
 let mut r = P::identity();
 for c in self.commitments.values() {
 let rho = self.binding_factor(c.index, group_pubkey);
 // D_i + ρ_i · E_i
 let bound = c.binding.mul_scalar(&rho);
 r = r.add(&c.hiding);
 r = r.add(&bound);
 }
 r
 }

 /// Compute the Schnorr challenge c = H("frost-challenge-v1" || R || Y || m).
 /// Public so a nested position's inner holders can INDEPENDENTLY recompute
 /// the outer context (challenge) from public data instead of trusting the
 /// coordinator's word for it.
 pub fn challenge(&self, group_commitment: &P, group_pubkey: &P) -> P::Scalar {
 compute_challenge::<P>(group_commitment, group_pubkey, &self.message)
 }
}

/// A single signer's share of the aggregate signature.
///
/// z_i = d_i + ρ_i · e_i + λ_i · c · s_i
pub struct SignatureShare<S: CurveScalar> {
 /// Signer index.
 pub index: u32,
 /// Partial response.
 pub response: S,
}

impl<S: CurveScalar> SignatureShare<S> {
 /// Serialize: `index:4 || z:32` = 36 bytes
 pub fn to_bytes(&self) -> [u8; 36] {
 let mut buf = [0u8; 36];
 buf[0..4].copy_from_slice(&self.index.to_le_bytes());
 buf[4..36].copy_from_slice(&self.response.to_bytes());
 buf
 }

 /// Deserialize.
 pub fn from_bytes(bytes: &[u8; 36]) -> Result<Self, Error> {
 let index = u32::from_le_bytes(bytes[0..4].try_into().unwrap());
 if index == 0 {
 return Err(Error::InvalidIndex);
 }
 let resp_bytes: [u8; 32] = bytes[4..36].try_into().unwrap();
 let response =
 S::from_canonical_bytes(&resp_bytes).ok_or(Error::InvalidResponse)?;
 Ok(Self { index, response })
 }
}

impl<S: CurveScalar> core::fmt::Debug for SignatureShare<S> {
 fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
 f.debug_struct("SignatureShare")
 .field("index", &self.index)
 .field("response", &"[REDACTED]")
 .finish()
 }
}

/// Aggregate Schnorr signature.
///
/// Verifiable with standard Schnorr: g^z == R + H(R, Y, m) · Y
///
/// Indistinguishable from a single-signer Schnorr signature.
#[derive(Clone, Debug)]
pub struct Signature<P: CurvePoint> {
 /// Group commitment.
 pub r: P,
 /// Aggregate response.
 pub z: P::Scalar,
}

impl<P: CurvePoint> Signature<P> {
 /// Byte length of the serialized form.
 #[inline]
 pub fn byte_size() -> usize {
 P::COMPRESSED_SIZE + 32
 }

 /// Serialize: `R || z`.
 pub fn to_bytes(&self) -> Vec<u8> {
 let mut buf = Vec::with_capacity(Self::byte_size());
 buf.extend_from_slice(self.r.compress().as_ref());
 buf.extend_from_slice(&self.z.to_bytes());
 buf
 }

 /// Deserialize.
 pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
 if bytes.len() != Self::byte_size() {
 return Err(Error::InvalidCommitment);
 }
 let n = P::COMPRESSED_SIZE;
 let r = P::decompress(&bytes[0..n]).ok_or(Error::InvalidCommitment)?;
 let z_bytes: [u8; 32] = bytes[n..n + 32].try_into().unwrap();
 let z = P::Scalar::from_canonical_bytes(&z_bytes)
 .ok_or(Error::InvalidResponse)?;
 Ok(Self { r, z })
 }
}

// ============================================================================
// Hash functions
// ============================================================================

/// Encode all commitments for binding factor input.
///
/// Deterministic encoding sorted by index (BTreeMap guarantees this).
fn encode_commitments<P: CurvePoint>(
 commitments: &BTreeMap<u32, SigningCommitments<P>>,
) -> Vec<u8> {
 let mut buf = Vec::with_capacity(commitments.len() * (4 + 2 * P::COMPRESSED_SIZE));
 for c in commitments.values() {
 buf.extend_from_slice(&c.index.to_le_bytes());
 buf.extend_from_slice(c.hiding.compress().as_ref());
 buf.extend_from_slice(c.binding.compress().as_ref());
 }
 buf
}

/// Binding factor
///
/// ```text
/// ρ_i = H("frost-binding-v2" ‖ Y ‖ len(m) ‖ m ‖ len(B) ‖ B ‖ i)
/// ```
///
/// Mixes the signer's index with the full commitment list to prevent adaptive
/// commitment selection attacks, and with the group public key.
///
/// # Why `Y` is in here
///
/// Through 0.4.x the binding factor was `H(dom ‖ i ‖ len(m) ‖ m ‖ B)` — no
/// group public key. RFC 9591 §4.4 puts it first in the binding-factor input:
///
/// ```text
/// rho_input = G.SerializeElement(group_public_key) ‖ H4(msg)
/// ‖ H5(encode_group_commitment_list(commitment_list))
/// ‖ EncodeScalar(identifier)
/// ```
///
/// The consequence of omitting it is that one commitment set and one message
/// produce the same ρ under every group key, so a transcript is not pinned to
/// the key it was collected for — which is exactly the freedom this otherwise hands a
/// coordinator that also gets to assert `Y`. Including it makes the whole
/// signing transcript, binding factor and challenge alike, a function of the
/// group key, so substituting `Y'` moves ρ as well as `c` and the two can no
/// longer be made to agree with a package the honest signers already accepted.
///
/// The ordering follows RFC 9591 (key, message, commitments, identifier); the
/// length prefixes on the two variable fields keep the encoding injective
/// without the RFC's intermediate H4/H5 hashes. `Y` needs none: a compressed
/// point is fixed-width for a given curve.
///
/// This changes every signature this crate produces, which is why it rides the
/// 0.5.0 wire break.
fn compute_binding_factor<P: CurvePoint>(
 index: u32,
 group_pubkey: &P,
 message: &[u8],
 encoded_commitments: &[u8],
) -> P::Scalar {
 let mut h = Sha512::new();
 h.update(b"frost-binding-v2");
 h.update(group_pubkey.compress());
 h.update((message.len() as u64).to_le_bytes());
 h.update(message);
 h.update((encoded_commitments.len() as u64).to_le_bytes());
 h.update(encoded_commitments);
 h.update(index.to_le_bytes());
 let hash: [u8; 64] = h.finalize().into();
 <P::Scalar as CurveScalar>::from_bytes_wide(&hash)
}

/// Schnorr challenge: c = H("frost-challenge-v1" || R || Y || m)
///
/// This is the standard Schnorr challenge computation with domain
/// separation. For zcash compatibility, replace with BLAKE2b-512
/// personalized with "Zcash_RedPallasH".
fn compute_challenge<P: CurvePoint>(
 group_commitment: &P,
 group_pubkey: &P,
 message: &[u8],
) -> P::Scalar {
 let mut h = Sha512::new();
 h.update(b"frost-challenge-v1");
 h.update(group_commitment.compress());
 h.update(group_pubkey.compress());
 h.update(message);
 let hash: [u8; 64] = h.finalize().into();
 P::Scalar::from_bytes_wide(&hash)
}

// ============================================================================
// Protocol
// ============================================================================

/// Round 1: sample nonces, return commitments for broadcast.
///
/// The returned [`Nonces`] MUST be passed to [`sign`] for exactly one
/// signing session. Store them securely until Round 2.
pub fn commit<P: CurvePoint, R: rand_core::RngCore + rand_core::CryptoRng>(
 index: u32,
 rng: &mut R,
) -> Result<(Nonces<P::Scalar>, SigningCommitments<P>), Error> {
 if index == 0 {
 return Err(Error::InvalidIndex);
 }

 let hiding = P::Scalar::random(rng);
 let binding = P::Scalar::random(rng);

 let commitments = SigningCommitments {
 index,
 hiding: P::generator().mul_scalar(&hiding),
 binding: P::generator().mul_scalar(&binding),
 };

 Ok((Nonces { hiding, binding }, commitments))
}

/// Round 2: produce a signature share.
///
/// Consumes the nonces to prevent reuse. Computes:
///
/// ```text
/// ρ_i = H_bind(i, m, B)
/// R = Σ (D_j + ρ_j · E_j)
/// c = H_sig(R, Y, m)
/// z_i = d_i + ρ_i · e_i + λ_i · c · s_i
/// ```
///
/// # Errors
///
/// Returns `InvalidIndex` if this signer's index is not in the package.
/// [`sign`] with the message given as an epoch-bound
/// [`SigningContext`](crate::SigningContext).
///
/// The package must have been built over `ctx.encode()`; otherwise this
/// returns [`Error::MessageMismatch`] rather than signing whatever the
/// coordinator put in the package. This is the only-way-in form: a caller that
/// uses it cannot forget to bind the epoch and manifest.
///
/// Note the verifier-side rule (see [`crate::context`]): epoch binding is a
/// property of the verifier. A verifier MUST rebuild the context bytes from an
/// epoch and manifest hash it obtains from an authoritative source, and never
/// from data carried alongside the signature.
pub fn sign_with_context<P: CurvePoint>(
 ctx: &crate::SigningContext<'_>,
 package: &SigningPackage<P>,
 nonces: Nonces<P::Scalar>,
 share: &SecretShare<P::Scalar>,
 group_pubkey: &P,
) -> Result<SignatureShare<P::Scalar>, Error> {
 if package.message() != ctx.encode().as_slice() {
 return Err(Error::MessageMismatch);
 }
 sign(package, nonces, share, group_pubkey)
}

pub fn sign<P: CurvePoint>(
 package: &SigningPackage<P>,
 nonces: Nonces<P::Scalar>,
 share: &SecretShare<P::Scalar>,
 group_pubkey: &P,
) -> Result<SignatureShare<P::Scalar>, Error> {
 // verify our index is in the signing set, and that the commitment the
 // package carries under it is the one these nonces produced.
 //
 // Without this the coordinator chooses the binding factor an honest signer
 // applies to its own binding nonce while holding the hiding nonce fixed.
 // One session is one equation in three unknowns, so it is not by itself an
 // extraction — but it becomes one for any signer whose nonce state
 // survives a process restart, and it is a cheap, standard invariant that
 // ZF `frost-core` enforces as `Error::IncorrectCommitment`.
 let mine = package
 .get_commitments(share.index)
 .ok_or(Error::InvalidIndex)?;
 if mine.hiding != P::generator().mul_scalar(&nonces.hiding)
 || mine.binding != P::generator().mul_scalar(&nonces.binding)
 {
 return Err(Error::UnexpectedCommitment);
 }

 // binding factor for this signer
 let rho = package.binding_factor(share.index, group_pubkey);

 // group commitment R
 let group_commitment = package.group_commitment(group_pubkey);

 // challenge c = H(R, Y, m)
 let challenge = package.challenge(&group_commitment, group_pubkey);

 // lagrange coefficient λ_i for this signer in the signing set
 let indices = package.signer_indices();
 let lagrange = compute_lagrange_coefficients::<P::Scalar>(&indices)?;
 let my_pos = indices
 .iter()
 .position(|&i| i == share.index)
 .ok_or(Error::InvalidIndex)?;
 let lambda = &lagrange[my_pos];

 // z_i = d_i + ρ_i · e_i + λ_i · c · s_i
 let response = nonces
 .hiding
 .add(&rho.mul(&nonces.binding))
 .add(&lambda.mul(&challenge).mul(share.scalar()));

 // nonces dropped here, zeroized

 Ok(SignatureShare {
 index: share.index,
 response,
 })
}

/// Aggregate signature shares into a standard Schnorr signature.
///
/// If `verifier_shares` is provided (map of index → g^{s_i}), each
/// share is verified before aggregation. This detects misbehaving
/// signers — if verification fails, the offending index is reported
/// in the error.
///
/// # Errors
///
/// - `InsufficientContributions` if fewer shares than signers in package
/// - `InvalidIndex` if a share's index is not in the signing package
/// - `InvalidResponse` if a share fails verification
pub fn aggregate<P: CurvePoint>(
 package: &SigningPackage<P>,
 shares: &[SignatureShare<P::Scalar>],
 group_pubkey: &P,
 verifier_shares: Option<&BTreeMap<u32, P>>,
) -> Result<Signature<P>, Error> {
 if shares.len() < package.num_signers() {
 return Err(Error::InsufficientContributions {
 got: shares.len(),
 need: package.num_signers(),
 });
 }

 let group_commitment = package.group_commitment(group_pubkey);
 let challenge = package.challenge(&group_commitment, group_pubkey);

 // optionally verify each share
 if let Some(vshares) = verifier_shares {
 let indices = package.signer_indices();
 let lagrange = compute_lagrange_coefficients::<P::Scalar>(&indices)?;

 for share in shares {
 let pos = indices
 .iter()
 .position(|&i| i == share.index)
 .ok_or(Error::InvalidIndex)?;

 let yi = vshares
 .get(&share.index)
 .ok_or(Error::InvalidIndex)?;

 let rho = package.binding_factor(share.index, group_pubkey);
 let comm = package
 .get_commitments(share.index)
 .ok_or(Error::InvalidIndex)?;

 // expected: g^{z_i} == D_i + ρ_i·E_i + λ_i·c·Y_i
 let lhs = P::generator().mul_scalar(&share.response);

 let rhs = comm
 .hiding
 .add(&comm.binding.mul_scalar(&rho))
 .add(&yi.mul_scalar(&lagrange[pos].mul(&challenge)));

 if lhs != rhs {
 return Err(Error::InvalidResponse);
 }
 }
 }

 // z = Σ z_i
 let mut z = P::Scalar::zero();
 for share in shares {
 z = z.add(&share.response);
 }

 Ok(Signature {
 r: group_commitment,
 z,
 })
}

/// Verify a standard Schnorr signature against a group public key.
///
/// Checks: g^z == R + H(R, Y, m) · Y
pub fn verify_signature<P: CurvePoint>(
 group_pubkey: &P,
 message: &[u8],
 signature: &Signature<P>,
) -> bool {
 let challenge = compute_challenge::<P>(&signature.r, group_pubkey, message);

 // lhs = g^z
 let lhs = P::generator().mul_scalar(&signature.z);

 // rhs = R + c · Y
 let rhs = signature.r.add(&group_pubkey.mul_scalar(&challenge));

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

 fn public_share(share: &SecretShare<Scalar>) -> RistrettoPoint {
 RistrettoPoint::generator().mul_scalar(share.scalar())
 }

 #[test]
 fn test_frost_basic() {
 let mut rng = OsRng;

 let secret = Scalar::random(&mut rng);
 let group_pubkey: RistrettoPoint =
 RistrettoPoint::generator().mul_scalar(&secret);

 let n = 5u32;
 let t = 3u32;
 let shares = shamir_split(&secret, n, t);
 let message = b"the signed zcash transaction goes here";

 // round 1: each signer commits
 let mut all_nonces = Vec::new();
 let mut all_commitments = Vec::new();
 for share in &shares[0..t as usize] {
 let (nonces, commitments) = commit::<RistrettoPoint, _>(share.index, &mut rng).expect("index is 1-indexed by construction");
 all_nonces.push(nonces);
 all_commitments.push(commitments);
 }

 // build signing package
 let package =
 SigningPackage::new(message.to_vec(), all_commitments).unwrap();

 // round 2: each signer produces a share
 let mut sig_shares = Vec::new();
 for (share, nonces) in shares[0..t as usize]
 .iter()
 .zip(all_nonces)
 {
 let sig_share =
 sign::<RistrettoPoint>(&package, nonces, share, &group_pubkey)
 .unwrap();
 sig_shares.push(sig_share);
 }

 // aggregate without share verification
 let signature = aggregate::<RistrettoPoint>(
 &package,
 &sig_shares,
 &group_pubkey,
 None,
 )
 .unwrap();

 // verify
 assert!(
 verify_signature(&group_pubkey, message, &signature),
 "FROST signature should verify"
 );
 }

 #[test]
 fn test_frost_with_share_verification() {
 let mut rng = OsRng;

 let secret = Scalar::random(&mut rng);
 let group_pubkey: RistrettoPoint =
 RistrettoPoint::generator().mul_scalar(&secret);

 let n = 7u32;
 let t = 4u32;
 let shares = shamir_split(&secret, n, t);
 let message = b"withdrawal tx bytes";

 // build verifier share map
 let mut vshares = BTreeMap::new();
 for s in &shares {
 vshares.insert(s.index, public_share(s));
 }

 // use non-consecutive signers: 1, 3, 5, 7
 let active: Vec<&SecretShare<Scalar>> =
 vec![&shares[0], &shares[2], &shares[4], &shares[6]];

 // round 1
 let mut nonces_vec = Vec::new();
 let mut commitments_vec = Vec::new();
 for s in &active {
 let (n, c) = commit::<RistrettoPoint, _>(s.index, &mut rng).expect("index is 1-indexed by construction");
 nonces_vec.push(n);
 commitments_vec.push(c);
 }

 let package =
 SigningPackage::new(message.to_vec(), commitments_vec).unwrap();

 // round 2
 let mut sig_shares = Vec::new();
 for (s, nonces) in active.iter().zip(nonces_vec) {
 sig_shares.push(
 sign::<RistrettoPoint>(&package, nonces, s, &group_pubkey)
 .unwrap(),
 );
 }

 // aggregate with verification
 let signature = aggregate::<RistrettoPoint>(
 &package,
 &sig_shares,
 &group_pubkey,
 Some(&vshares),
 )
 .unwrap();

 assert!(verify_signature(&group_pubkey, message, &signature));
 }

 #[test]
 fn test_frost_wrong_message_fails() {
 let mut rng = OsRng;

 let secret = Scalar::random(&mut rng);
 let group_pubkey: RistrettoPoint =
 RistrettoPoint::generator().mul_scalar(&secret);

 let shares = shamir_split(&secret, 5, 3);
 let message = b"correct message";

 let mut nonces_vec = Vec::new();
 let mut commitments_vec = Vec::new();
 for s in &shares[0..3] {
 let (n, c) = commit::<RistrettoPoint, _>(s.index, &mut rng).expect("index is 1-indexed by construction");
 nonces_vec.push(n);
 commitments_vec.push(c);
 }

 let package =
 SigningPackage::new(message.to_vec(), commitments_vec).unwrap();

 let mut sig_shares = Vec::new();
 for (s, nonces) in shares[0..3].iter().zip(nonces_vec) {
 sig_shares.push(
 sign::<RistrettoPoint>(&package, nonces, s, &group_pubkey)
 .unwrap(),
 );
 }

 let signature =
 aggregate::<RistrettoPoint>(&package, &sig_shares, &group_pubkey, None)
 .unwrap();

 assert!(verify_signature(&group_pubkey, message, &signature));
 assert!(
 !verify_signature(&group_pubkey, b"wrong message", &signature),
 "wrong message should not verify"
 );
 }

 #[test]
 fn test_frost_wrong_pubkey_fails() {
 let mut rng = OsRng;

 let secret = Scalar::random(&mut rng);
 let group_pubkey: RistrettoPoint =
 RistrettoPoint::generator().mul_scalar(&secret);

 let shares = shamir_split(&secret, 5, 3);
 let message = b"test";

 let mut nonces_vec = Vec::new();
 let mut commitments_vec = Vec::new();
 for s in &shares[0..3] {
 let (n, c) = commit::<RistrettoPoint, _>(s.index, &mut rng).expect("index is 1-indexed by construction");
 nonces_vec.push(n);
 commitments_vec.push(c);
 }

 let package =
 SigningPackage::new(message.to_vec(), commitments_vec).unwrap();

 let mut sig_shares = Vec::new();
 for (s, nonces) in shares[0..3].iter().zip(nonces_vec) {
 sig_shares.push(
 sign::<RistrettoPoint>(&package, nonces, s, &group_pubkey)
 .unwrap(),
 );
 }

 let signature =
 aggregate::<RistrettoPoint>(&package, &sig_shares, &group_pubkey, None)
 .unwrap();

 let wrong_pubkey: RistrettoPoint =
 RistrettoPoint::generator().mul_scalar(&Scalar::random(&mut rng));
 assert!(!verify_signature(&wrong_pubkey, message, &signature));
 }

 #[test]
 fn test_frost_signature_serialization() {
 let mut rng = OsRng;

 let secret = Scalar::random(&mut rng);
 let group_pubkey: RistrettoPoint =
 RistrettoPoint::generator().mul_scalar(&secret);

 let shares = shamir_split(&secret, 3, 2);
 let message = b"roundtrip test";

 let mut nonces_vec = Vec::new();
 let mut commitments_vec = Vec::new();
 for s in &shares[0..2] {
 let (n, c) = commit::<RistrettoPoint, _>(s.index, &mut rng).expect("index is 1-indexed by construction");
 nonces_vec.push(n);
 commitments_vec.push(c);
 }

 let package =
 SigningPackage::new(message.to_vec(), commitments_vec).unwrap();

 let mut sig_shares = Vec::new();
 for (s, nonces) in shares[0..2].iter().zip(nonces_vec) {
 sig_shares.push(
 sign::<RistrettoPoint>(&package, nonces, s, &group_pubkey)
 .unwrap(),
 );
 }

 let signature =
 aggregate::<RistrettoPoint>(&package, &sig_shares, &group_pubkey, None)
 .unwrap();

 let bytes = signature.to_bytes();
 let recovered =
 Signature::<RistrettoPoint>::from_bytes(&bytes).unwrap();

 assert!(verify_signature(&group_pubkey, message, &recovered));
 }

 #[test]
 fn test_frost_bad_share_detected() {
 let mut rng = OsRng;

 let secret = Scalar::random(&mut rng);
 let group_pubkey: RistrettoPoint =
 RistrettoPoint::generator().mul_scalar(&secret);

 let shares = shamir_split(&secret, 5, 3);

 let mut vshares = BTreeMap::new();
 for s in &shares {
 vshares.insert(s.index, public_share(s));
 }

 let message = b"detect misbehaver";

 let mut nonces_vec = Vec::new();
 let mut commitments_vec = Vec::new();
 for s in &shares[0..3] {
 let (n, c) = commit::<RistrettoPoint, _>(s.index, &mut rng).expect("index is 1-indexed by construction");
 nonces_vec.push(n);
 commitments_vec.push(c);
 }

 let package =
 SigningPackage::new(message.to_vec(), commitments_vec).unwrap();

 let mut sig_shares = Vec::new();
 for (s, nonces) in shares[0..3].iter().zip(nonces_vec) {
 sig_shares.push(
 sign::<RistrettoPoint>(&package, nonces, s, &group_pubkey)
 .unwrap(),
 );
 }

 // tamper with one share
 sig_shares[1] = SignatureShare {
 index: shares[1].index,
 response: Scalar::random(&mut rng),
 };

 let result = aggregate::<RistrettoPoint>(
 &package,
 &sig_shares,
 &group_pubkey,
 Some(&vshares),
 );
 assert!(
 matches!(result, Err(Error::InvalidResponse)),
 "tampered share should be detected"
 );
 }

 #[test]
 fn test_frost_duplicate_commitments_rejected() {
 let mut rng = OsRng;
 let (_, c1) = commit::<RistrettoPoint, _>(1, &mut rng).expect("index is 1-indexed by construction");
 let (_, c2) = commit::<RistrettoPoint, _>(1, &mut rng).expect("index is 1-indexed by construction"); // same index
 let result =
 SigningPackage::<RistrettoPoint>::new(b"test".to_vec(), vec![c1, c2]);
 assert!(matches!(result, Err(Error::DuplicateIndex(1))));
 }
}

#[cfg(all(test, feature = "pallas"))]
mod pallas_tests {
 use super::*;
 use crate::SecretShare;
 use alloc::collections::BTreeMap;
 use pasta_curves::group::ff::Field;
 use pasta_curves::pallas::{Point, Scalar};
 use rand::rngs::OsRng;

 fn shamir_split(secret: &Scalar, n: u32, t: u32) -> Vec<SecretShare<Scalar>> {
 let mut rng = OsRng;
 let mut coeffs = vec![*secret];
 for _ in 1..t {
 coeffs.push(<Scalar as crate::curve::CurveScalar>::random(&mut rng));
 }
 (1..=n)
 .map(|i| {
 let x = Scalar::from(i as u64);
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

 #[test]
 fn test_pallas_frost() {
 let mut rng = OsRng;

 let secret = <Scalar as crate::curve::CurveScalar>::random(&mut rng);
 let group_pubkey: Point = Point::generator().mul_scalar(&secret);

 let n = 5u32;
 let t = 3u32;
 let shares = shamir_split(&secret, n, t);
 let message = b"pallas frost withdrawal";

 // round 1
 let mut nonces_vec = Vec::new();
 let mut commitments_vec = Vec::new();
 for s in &shares[0..t as usize] {
 let (nonces, commitments) = commit::<Point, _>(s.index, &mut rng).expect("index is 1-indexed by construction");
 nonces_vec.push(nonces);
 commitments_vec.push(commitments);
 }

 let package =
 SigningPackage::new(message.to_vec(), commitments_vec).unwrap();

 // round 2
 let mut sig_shares = Vec::new();
 for (s, nonces) in shares[0..t as usize]
 .iter()
 .zip(nonces_vec)
 {
 sig_shares.push(
 sign::<Point>(&package, nonces, s, &group_pubkey).unwrap(),
 );
 }

 let signature =
 aggregate::<Point>(&package, &sig_shares, &group_pubkey, None)
 .unwrap();

 assert!(verify_signature(&group_pubkey, message, &signature));
 }

 #[test]
 fn test_pallas_frost_with_dkg() {
 use crate::dkg;

 let mut rng = OsRng;
 let n = 5u32;
 let t = 3u32;

 // DKG
 let dealers: Vec<dkg::Dealer<Point>> =
 (1..=n).map(|i| dkg::Dealer::new(i, t, &mut rng).expect("index is 1-indexed by construction")).collect();

 let commitments: Vec<&crate::reshare::DealerCommitment<Point>> =
 dealers.iter().map(|d| d.commitment()).collect();

 let mut secret_shares = Vec::new();
 let mut group_key = None;
 let mut vshares = BTreeMap::new();

 for j in 1..=n {
 let mut agg: dkg::Aggregator<Point> = dkg::Aggregator::all_dealers(j, n).unwrap();
 for dealer in &dealers {
 let subshare = dealer.generate_subshare(j).expect("index is 1-indexed by construction");
 agg.add_subshare(subshare, commitments[(dealer.index() - 1) as usize])
 .unwrap();
 }
 let share_scalar = agg.finalize().unwrap();
 if group_key.is_none() {
 group_key = Some(agg.derive_group_key().unwrap());
 }
 let ss = SecretShare::new(j, share_scalar).expect("index is 1-indexed by construction");
 vshares.insert(j, Point::generator().mul_scalar(ss.scalar()));
 secret_shares.push(ss);
 }

 let group_key = group_key.unwrap();
 let message = b"dkg + frost integration test";

 // FROST sign with 3 of 5
 let active = &secret_shares[0..t as usize];

 let mut nonces_vec = Vec::new();
 let mut commitments_vec = Vec::new();
 for s in active {
 let (n, c) = commit::<Point, _>(s.index, &mut rng).expect("index is 1-indexed by construction");
 nonces_vec.push(n);
 commitments_vec.push(c);
 }

 let package =
 SigningPackage::new(message.to_vec(), commitments_vec).unwrap();

 let mut sig_shares = Vec::new();
 for (s, nonces) in active.iter().zip(nonces_vec) {
 sig_shares.push(
 sign::<Point>(&package, nonces, s, &group_key).unwrap(),
 );
 }

 // aggregate with share verification
 let signature = aggregate::<Point>(
 &package,
 &sig_shares,
 &group_key,
 Some(&vshares),
 )
 .unwrap();

 assert!(
 verify_signature(&group_key, message, &signature),
 "DKG + FROST should produce valid signature"
 );
 }
}
