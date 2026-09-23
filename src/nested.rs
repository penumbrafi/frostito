//! nested FROST: one outer share controlled by an inner threshold group
//!
//! the inner group collectively holds one position in an outer FROST scheme.
//! the outer share's secret never exists as a single scalar — it is born
//! distributed via interleaved DKG and used distributed via nested signing.
//!
//! # architecture
//!
//! ```text
//! outer FROST (t_out, n_out):
//! positions 1..n_out, one of which is the nested position
//!
//! nested position (t_in, n_in):
//! inner holders collectively control one outer share
//! OSST gates authorization, inner FROST produces the partial signature
//! ```
//!
//! # signing protocol (v2)
//!
//! 1. inner holders agree a `session_id`, generate nonce pairs, publish
//!    H(k ‖ session ‖ D_k ‖ E_k), then reveal (D_k, E_k)
//! 2. the aggregate PAIR (Σ D_k, Σ E_k) is presented to the outer protocol as
//!    the nested position's ordinary `SigningCommitments`
//! 3. the outer protocol computes ρ = H(index, m, B) over the full outer
//!    commitment list and c = H(R, Y, m) exactly as for any other signer
//! 4. each inner holder recomputes ρ and c itself from the outer package —
//!    it holds the message it approved, and refuses to sign any other — and
//!    produces z_k = d_k + ρ·e_k + (λ_out·c·μ_k)·σ_k
//! 5. shares are verified individually, then summed: z_nested = Σ z_k
//!
//! # security
//!
//! The nested position is presented to the outer protocol exactly as a flat
//! signer would be, so it receives a real outer binding factor: ρ moves
//! whenever any honest inner commitment moves, and an adversary cannot hold an
//! honest effective nonce fixed while sweeping the challenge.
//!
//! What the in-crate equivalence test establishes is honest-transcript
//! equality — the nested position's response is bit-for-bit a flat signer's —
//! **not** a reduction. A reduction from an adversary against the nested
//! scheme to one against FROST is plausible and is the right question for a
//! cryptographer; it has not been done. The inner group must be treated as one
//! trust unit: `t_in` corrupt holders are a corrupt outer signer, with no
//! further guarantee.
//!
//! v1 — a pre-bound single point with an identity binding commitment — was
//! insecure and has been removed.

use alloc::vec;
use alloc::vec::Vec;
use sha2::{Digest, Sha512};

use crate::curve::{CurvePoint, CurveScalar};
use crate::dkg;
use crate::error::Error;
use crate::lagrange::compute_lagrange_coefficients;
use crate::reshare::DealerCommitment;
use crate::SecretShare;

// ============================================================================
// Interleaved DKG
// ============================================================================

/// state for one coefficient's inner DKG
///
/// the nested position's outer polynomial f_p(x) = a_0 + a_1*x + ... + a_{t-1}*x^{t-1}
/// has t_out coefficients. each coefficient is shared via an independent inner DKG.
pub struct CoefficientDkg<P: CurvePoint> {
 /// which outer polynomial coefficient this DKG is for (0-indexed)
 pub coeff_index: u32,
 /// inner DKG dealers (one per inner holder)
 pub dealers: Vec<dkg::Dealer<P>>,
}

/// result of the interleaved DKG for one inner holder
pub struct InnerShare<S: CurveScalar> {
 /// inner holder's index (1-indexed)
 pub holder_index: u32,
 /// shamir shares of each outer polynomial coefficient
 /// `alpha[j]` = holder's share of coefficient `j`
 pub coefficient_shares: Vec<S>,
}

impl<S: CurveScalar> InnerShare<S> {
 /// compute this holder's share of the outer polynomial evaluated at point x
 ///
 /// returns: Σ_j alpha_j * x^j (share of f_p(x))
 /// this is a valid shamir share of f_p(x) by the homomorphic property.
 pub fn eval_at(&self, x: u32) -> S {
 let x_scalar = S::from_u32(x);
 let mut result = S::zero();
 let mut x_pow = S::one();
 for alpha in &self.coefficient_shares {
 result = result.add(&alpha.mul(&x_pow));
 x_pow = x_pow.mul(&x_scalar);
 }
 result
 }
}

/// run the interleaved DKG for a nested position
///
/// produces inner holders' shares of each outer polynomial coefficient.
/// The output of [`interleaved_dkg`]: one [`InnerShare`] per inner holder,
/// and `g^{a_j}` for each coefficient of the outer polynomial.
pub type InterleavedDkg<P> = (Vec<InnerShare<<P as CurvePoint>::Scalar>>, Vec<P>);

/// nobody learns the coefficients themselves.
///
/// # returns
/// - `Vec<InnerShare>`: one per inner holder (1-indexed)
/// - `Vec<P>`: g^{a_j} for each coefficient j (public commitments)
pub fn interleaved_dkg<P: CurvePoint, R: rand_core::RngCore + rand_core::CryptoRng>(
 inner_n: u32,
 inner_t: u32,
 outer_t: u32,
 rng: &mut R,
) -> Result<InterleavedDkg<P>, Error> {
 let mut coeff_dkgs: Vec<CoefficientDkg<P>> = Vec::with_capacity(outer_t as usize);
 for j in 0..outer_t {
 let dealers: Vec<dkg::Dealer<P>> = (1..=inner_n)
 .map(|k| dkg::Dealer::new(k, inner_t, rng).expect("index is 1-indexed by construction"))
 .collect();
 coeff_dkgs.push(CoefficientDkg {
 coeff_index: j,
 dealers,
 });
 }

 // coefficient commitments: g^{a_j} = Σ_k g^{p_k(0)} for each DKG j
 let mut coeff_commitments: Vec<P> = Vec::with_capacity(outer_t as usize);
 for dkg_j in &coeff_dkgs {
 let mut commitment = P::identity();
 for dealer in &dkg_j.dealers {
 commitment = commitment.add(dealer.commitment().share_commitment());
 }
 coeff_commitments.push(commitment);
 }

 // aggregate shares for each holder
 let mut inner_shares: Vec<InnerShare<P::Scalar>> = Vec::with_capacity(inner_n as usize);
 for k in 1..=inner_n {
 let mut coefficient_shares = Vec::with_capacity(outer_t as usize);
 for dkg_j in &coeff_dkgs {
 let commitments: Vec<&DealerCommitment<P>> =
 dkg_j.dealers.iter().map(|d| d.commitment()).collect();

 // new dkg::Aggregator API: the agreed dealer set is fixed at
 // construction (here, exactly this DKG's dealers) and finalize()
 // takes no args - it sums the verified sub-shares once every dealer
 // in the set has delivered.
 let dealer_set: Vec<u32> = dkg_j.dealers.iter().map(|d| d.index()).collect();
 let mut agg: dkg::Aggregator<P> = dkg::Aggregator::new(k, &dealer_set)?;
 for dealer in &dkg_j.dealers {
 let subshare = dealer.generate_subshare(k).expect("index is 1-indexed by construction");
 agg.add_subshare(subshare, commitments[(dealer.index() - 1) as usize])?;
 }
 coefficient_shares.push(agg.finalize()?);
 }
 inner_shares.push(InnerShare {
 holder_index: k,
 coefficient_shares,
 });
 }

 Ok((inner_shares, coeff_commitments))
}

/// split an outer participant's evaluation among inner holders via shamir.
///
/// returns (shares, feldman_commitments) so inner holders can verify.
/// the feldman commitments are g^{c_j} for the splitting polynomial
/// c(x) = evaluation + c_1·x + ... + c_{t-1}·x^{t-1}.
pub fn split_evaluation_for_inner<P: CurvePoint, R: rand_core::RngCore + rand_core::CryptoRng>(
 evaluation: &P::Scalar,
 inner_n: u32,
 inner_t: u32,
 rng: &mut R,
) -> (Vec<(u32, P::Scalar)>, DealerCommitment<P>) {
 let mut coeffs = vec![evaluation.clone()];
 for _ in 1..inner_t {
 coeffs.push(P::Scalar::random(rng));
 }

 // feldman commitment for verification
 // dealer_index is arbitrary here (must be >0 per DealerCommitment invariant).
 // use 1 as placeholder — the index is not meaningful for split verification,
 // only the polynomial commitments matter.
 let commitment = DealerCommitment::from_polynomial(1, &coeffs).expect("index is 1-indexed by construction");

 let shares = (1..=inner_n)
 .map(|k| {
 let x = P::Scalar::from_u32(k);
 let mut result = P::Scalar::zero();
 let mut x_pow = P::Scalar::one();
 for c in &coeffs {
 result = result.add(&c.mul(&x_pow));
 x_pow = x_pow.mul(&x);
 }
 (k, result)
 })
 .collect();

 (shares, commitment)
}

/// verify a split evaluation piece against its feldman commitment
pub fn verify_split_piece<P: CurvePoint>(
 commitment: &DealerCommitment<P>,
 holder_index: u32,
 piece: &P::Scalar,
) -> bool {
 commitment.verify_subshare(holder_index, piece)
}

/// combine inner DKG shares with outer participants' split evaluations.
///
/// σ_k = inner_eval_at(p) + Σ_i π_{i,k}
///
/// the sum of shamir shares is a shamir share of the sum (homomorphic property).
/// since inner_eval_at(p) is a shamir share of f_p(p) and each π_{i,k} is a
/// shamir share of f_i(p), the result is a shamir share of
/// f_1(p) + f_2(p) + ... + f_p(p) = s_p (the nested position's outer secret).
pub fn combine_shares<S: CurveScalar>(
 inner_share: &InnerShare<S>,
 nested_position: u32,
 outer_eval_pieces: &[(u32, S)],
) -> S {
 let mut result = inner_share.eval_at(nested_position);
 for (_, piece) in outer_eval_pieces {
 result = result.add(piece);
 }
 result
}

// ============================================================================
// Nested FROST signing
// ============================================================================

/// inner holder's nonce pair for nested signing
pub struct InnerNonces<S: CurveScalar> {
 pub holder_index: u32,
 /// The round this nonce pair belongs to. Carried so that
 /// [`inner_sign_v2`] can refuse to answer a round the holder did not
 /// commit to.
 pub session_id: [u8; 32],
 pub(crate) hiding: S,
 pub(crate) binding: S,
}

impl<S: CurveScalar> Drop for InnerNonces<S> {
 fn drop(&mut self) {
 self.hiding.zeroize();
 self.binding.zeroize();
 }
}

/// inner holder's nonce commitments (broadcast to relay + other inner holders)
#[derive(Clone, Debug, PartialEq)]
pub struct InnerCommitments<P: CurvePoint> {
 pub holder_index: u32,
 /// The inner round this commitment was produced for.
 pub session_id: [u8; 32],
 pub hiding: P,
 pub binding: P,
}

/// generate nonces for an inner holder
///
/// `session_id` names the inner round. It is public, must be agreed by the
/// inner group before round 1 (a hash of the epoch, the nested position and a
/// round counter is the intended shape), and is carried through to
/// [`inner_sign_v2`], which refuses to sign for any other round.
pub fn inner_commit<P: CurvePoint, R: rand_core::RngCore + rand_core::CryptoRng>(
 holder_index: u32,
 session_id: [u8; 32],
 rng: &mut R,
) -> (InnerNonces<P::Scalar>, InnerCommitments<P>) {
 let hiding = P::Scalar::random(rng);
 let binding = P::Scalar::random(rng);

 let commitments = InnerCommitments {
 holder_index,
 session_id,
 hiding: P::generator().mul_scalar(&hiding),
 binding: P::generator().mul_scalar(&binding),
 };

 (
 InnerNonces {
 holder_index,
 session_id,
 hiding,
 binding,
 },
 commitments,
 )
}


/// inner holder's partial signature
pub struct InnerSignatureShare<S: CurveScalar> {
 pub holder_index: u32,
 pub response: S,
}

impl<S: CurveScalar> core::fmt::Debug for InnerSignatureShare<S> {
 fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
 f.debug_struct("InnerSignatureShare")
 .field("holder_index", &self.holder_index)
 .field("response", &"[REDACTED]")
 .finish()
 }
}


// ============================================================================
// Tests
// ============================================================================

#[cfg(all(test, feature = "ristretto255"))]
mod tests {
 use super::*;
 use crate::frost;
 use curve25519_dalek::ristretto::RistrettoPoint;
 use curve25519_dalek::scalar::Scalar;
 use rand::rngs::OsRng;

 type Point = RistrettoPoint;

 const SESSION: [u8; 32] = [0xA5; 32];

 /// `from_outer` must reproduce, exactly, the derivation every call site
 /// was hand-rolling — otherwise inner shares silently fail to verify.
 #[test]
 fn from_outer_matches_the_hand_rolled_derivation() {
 let mut rng = OsRng;
 let msg = b"outer context derivation";

 let secret = <Scalar as CurveScalar>::random(&mut rng);
 let group_pubkey = <Point as CurvePoint>::generator().mul_scalar(&secret);

 let (_, commits_1) = frost::commit::<Point, _>(1, &mut rng).expect("index is 1-indexed by construction");
 let (_, commits_2) = frost::commit::<Point, _>(2, &mut rng).expect("index is 1-indexed by construction");
 let package =
 frost::SigningPackage::new(msg.to_vec(), vec![commits_1, commits_2]).unwrap();

 // hand-rolled, as jury.rs / escrow.rs do it today
 let rho_2 = package.binding_factor(2, &group_pubkey);
 let r_outer = package.group_commitment(&group_pubkey);
 let challenge = package.challenge(&r_outer, &group_pubkey);
 let indices = package.signer_indices();
 let outer_lagrange = compute_lagrange_coefficients::<Scalar>(&indices).unwrap();
 let pos_2 = indices.iter().position(|&i| i == 2).unwrap();

 let derived = InnerSigningParamsV2::from_outer::<Point>(&package, &group_pubkey, 2).unwrap();

 assert_eq!(derived.outer_binding, rho_2);
 assert_eq!(derived.outer_challenge, challenge);
 assert_eq!(derived.outer_lambda, outer_lagrange[pos_2]);

 // position 1 gets a different context, as it must
 let derived_1 =
 InnerSigningParamsV2::from_outer::<Point>(&package, &group_pubkey, 1).unwrap();
 assert_ne!(derived_1.outer_binding, derived.outer_binding);
 assert_ne!(derived_1.outer_lambda, derived.outer_lambda);
 // the challenge is a property of the session, not the position
 assert_eq!(derived_1.outer_challenge, derived.outer_challenge);

 // an index outside the outer signing set has no context at all
 assert!(matches!(
 InnerSigningParamsV2::from_outer::<Point>(&package, &group_pubkey, 7),
 Err(Error::InvalidIndex)
 ));
 }

 /// THE property that makes v2 reviewable: a nested position is
 /// indistinguishable from a flat FROST signer.
 ///
 /// We build a real outer 2-of-2 over positions {1, 2}. Position 2's key is
 /// split 3-of-5 among inner holders, and its nonce is the sum of the inner
 /// holders' nonces. We then produce the signature TWICE — once through the
 /// nested v2 path, once with position 2 as an ordinary signer holding the
 /// reconstructed scalar — and assert the signature shares and the final
 /// signatures are IDENTICAL, and that both verify.
 ///
 /// If this holds, security reduces to FROST's own proof: the outer
 /// protocol cannot tell a nested position from a flat one, so an adversary
 /// against the nested scheme is an adversary against FROST.
 #[test]
 fn nested_v2_equals_flat_frost() {
 let mut rng = OsRng;
 let msg = b"settlement: a=1000 b=0";

 // ── outer key: degree-1 polynomial ⇒ 2-of-2 over positions 1,2 ──────
 let secret = Scalar::random(&mut rng);
 let a1 = Scalar::random(&mut rng);
 let eval = |x: u32| {
 let x = <Scalar as CurveScalar>::from_u32(x);
 secret.add(&a1.mul(&x))
 };
 let sigma_1 = eval(1);
 let sigma_2 = eval(2); // the NESTED position's outer share
 let group_pubkey = <Point as CurvePoint>::generator().mul_scalar(&secret);

 let share_1 = SecretShare::new(1, sigma_1).expect("index is 1-indexed by construction");
 let share_2_flat = SecretShare::new(2, sigma_2).expect("index is 1-indexed by construction");

 // ── split position 2's key 3-of-5 among inner holders ──────────────
 let inner_t = 3u32;
 let inner_n = 5u32;
 let (inner_pieces, dealer_commitment) =
 split_evaluation_for_inner::<Point, _>(&sigma_2, inner_n, inner_t, &mut rng);

 // every holder verifies its piece against the Feldman commitment
 for (k, piece) in &inner_pieces {
 assert!(
 verify_split_piece::<Point>(&dealer_commitment, *k, piece),
 "inner piece {} failed Feldman verification",
 k
 );
 }

 let quorum: Vec<u32> = vec![1, 2, 3];
 let inner_shares: Vec<SecretShare<Scalar>> = quorum
 .iter()
 .map(|k| {
 let (_, piece) = inner_pieces.iter().find(|(i, _)| i == k).unwrap();
 SecretShare::new(*k, *piece).expect("index is 1-indexed by construction")
 })
 .collect();

 // sanity: the quorum reconstructs position 2's outer share
 {
 let lag = compute_lagrange_coefficients::<Scalar>(&quorum).unwrap();
 let mut recon = <Scalar as CurveScalar>::zero();
 for (i, s) in inner_shares.iter().enumerate() {
 recon = recon.add(&lag[i].mul(s.scalar()));
 }
 assert_eq!(recon, sigma_2, "inner quorum must reconstruct the outer share");
 }

 // ── inner round 0/1: commit–reveal ─────────────────────────────────
 let mut inner_nonces = Vec::new();
 let mut inner_commitments = Vec::new();
 let mut precommits = Vec::new();
 for &k in &quorum {
 let (n, c) = inner_commit::<Point, _>(k, SESSION, &mut rng);
 precommits.push(inner_precommit(&c));
 inner_nonces.push(n);
 inner_commitments.push(c);
 }
 for (pre, revealed) in precommits.iter().zip(inner_commitments.iter()) {
 assert!(verify_inner_precommit::<Point>(pre, revealed));
 }
 // a tampered reveal must be caught
 {
 let mut tampered = inner_commitments[0].clone();
 tampered.hiding = tampered.hiding.add(&<Point as CurvePoint>::generator());
 assert!(!verify_inner_precommit::<Point>(&precommits[0], &tampered));
 }

 // capture the aggregate nonce scalars so we can drive the FLAT signer
 // with the same randomness (this is test-only introspection)
 let d_sum = inner_nonces
 .iter()
 .fold(<Scalar as CurveScalar>::zero(), |acc, n| acc.add(&n.hiding));
 let e_sum = inner_nonces
 .iter()
 .fold(<Scalar as CurveScalar>::zero(), |acc, n| acc.add(&n.binding));

 // round 0: the commit-reveal precommitments the aggregate now verifies
 let inner_precommits: Vec<(u32, [u8; 32])> = inner_commitments
 .iter()
 .map(|c| (c.holder_index, inner_precommit::<Point>(c)))
 .collect();
 let (d_nested, e_nested) =
 aggregate_inner_commitment_pair::<Point>(&SESSION, &inner_precommits, &inner_commitments)
 .unwrap();
 assert_eq!(d_nested, <Point as CurvePoint>::generator().mul_scalar(&d_sum));
 assert_eq!(e_nested, <Point as CurvePoint>::generator().mul_scalar(&e_sum));

 // ── outer round: position 1 commits normally, position 2 uses the
 // aggregate PAIR (so the outer binding factor actually applies) ──
 let (nonces_1, commits_1) = frost::commit::<Point, _>(1, &mut rng).expect("index is 1-indexed by construction");
 let commits_2 = frost::SigningCommitments {
 index: 2,
 hiding: d_nested,
 binding: e_nested,
 };
 let package =
 frost::SigningPackage::new(msg.to_vec(), vec![commits_1, commits_2.clone()]).unwrap();

 // outer context — recomputable by any inner holder from public data
 let rho_2 = package.binding_factor(2, &group_pubkey);
 let r_outer = package.group_commitment(&group_pubkey);
 let challenge = package.challenge(&r_outer, &group_pubkey);
 let indices = package.signer_indices();
 let outer_lagrange = compute_lagrange_coefficients::<Scalar>(&indices).unwrap();
 let pos_2 = indices.iter().position(|&i| i == 2).unwrap();
 // A coordinator-supplied context is only accepted when it is the one
 // the holder recomputes for itself. Deprecated since 0.5.0 —
 // still exercised here because the legacy wire path still ships.
 #[allow(deprecated)]
 let params = InnerSigningParamsV2::from_coordinator_checked::<Point>(
 &rho_2,
 &challenge,
 &outer_lagrange[pos_2],
 &package,
 &group_pubkey,
 2,
 )
 .unwrap();
 #[allow(deprecated)]
 let mismatched = InnerSigningParamsV2::from_coordinator_checked::<Point>(
 &rho_2,
 &Scalar::random(&mut rng),
 &outer_lagrange[pos_2],
 &package,
 &group_pubkey,
 2,
 );
 assert!(matches!(mismatched, Err(Error::ChallengeMismatch)));

 let request = NestedSigningRequest {
 package: &package,
 nested_index: 2,
 session_id: SESSION,
 inner_precommits: &inner_precommits,
 inner_commitments: &inner_commitments,
 active_indices: &quorum,
 inner_threshold: 3,
 };

 // ── inner holders sign; every share is verified before aggregation ──
 let inner_lagrange = compute_lagrange_coefficients::<Scalar>(&quorum).unwrap();
 let public_shares: Vec<(u32, Point)> = inner_shares
 .iter()
 .map(|s| {
 (
 s.index,
 <Point as CurvePoint>::generator().mul_scalar(s.scalar()),
 )
 })
 .collect();

 let mut inner_sigs = Vec::new();
 for (n, share) in inner_nonces.into_iter().zip(inner_shares.iter()) {
 let sig = inner_sign_v2::<Point>(n, share, &group_pubkey, msg, &request).unwrap();
 let pos = quorum.iter().position(|&i| i == share.index).unwrap();
 let commitment = inner_commitments
 .iter()
 .find(|c| c.holder_index == share.index)
 .unwrap();
 let public = &public_shares
 .iter()
 .find(|(i, _)| *i == share.index)
 .unwrap()
 .1;
 assert!(
 verify_inner_share::<Point>(&sig, commitment, public, &params, &inner_lagrange[pos]),
 "holder {} produced an unverifiable share",
 share.index
 );
 inner_sigs.push(sig);
 }

 let z_nested = aggregate_inner_shares_verified::<Point>(
 &inner_sigs,
 &inner_commitments,
 &public_shares,
 &params,
 &quorum,
 )
 .expect("all inner shares must verify");

 // ── the equivalence: what a FLAT signer at position 2 would produce ──
 // z_flat = d + ρ·e + λ·c·σ₂
 let z_flat = d_sum
 .add(&rho_2.mul(&e_sum))
 .add(&params.outer_lambda.mul(&challenge).mul(&sigma_2));
 assert_eq!(
 z_nested, z_flat,
 "nested share must equal the flat FROST share bit-for-bit"
 );

 // ── and the assembled signature must verify ────────────────────────
 let sig_1 = frost::sign::<Point>(&package, nonces_1, &share_1, &group_pubkey).unwrap();
 let sig_2 = frost::SignatureShare {
 index: 2,
 response: z_nested,
 };
 let signature =
 frost::aggregate::<Point>(&package, &[sig_1, sig_2], &group_pubkey, None).unwrap();
 assert!(
 frost::verify_signature::<Point>(&group_pubkey, msg, &signature),
 "nested-produced signature must verify under the group key"
 );

 // silence unused warning for the flat share (kept for documentation)
 let _ = share_2_flat;
 }

 /// A dishonest inner holder is NAMED, not silently folded into a signature
 /// that then fails to verify with no attribution.
 #[test]
 fn v2_names_the_dishonest_inner_holder() {
 let mut rng = OsRng;
 let msg = b"m";
 let sigma_2 = Scalar::random(&mut rng);
 let quorum: Vec<u32> = vec![1, 2, 3];
 let (inner_pieces, _) = split_evaluation_for_inner::<Point, _>(&sigma_2, 5, 3, &mut rng);
 let inner_shares: Vec<SecretShare<Scalar>> = quorum
 .iter()
 .map(|k| {
 let (_, piece) = inner_pieces.iter().find(|(i, _)| i == k).unwrap();
 SecretShare::new(*k, *piece).expect("index is 1-indexed by construction")
 })
 .collect();

 let mut inner_nonces = Vec::new();
 let mut inner_commitments = Vec::new();
 for &k in &quorum {
 let (n, c) = inner_commit::<Point, _>(k, SESSION, &mut rng);
 inner_nonces.push(n);
 inner_commitments.push(c);
 }
 // round 0: the commit-reveal precommitments the aggregate now verifies
 let inner_precommits: Vec<(u32, [u8; 32])> = inner_commitments
 .iter()
 .map(|c| (c.holder_index, inner_precommit::<Point>(c)))
 .collect();
 let (d_nested, e_nested) =
 aggregate_inner_commitment_pair::<Point>(&SESSION, &inner_precommits, &inner_commitments)
 .unwrap();
 let group_pubkey = <Point as CurvePoint>::generator().mul_scalar(&sigma_2);

 let (_, commits_1) = frost::commit::<Point, _>(1, &mut rng).expect("index is 1-indexed by construction");
 let commits_2 = frost::SigningCommitments {
 index: 2,
 hiding: d_nested,
 binding: e_nested,
 };
 let package =
 frost::SigningPackage::new(msg.to_vec(), vec![commits_1, commits_2]).unwrap();
 let r_outer = package.group_commitment(&group_pubkey);
 let indices = package.signer_indices();
 let outer_lagrange = compute_lagrange_coefficients::<Scalar>(&indices).unwrap();
 let pos_2 = indices.iter().position(|&i| i == 2).unwrap();
 let _ = (&r_outer, &outer_lagrange, pos_2);
 let params = InnerSigningParamsV2::from_outer::<Point>(&package, &group_pubkey, 2).unwrap();
 let request = NestedSigningRequest {
 package: &package,
 nested_index: 2,
 session_id: SESSION,
 inner_precommits: &inner_precommits,
 inner_commitments: &inner_commitments,
 active_indices: &quorum,
 inner_threshold: 3,
 };

 let public_shares: Vec<(u32, Point)> = inner_shares
 .iter()
 .map(|s| {
 (
 s.index,
 <Point as CurvePoint>::generator().mul_scalar(s.scalar()),
 )
 })
 .collect();

 let mut sigs = Vec::new();
 for (n, share) in inner_nonces.into_iter().zip(inner_shares.iter()) {
 sigs.push(inner_sign_v2::<Point>(n, share, &group_pubkey, msg, &request).unwrap());
 }
 // holder 2 goes rogue
 sigs[1].response = sigs[1].response.add(&<Scalar as CurveScalar>::one());

 let err = aggregate_inner_shares_verified::<Point>(
 &sigs,
 &inner_commitments,
 &public_shares,
 &params,
 &quorum,
 )
 .expect_err("a tampered share must be rejected");
 assert_eq!(err, vec![2], "the cheating holder must be identified");
 }

 #[test]
 fn test_interleaved_dkg() {
 let mut rng = OsRng;
 let inner_n = 5u32;
 let inner_t = 3u32;
 let outer_t = 2u32;

 let (inner_shares, coeff_commitments) =
 interleaved_dkg::<Point, _>(inner_n, inner_t, outer_t, &mut rng).unwrap();

 assert_eq!(inner_shares.len(), inner_n as usize);
 assert_eq!(coeff_commitments.len(), outer_t as usize);

 // verify: any t_inner shares of each coefficient reconstruct correctly
 for (j, _) in coeff_commitments.iter().enumerate().take(outer_t as usize) {
 let shares_j: Vec<(u32, Scalar)> = inner_shares
 .iter()
 .map(|s| (s.holder_index, s.coefficient_shares[j]))
 .collect();

 let active: Vec<u32> = shares_j[..inner_t as usize]
 .iter()
 .map(|s| s.0)
 .collect();
 let lambda = compute_lagrange_coefficients::<Scalar>(&active).unwrap();
 let mut reconstructed = Scalar::ZERO;
 for (i, (_, val)) in shares_j[..inner_t as usize].iter().enumerate() {
 reconstructed += lambda[i] * val;
 }

 let expected_point = Point::generator().mul_scalar(&reconstructed);
 assert_eq!(expected_point, coeff_commitments[j]);
 }
 }

 #[test]
 fn test_split_evaluation_with_feldman_verification() {
 let mut rng = OsRng;
 let secret = Scalar::random(&mut rng);
 let inner_n = 5u32;
 let inner_t = 3u32;

 let (pieces, commitment) =
 split_evaluation_for_inner::<Point, _>(&secret, inner_n, inner_t, &mut rng);

 // every piece should verify against the feldman commitment
 for &(k, ref piece) in &pieces {
 assert!(
 verify_split_piece::<Point>(&commitment, k, piece),
 "piece {} failed feldman verification",
 k
 );
 }

 // a tampered piece should fail
 let tampered = Scalar::random(&mut rng);
 assert!(!verify_split_piece::<Point>(&commitment, 1, &tampered));
 }


}


// ============================================================================
// Nested FROST v2 — outer-bound, commit-reveal, verifiable
// ============================================================================
//
// v1 pre-bound the inner nonces and presented one point to the outer protocol.
// That severs the outer binding coupling (see the warning on
// `aggregate_inner_commitments`) and admits a ROS-style forgery.
//
// v2 instead presents the nested position as an ORDINARY FROST signer:
//
// D_nested = Σ_k D_k E_nested = Σ_k E_k
//
// The outer protocol computes ρ = H(index, m, B) over the FULL outer
// commitment list, exactly as for any other signer, and each inner holder
// signs with that same ρ:
//
// z_k = d_k + ρ·e_k + (λ_out·c·μ_k)·σ_k
//
// Summing over the inner quorum, with d = Σd_k, e = Σe_k and Σ μ_k·σ_k = σ_out
// (inner Lagrange interpolation):
//
// z_nested = d + ρ·e + λ_out·c·σ_out
//
// which is bit-for-bit what a single FROST signer holding σ_out with nonces
// (d, e) produces. The nested position is therefore INDISTINGUISHABLE from a
// flat signer whose nonce and key happen to be additively shared — so security
// reduces to FROST's own proof plus inner-group honesty, rather than requiring
// a novel composition argument. `nested_equals_flat_frost` in the tests below
// asserts that equivalence on real values.
//
// Because the inner binding factor is gone, adaptive commitment selection
// INSIDE the jury is prevented by an explicit commit–reveal round instead:
// every holder publishes H(k ‖ D_k ‖ E_k) before any commitment is revealed.

/// Round-0 hash commitment to an inner holder's nonce commitments.
pub fn inner_precommit<P: CurvePoint>(c: &InnerCommitments<P>) -> [u8; 32] {
 let mut h = Sha512::new();
 h.update(b"frostito-inner-precommit-v2");
 h.update(c.holder_index.to_le_bytes());
 h.update(c.session_id);
 h.update(c.hiding.compress());
 h.update(c.binding.compress());
 let full: [u8; 64] = h.finalize().into();
 let mut out = [0u8; 32];
 out.copy_from_slice(&full[..32]);
 out
}

/// Verify a revealed commitment against its round-0 precommitment.
///
/// Every holder MUST check every other holder's reveal before the aggregate is
/// formed. Without this, a holder revealing last can choose D_k to steer
/// D_nested to a value of its choosing.
pub fn verify_inner_precommit<P: CurvePoint>(
 precommit: &[u8; 32],
 revealed: &InnerCommitments<P>,
) -> bool {
 // constant-time-ish compare; these are public values, but keep the habit
 let computed = inner_precommit(revealed);
 let mut diff = 0u8;
 for (a, b) in computed.iter().zip(precommit.iter()) {
 diff |= a ^ b;
 }
 diff == 0
}

/// Aggregate inner nonce commitments into the pair the OUTER protocol consumes.
///
/// Returns `(D_nested, E_nested)`. Feed these to the outer `SigningCommitments`
/// as `hiding` and `binding` respectively — the nested position then looks
/// exactly like any other signer and receives a real outer binding factor.
///
/// # The commit–reveal round is enforced here
///
/// Through 0.4.x the requirement was a doc comment — "callers MUST have
/// verified every precommitment" — and nothing called
/// [`verify_inner_precommit`], including `inner_sign_v2`. "Not load-bearing"
/// and "unenforced" together mean nobody notices when a caller skips it, and
/// the callers this crate has do skip it.
///
/// So the precommitments are now an argument, and every revealed commitment
/// must have one that matches. `precommits` is a list of
/// `(holder_index, precommit)` as produced by [`inner_precommit`]; extra
/// entries for holders that did not reveal are fine — a holder can precommit
/// and then fail to appear — but a reveal with no matching precommit, or one
/// that does not match, is a rejection naming the holder.
///
/// On why the round exists at all: the prior audit's is right that it is
/// belt-and-braces rather than load-bearing, because the outer ρ covers the
/// full outer commitment list including the nested aggregate, so a holder
/// revealing last cannot hold an honest effective nonce fixed. The reason to
/// enforce it anyway is that the argument depends on the outer protocol
/// behaving, and this check does not.
///
/// # Errors
///
/// - [`Error::EmptyContributions`] if the list is empty.
/// - [`Error::DuplicateIndex`] if a holder appears twice.
/// - [`Error::SessionMismatch`] if any commitment belongs to another round.
/// - [`Error::PrecommitMismatch`] naming a holder whose reveal has no
///   matching round-0 precommitment.
pub fn aggregate_inner_commitment_pair<P: CurvePoint>(
 session_id: &[u8; 32],
 precommits: &[(u32, [u8; 32])],
 inner_commitments: &[InnerCommitments<P>],
) -> Result<(P, P), Error> {
 if inner_commitments.is_empty() {
 return Err(Error::EmptyContributions);
 }
 let mut seen: Vec<u32> = Vec::with_capacity(inner_commitments.len());
 let mut d = P::identity();
 let mut e = P::identity();
 for c in inner_commitments {
 if c.holder_index == 0 {
 return Err(Error::InvalidIndex);
 }
 if &c.session_id != session_id {
 return Err(Error::SessionMismatch);
 }
 if seen.contains(&c.holder_index) {
 return Err(Error::DuplicateIndex(c.holder_index));
 }
 seen.push(c.holder_index);

 // the reveal must be the one this holder committed to in round 0
 let pre = precommits
 .iter()
 .find(|(k, _)| *k == c.holder_index)
 .map(|(_, p)| p)
 .ok_or(Error::PrecommitMismatch(c.holder_index))?;
 if !verify_inner_precommit::<P>(pre, c) {
 return Err(Error::PrecommitMismatch(c.holder_index));
 }

 d = d.add(&c.hiding);
 e = e.add(&c.binding);
 }
 Ok((d, e))
}

/// Check that the outer package's commitment for the nested position is the
/// pair this inner round actually produced.
///
/// Every inner holder calls this — directly, or via [`inner_sign_v2`], which
/// calls it for them — before signing. Without it a coordinator can run the
/// holders through a round over a commitment set they never agreed to.
///
/// # Errors
///
/// [`Error::InvalidIndex`] if `nested_index` is not in the package;
/// [`Error::UnexpectedCommitment`] if the package's entry is not
/// `(Σ D_k, Σ E_k)`; the errors of [`aggregate_inner_commitment_pair`]
/// otherwise.
pub fn verify_nested_commitment<P: CurvePoint>(
 package: &crate::frost::SigningPackage<P>,
 nested_index: u32,
 session_id: &[u8; 32],
 precommits: &[(u32, [u8; 32])],
 inner_commitments: &[InnerCommitments<P>],
) -> Result<(), Error> {
 let entry = package
 .get_commitments(nested_index)
 .ok_or(Error::InvalidIndex)?;
 let (d, e) = aggregate_inner_commitment_pair::<P>(session_id, precommits, inner_commitments)?;
 if entry.hiding != d || entry.binding != e {
 return Err(Error::UnexpectedCommitment);
 }
 Ok(())
}

/// Everything an inner holder needs about the OUTER round that legitimately
/// comes from the coordinator.
///
/// Passed by reference to [`inner_sign_v2`]. Every field is public data; the
/// holder derives the outer binding factor, challenge and Lagrange coefficient
/// from it locally, so no coordinator ever gets to assert them.
///
/// # Public is not the same as locally anchored
///
/// The 0.4.0 doc comment said "every field is public data", which is true and
/// beside the point: *public* means an adversary learns nothing by seeing it,
/// not that a holder may take it from whoever sent the request. Two fields
/// here still have to be anchored against the holder's own state before the
/// request is trusted, and one has been removed from the struct outright:
///
/// - **`group_pubkey` — removed.** It used to live here, and a coordinator
///   that substituted `Y'` got a package that passed every self-consistency
///   check, including
///   [`from_coordinator_checked`](InnerSigningParamsV2::from_coordinator_checked),
///   because everything was recomputed *using the supplied `Y`*. The holder
///   then signed the approved message under an attacker-chosen challenge.
///   That is not a forgery — the result verifies under nothing — but it is
///   free choice of `c` over a fixed `m`, which is the degree of freedom the
///   ROS literature is about, and there is no reason to concede it. `Y` is now
///   a separate argument to [`inner_sign_v2`], which the holder must supply
///   from its own key package, so a request simply cannot carry one.
/// - **`nested_index`** must be the holder's own group's position in the outer
///   set, as fixed when the outer key was generated — not a position a
///   coordinator assigns per request.
/// - **`active_indices`** must be the inner quorum the holder's own group
///   agreed, not a set the coordinator picks. [`inner_sign_v2`] validates it
///   against `inner_commitments`, which bounds the damage but does not
///   make a coordinator-chosen quorum the holder's own choice.
///
/// `package`, `session_id` and `inner_commitments` are checked against local
/// state inside [`inner_sign_v2`]: the message against the holder's approved
/// bytes, the session against its nonces, and the commitment set against its
/// own round-1 commitment and the package's nested entry.
pub struct NestedSigningRequest<'a, P: CurvePoint> {
 /// The outer signing package (carries the message and the FULL commitment list).
 pub package: &'a crate::frost::SigningPackage<P>,
 /// The nested position's index in the OUTER signing set.
 ///
 /// Caller-anchored: see the type documentation.
 pub nested_index: u32,
 /// The inner round's id, as agreed before round 1.
 pub session_id: [u8; 32],
 /// The round-0 precommitments, as `(holder_index, precommit)`.
 ///
 /// Verified against `inner_commitments` by [`inner_sign_v2`] — the
 /// commit–reveal round is no longer a caller convention. These come from
 /// the inner group's own round 0, not from the coordinator.
 pub inner_precommits: &'a [(u32, [u8; 32])],
 /// The revealed inner commitment set from round 1.
 pub inner_commitments: &'a [InnerCommitments<P>],
 /// The inner quorum actually signing.
 ///
 /// Caller-anchored: see the type documentation. Validated against
 /// `inner_commitments` and `inner_threshold` by [`inner_sign_v2`].
 pub active_indices: &'a [u32],
 /// The inner group's own threshold `t_in`, from the holder's inner key
 /// material.
 ///
 /// Caller-anchored, and the reason it is here rather than derived: a
 /// [`SecretShare`] carries an index and a scalar and
 /// nothing else, so `inner_sign_v2` has no way to learn `t_in` from its
 /// arguments. Supply the value the inner DKG or reshare fixed; a holder
 /// that passes a coordinator's number has anchored nothing.
 pub inner_threshold: u32,
}

/// Outer context for v2 signing.
///
/// The fields are private and [`InnerSigningParamsV2::from_outer`] is the only
/// way to obtain them from public data: a coordinator cannot hand an inner
/// holder a challenge, because the type cannot be built out of scalars. Where
/// a coordinator distributes them anyway (a legacy wire format, say), they
/// must be checked with [`InnerSigningParamsV2::from_coordinator_checked`],
/// which recomputes and rejects a mismatch.
#[derive(Clone)]
pub struct InnerSigningParamsV2<S: CurveScalar> {
 /// outer binding factor for the nested position: ρ = H(Y, index, m, B)
 outer_binding: S,
 /// outer schnorr challenge: c = H(R_outer, Y, m)
 outer_challenge: S,
 /// outer lagrange coefficient for the nested position
 outer_lambda: S,
}

impl<S: CurveScalar> InnerSigningParamsV2<S> {
 /// Build from an outer context derived somewhere other than
 /// [`from_outer`](Self::from_outer).
 ///
 /// The three values must be the holder's own derivation from the outer
 /// signing package, never a coordinator's assertion — that is the whole
 /// point of this type. [`crate::zf::inner_params_from_zf`] is the
 /// supported producer, deriving them from a `frost-core` package.
 pub fn from_parts(outer_binding: S, outer_challenge: S, outer_lambda: S) -> Self {
 Self {
 outer_binding,
 outer_challenge,
 outer_lambda,
 }
 }

 /// The outer binding factor ρ for the nested position.
 #[inline]
 pub fn outer_binding(&self) -> &S {
 &self.outer_binding
 }

 /// The outer Schnorr challenge c.
 #[inline]
 pub fn outer_challenge(&self) -> &S {
 &self.outer_challenge
 }

 /// The nested position's outer Lagrange coefficient λ.
 #[inline]
 pub fn outer_lambda(&self) -> &S {
 &self.outer_lambda
 }

 /// Derive the nested position's outer context from public data alone.
 ///
 /// This is the constructor every inner holder uses — through
 /// [`inner_sign_v2`], which calls it internally. All three fields come out
 /// of the outer [`SigningPackage`](crate::frost::SigningPackage) and the
 /// group public key, both of which the holder already has.
 ///
 /// `nested_index` is the nested position's index in the OUTER signing set.
 ///
 /// # Errors
 ///
 /// [`Error::InvalidIndex`] if `nested_index` is not one of the outer
 /// package's signers.
 pub fn from_outer<P: CurvePoint<Scalar = S>>(
 package: &crate::frost::SigningPackage<P>,
 group_pubkey: &P,
 nested_index: u32,
 ) -> Result<Self, Error> {
 let indices = package.signer_indices();
 let pos = indices
 .iter()
 .position(|&i| i == nested_index)
 .ok_or(Error::InvalidIndex)?;
 let lagrange = compute_lagrange_coefficients::<S>(&indices)?;
 let group_commitment = package.group_commitment(group_pubkey);

 Ok(Self {
 outer_binding: package.binding_factor(nested_index, group_pubkey),
 outer_challenge: package.challenge(&group_commitment, group_pubkey),
 outer_lambda: lagrange[pos].clone(),
 })
 }

 /// Accept a coordinator-supplied outer context ONLY if it is the one the
 /// holder recomputes from the package itself.
 ///
 /// # Deprecated: this validates self-consistency, not provenance
 ///
 /// It does what it says, and it is correctly documented as the
 /// legacy-wire-format escape hatch — but it *reads* like the blessed way
 /// to accept coordinator input, and a caller who stops reading at the name
 /// is protected against nothing. Everything here is recomputed against the
 /// **supplied** `package` and `group_pubkey`, so a coordinator that
 /// substitutes either gets a self-consistent triple that passes. narsild
 /// made exactly this mistake: it called this function correctly and
 /// still signed under an attacker-supplied `Y`.
 ///
 /// Prefer [`from_outer`](Self::from_outer), and take `group_pubkey` from
 /// your own key package rather than from the request. Where a legacy wire
 /// format distributes the three scalars anyway, this still recomputes and
 /// still rejects a mismatch — just do not read it as an authenticity
 /// check.
 ///
 /// # Errors
 ///
 /// [`Error::ChallengeMismatch`] if any of the three scalars differs
 /// from the locally derived value.
 #[deprecated(
 since = "0.5.0",
 note = "validates self-consistency, not the provenance of `package` or `group_pubkey`: \
 a substituted group key passes. Prefer `from_outer`, with `group_pubkey` taken \
 from the signer's own key package."
 )]
 pub fn from_coordinator_checked<P: CurvePoint<Scalar = S>>(
 supplied_binding: &S,
 supplied_challenge: &S,
 supplied_lambda: &S,
 package: &crate::frost::SigningPackage<P>,
 group_pubkey: &P,
 nested_index: u32,
 ) -> Result<Self, Error> {
 let local = Self::from_outer::<P>(package, group_pubkey, nested_index)?;
 if &local.outer_binding != supplied_binding
 || &local.outer_challenge != supplied_challenge
 || &local.outer_lambda != supplied_lambda
 {
 return Err(Error::ChallengeMismatch);
 }
 Ok(local)
 }
}

/// Inner holder's partial signature under v2.
///
/// z_k = d_k + ρ·e_k + (λ_out·c·μ_k)·σ_k
///
/// The holder supplies the message it approved and the full public commitment
/// set; the outer binding factor and challenge are recomputed here, from the
/// package, and never accepted from a coordinator. Concretely, this function
/// refuses to produce a share unless:
///
/// 1. `approved_message` is byte-for-byte the package's message — so a
///    coordinator cannot obtain a signature over a payload the inner group
///    never saw, and an application policy check on the approved bytes is
///    possible before the call;
/// 2. the round-1 commitment set contains this holder's own commitment, for
///    this `session_id`, matching the nonces being consumed;
/// 3. the package's entry for the nested position is exactly
///    `(Σ D_k, Σ E_k)` over that set.
///
/// Note `nonces` is taken BY VALUE: the nonce pair is consumed and zeroized on
/// drop, so a holder cannot produce two shares from one commitment round
/// without deliberately cloning.
///
/// # This function is not a replay guard
///
/// `session_id` is a mixing guard: it stops two concurrent rounds being
/// spliced together, and it enters neither the binding factor nor the
/// challenge. Within one process, consuming the nonces by value plus the
/// commitment check above is sound. Across a process boundary it is nothing —
/// a snapshot-restore replays the nonces under a fresh challenge and two
/// responses under one nonce give up the share by elementary algebra.
///
/// Any caller whose state can survive or roll back a restart — which is every
/// daemon — MUST record `(session_id, holder_index)` as spent, durably, before
/// the share leaves the process. [`inner_sign_v2_spending`] does that ordering
/// for you against a [`SpentSessions`] store; the full contract is on that
/// trait.
///
/// # `local_group_pubkey`
///
/// The outer group public key is a parameter of this function and NOT a field
/// of [`NestedSigningRequest`], because it must come from the holder's own key
/// material — the key package written when the outer key was generated — and
/// never from the coordinator's request. It enters both the binding factor
/// and the challenge `c = H(R ‖ Y ‖ m)`. A coordinator that gets to
/// choose it gets free choice of `c` over a fixed `m` and a package that
/// passes every self-consistency check, which is the trap narsild fell into.
///
/// Nothing here can verify that the value you pass is the real group key —
/// only that you, not the coordinator, chose it. Read it from local storage.
///
/// # Errors
///
/// [`Error::MessageMismatch`], [`Error::UnexpectedCommitment`],
/// [`Error::SessionMismatch`], [`Error::InvalidIndex`],
/// [`Error::DuplicateIndex`].
pub fn inner_sign_v2<P: CurvePoint>(
 nonces: InnerNonces<P::Scalar>,
 share: &SecretShare<P::Scalar>,
 local_group_pubkey: &P,
 approved_message: &[u8],
 request: &NestedSigningRequest<'_, P>,
) -> Result<InnerSignatureShare<P::Scalar>, Error> {
 // the holder signs a message it holds, not one a coordinator asserts.
 if request.package.message() != approved_message {
 return Err(Error::MessageMismatch);
 }

 // the quorum the μ_k are computed over must be a real quorum of the
 // commitment set the nested aggregate was formed from. `active_indices` is
 // coordinator-supplied, and through 0.4.x the only check was that this
 // holder appeared somewhere in it: a set with duplicates, with members that
 // published no round-1 commitment, or smaller than t_in produced Lagrange
 // coefficients over a quorum that does not match the ΣD the package
 // committed to. The share then simply failed to aggregate fixed
 // exactly this on the aggregation side and left the signing side open.
 // These are errors, never panics: the values come off the wire.
 if (request.active_indices.len() as u64) < request.inner_threshold as u64 {
 return Err(Error::InsufficientContributions {
 got: request.active_indices.len(),
 need: request.inner_threshold as usize,
 });
 }
 for (i, &k) in request.active_indices.iter().enumerate() {
 if k == 0 {
 return Err(Error::InvalidIndex);
 }
 if request.active_indices[..i].contains(&k) {
 return Err(Error::DuplicateIndex(k));
 }
 if !request
 .inner_commitments
 .iter()
 .any(|c| c.holder_index == k)
 {
 return Err(Error::UnknownQuorumMember(k));
 }
 }


 // this round is the round the nonces were committed to ...
 if nonces.session_id != request.session_id {
 return Err(Error::SessionMismatch);
 }

 // ... and the published set really contains our own round-1 commitment.
 let mine = request
 .inner_commitments
 .iter()
 .find(|c| c.holder_index == nonces.holder_index)
 .ok_or(Error::UnexpectedCommitment)?;
 if mine.session_id != request.session_id
 || mine.hiding != P::generator().mul_scalar(&nonces.hiding)
 || mine.binding != P::generator().mul_scalar(&nonces.binding)
 {
 return Err(Error::UnexpectedCommitment);
 }

 // the nested position's outer commitment is this round's aggregate.
 verify_nested_commitment::<P>(
 request.package,
 request.nested_index,
 &request.session_id,
 request.inner_precommits,
 request.inner_commitments,
 )?;

 // Outer context, recomputed locally from the package.
 let params = InnerSigningParamsV2::from_outer::<P>(
 request.package,
 local_group_pubkey,
 request.nested_index,
 )?;

 let lagrange = compute_lagrange_coefficients::<P::Scalar>(request.active_indices)?;
 let my_pos = request
 .active_indices
 .iter()
 .position(|&i| i == share.index)
 .ok_or(Error::InvalidIndex)?;
 let mu_k = &lagrange[my_pos];

 let rho_e = params.outer_binding.mul(&nonces.binding);
 let weight = params.outer_lambda.mul(&params.outer_challenge).mul(mu_k);
 let response = nonces.hiding.add(&rho_e).add(&weight.mul(share.scalar()));

 Ok(InnerSignatureShare {
 holder_index: nonces.holder_index,
 response,
 })
}


// ============================================================================
// The session-id contract, and spent-session tracking
// ============================================================================

/// A record of which `(session_id, holder_index)` pairs have already produced
/// a signature share.
///
/// # What `session_id` is, precisely
///
/// This is worth stating exactly, because the 0.4.0 CHANGELOG's entry can
/// be read as more than it is.
///
/// `session_id` is a **mixing guard, not a replay guard.** It threads through
/// [`InnerNonces`], [`InnerCommitments`] and [`inner_precommit`], and it is
/// checked for equality in [`inner_sign_v2`],
/// [`aggregate_inner_commitment_pair`] and [`verify_nested_commitment`]. What
/// it buys is that two concurrent inner rounds cannot be spliced into each
/// other: a commitment from round A cannot be presented as part of round B,
/// and nonces from A cannot sign in B.
///
/// It enters **neither** hash that matters. `compute_binding_factor` and
/// `compute_challenge` never see it, so two sessions over the same message and
/// the same outer commitment list produce the same ρ and the same `c`. It is
/// not in the signature, it is not in the transcript a verifier checks, and
/// nothing about it is enforced across a process boundary.
///
/// # What actually prevents nonce reuse, and where it stops
///
/// Two things, both in-process:
///
/// 1. [`inner_sign_v2`] takes `nonces` **by value**, so the pair is consumed
///    and zeroized on drop; producing two shares from one commitment round
///    requires deliberately cloning.
/// 2. It checks that the published commitment matches the nonces being
///    consumed, so a second share would have to be for a round that published
///    the same commitment.
///
/// Within one process that is sound. Across a restart it is nothing: a VM
/// snapshot-restore, a container restarted from an image, or any rollback of
/// the node's state brings the nonces back and lets them sign a second time
/// under a fresh challenge. Two responses under one nonce give
/// `σ = (z₁ − z₂)/(w₁ − w₂)` — the share falls out by elementary algebra. For
/// a daemon holding long-lived escrow authority this is the failure mode most
/// likely to actually happen, because snapshots are operational routine rather
/// than an attack.
///
/// The type system cannot see a process boundary. This trait is where a caller
/// puts the thing that can.
///
/// # Implementing this
///
/// The implementation must be **durable and write-ahead**: the record has to
/// be on stable storage, `fsync`'d, *before* the share leaves the process.
/// [`inner_sign_v2_spending`] calls [`spend`](Self::spend) before it computes
/// anything, so an implementation that writes synchronously gets the ordering
/// for free. An implementation that buffers, or that records after the fact,
/// provides nothing: the crash window is exactly the window that matters.
///
/// [`MemorySpentSessions`] is for tests. It is not durable, and its
/// documentation says so; a deployment that uses it has not implemented this.
pub trait SpentSessions {
 /// Mark `(session_id, holder_index)` spent, or refuse if it already is.
 ///
 /// Must be atomic with respect to crashes: either the pair is durably
 /// recorded when this returns `Ok`, or it returns `Err`.
 ///
 /// # Errors
 ///
 /// [`Error::SessionSpent`] if the pair has already produced a share.
 /// An implementation backed by storage may return any other
 /// [`Error`] for a write failure — a failure to record MUST be
 /// reported, never swallowed, since the caller will otherwise sign.
 fn spend(&mut self, session_id: &[u8; 32], holder_index: u32) -> Result<(), Error>;

 /// Whether the pair has already been spent. Advisory: a caller must still
 /// go through [`spend`](Self::spend), which is the atomic operation.
 fn is_spent(&self, session_id: &[u8; 32], holder_index: u32) -> bool;
}

/// An in-memory [`SpentSessions`], for tests.
///
/// **Not durable.** It is exactly the thing to worry about — state that does
/// not survive the process — and it exists so the tests and examples can
/// exercise the spending path. Do not deploy it.
#[derive(Clone, Debug, Default)]
pub struct MemorySpentSessions {
 spent: alloc::collections::BTreeSet<([u8; 32], u32)>,
}

impl MemorySpentSessions {
 pub fn new() -> Self {
 Self::default()
 }

 /// How many pairs have been recorded.
 pub fn len(&self) -> usize {
 self.spent.len()
 }

 pub fn is_empty(&self) -> bool {
 self.spent.is_empty()
 }
}

impl SpentSessions for MemorySpentSessions {
 fn spend(&mut self, session_id: &[u8; 32], holder_index: u32) -> Result<(), Error> {
 if !self.spent.insert((*session_id, holder_index)) {
 return Err(Error::SessionSpent);
 }
 Ok(())
 }

 fn is_spent(&self, session_id: &[u8; 32], holder_index: u32) -> bool {
 self.spent.contains(&(*session_id, holder_index))
 }
}

/// [`inner_sign_v2`], with `(session_id, holder_index)` recorded as spent
/// before the share is computed.
///
/// This is the form a daemon should use. The write happens first, so a crash
/// between the record and the share leaves the session burnt rather than
/// replayable — the safe direction. A caller that records afterwards has
/// implemented nothing: the crash window is the whole point.
///
/// The `session_id` a holder spends is the one in its own nonces, not the one
/// in the request, so a coordinator cannot get a share recorded against a
/// session the holder is not in.
///
/// # Errors
///
/// [`Error::SessionSpent`] if this holder has already signed this session,
/// whatever the store says happened before the process started; anything
/// [`SpentSessions::spend`] returns for a write failure; and every error of
/// [`inner_sign_v2`].
pub fn inner_sign_v2_spending<P: CurvePoint, S: SpentSessions + ?Sized>(
 store: &mut S,
 nonces: InnerNonces<P::Scalar>,
 share: &SecretShare<P::Scalar>,
 local_group_pubkey: &P,
 approved_message: &[u8],
 request: &NestedSigningRequest<'_, P>,
) -> Result<InnerSignatureShare<P::Scalar>, Error> {
 store.spend(&nonces.session_id, nonces.holder_index)?;
 inner_sign_v2::<P>(
 nonces,
 share,
 local_group_pubkey,
 approved_message,
 request,
 )
}

/// [`inner_sign_v2`] with the approved message given as an epoch-bound
/// [`SigningContext`](crate::SigningContext) rather than raw bytes.
///
/// The package must have been built over `ctx.encode()`; otherwise this
/// returns [`Error::MessageMismatch`]. This is the form to prefer: it
/// makes the epoch and manifest the holder approved part of the bytes that get
/// signed, instead of leaving them to a convention.
pub fn inner_sign_v2_with_context<P: CurvePoint>(
 nonces: InnerNonces<P::Scalar>,
 share: &SecretShare<P::Scalar>,
 local_group_pubkey: &P,
 ctx: &crate::SigningContext<'_>,
 request: &NestedSigningRequest<'_, P>,
) -> Result<InnerSignatureShare<P::Scalar>, Error> {
 inner_sign_v2::<P>(nonces, share, local_group_pubkey, &ctx.encode(), request)
}

/// Verify one inner holder's share before it is aggregated:
///
/// z_k·G == (D_k + ρ·E_k) + (λ_out·c·μ_k)·P_k
///
/// where `P_k = σ_k·G` is the holder's public share (derivable from the DKG
/// coefficient commitments). Without this an invalid share is silently folded
/// into the sum, producing a signature that fails to verify with no indication
/// of which holder was at fault.
pub fn verify_inner_share<P: CurvePoint>(
 sig: &InnerSignatureShare<P::Scalar>,
 commitment: &InnerCommitments<P>,
 public_share: &P,
 params: &InnerSigningParamsV2<P::Scalar>,
 mu_k: &P::Scalar,
) -> bool {
 let lhs = P::generator().mul_scalar(&sig.response);
 let weight = params
 .outer_lambda
 .mul(&params.outer_challenge)
 .mul(mu_k);
 let rhs = commitment
 .hiding
 .add(&commitment.binding.mul_scalar(&params.outer_binding))
 .add(&public_share.mul_scalar(&weight));
 lhs == rhs
}

/// Verify every inner share, then aggregate.
///
/// `Err(indices)` names the holders whose shares failed — the caller can evict
/// them and retry with a different quorum instead of broadcasting a signature
/// that will simply be rejected. A holder in `active_indices` that produced no
/// share, and a holder that produced two, are both named the same way:
/// the multiset of `holder_index` must equal `active_indices` exactly, or the
/// aggregate is not the nested position's response.
pub fn aggregate_inner_shares_verified<P: CurvePoint>(
 sigs: &[InnerSignatureShare<P::Scalar>],
 commitments: &[InnerCommitments<P>],
 public_shares: &[(u32, P)],
 params: &InnerSigningParamsV2<P::Scalar>,
 active_indices: &[u32],
) -> Result<P::Scalar, Vec<u32>> {
 let lagrange = match compute_lagrange_coefficients::<P::Scalar>(active_indices) {
 Ok(l) => l,
 Err(_) => return Err(active_indices.to_vec()),
 };

 let mut bad = Vec::new();

 // quorum coverage: every active index exactly once, nothing else.
 let mut seen: Vec<u32> = Vec::with_capacity(sigs.len());
 for sig in sigs {
 if (!active_indices.contains(&sig.holder_index) || seen.contains(&sig.holder_index))
 && !bad.contains(&sig.holder_index) {
 bad.push(sig.holder_index);
 }
 seen.push(sig.holder_index);
 }
 for &k in active_indices {
 if !seen.contains(&k) && !bad.contains(&k) {
 bad.push(k);
 }
 }

 let mut z = P::Scalar::zero();
 for sig in sigs {
 let k = sig.holder_index;
 let pos = active_indices.iter().position(|&i| i == k);
 let commitment = commitments.iter().find(|c| c.holder_index == k);
 let public = public_shares.iter().find(|(i, _)| *i == k).map(|(_, p)| p);
 match (pos, commitment, public) {
 (Some(pos), Some(commitment), Some(public)) => {
 if verify_inner_share::<P>(sig, commitment, public, params, &lagrange[pos]) {
 z = z.add(&sig.response);
 } else if !bad.contains(&k) {
 bad.push(k);
 }
 }
 // missing commitment or public share ⇒ cannot verify ⇒ reject
 _ => {
 if !bad.contains(&k) {
 bad.push(k);
 }
 }
 }
 }

 if bad.is_empty() {
 Ok(z)
 } else {
 bad.sort_unstable();
 Err(bad)
 }
}
