//! Audit regression tests — `frostito::nested` v2 (the 2026-09 review,
//! findings ..).
//!
//! These began as adversarial PoCs on branch `audit-2026-09`, each `#[ignore]`d
//! with the finding it demonstrated. The fixes in this branch turn them around:
//! every one now asserts that the attack **fails**, so they are regression
//! tests and none of them is ignored. The attack each one performs is
//! unchanged — only the expected outcome is.

#![cfg(all(feature = "zf-ristretto255", feature = "std"))]

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use frostito::curve::{CurvePoint, CurveScalar};
use frost_core::{
 keys::{KeyPackage, PublicKeyPackage, SigningShare, VerifyingShare},
 round1::{Nonce, NonceCommitment, SigningCommitments, SigningNonces},
 round2, Identifier, SigningPackage, VerifyingKey,
};
use frost_ristretto255::Ristretto255Sha512 as C;
use std::collections::BTreeMap;
use frostito::nested::{
 aggregate_inner_commitment_pair, aggregate_inner_shares_verified, inner_commit,
 inner_precommit, inner_sign_v2, InnerCommitments,
 NestedSigningRequest,
};
use frostito::{compute_lagrange_coefficients, Error, SecretShare};
use rand::rngs::OsRng;

type Point = RistrettoPoint;

const SESSION: [u8; 32] = [0x5Au8; 32];

// ── ZF adapters ─────────────────────────────────────────────────────────────
// The outer round runs on `frost-core`; these keep the tests reading the way
// they did when it ran on this crate's own FROST.

fn id(i: u32) -> Identifier<C> {
 (i as u16).try_into().unwrap()
}

fn vk(p: Point) -> VerifyingKey<C> {
 VerifyingKey::new(p)
}

/// Round 1 for an outer signer: sample nonces, return them with their
/// commitments, as `frost::commit` used to.
fn zf_commit(rng: &mut OsRng) -> (SigningNonces<C>, SigningCommitments<C>) {
 let h = <Scalar as CurveScalar>::random(rng);
 let b = <Scalar as CurveScalar>::random(rng);
 let n = SigningNonces::from_nonces(Nonce::<C>::from_scalar(h), Nonce::<C>::from_scalar(b));
 let c = *n.commitments();
 (n, c)
}

/// A commitment pair built from points the caller already holds — how the
/// nested position enters the outer round.
fn zf_commitments(hiding: Point, binding: Point) -> SigningCommitments<C> {
 SigningCommitments::new(NonceCommitment::new(hiding), NonceCommitment::new(binding))
}

/// An outer signing package over `msg` for the given `(index, commitments)`.
fn zf_package(msg: &[u8], entries: Vec<(u32, SigningCommitments<C>)>) -> SigningPackage<C> {
 SigningPackage::new(entries.into_iter().map(|(i, c)| (id(i), c)).collect(), msg)
}

/// A key package for an ordinary outer signer.
fn zf_key_package(index: u32, share: &SecretShare<Scalar>, group: Point, t: u16) -> KeyPackage<C> {
 KeyPackage::new(
 id(index),
 SigningShare::new(*share.scalar()),
 VerifyingShare::new(<Point as CurvePoint>::generator().mul_scalar(share.scalar())),
 vk(group),
 t,
 )
}



/// Shamir-split `secret` into `n` shares with threshold `t`.
fn split(secret: &Scalar, n: u32, t: u32, rng: &mut OsRng) -> Vec<SecretShare<Scalar>> {
 let mut coeffs = vec![*secret];
 for _ in 1..t {
 coeffs.push(<Scalar as CurveScalar>::random(rng));
 }
 (1..=n)
 .map(|i| {
 let x = <Scalar as CurveScalar>::from_u32(i);
 let mut y = <Scalar as CurveScalar>::zero();
 let mut xp = <Scalar as CurveScalar>::one();
 for c in &coeffs {
 y = y.add(&c.mul(&xp));
 xp = xp.mul(&x);
 }
 SecretShare::new(i, y).unwrap()
 })
 .collect()
}

/// Build the whole outer 2-of-2 world used by the tests below.
///
/// Position 1 is an ordinary signer. Position 2 is the nested position, whose
/// outer share sigma_2 is split 3-of-5 among inner holders {1,2,3}.
struct World {
 group_pubkey: Point,
 share_1: SecretShare<Scalar>,
 inner_shares: Vec<SecretShare<Scalar>>,
 quorum: Vec<u32>,
 /// g^sigma_2 — the nested position's outer verifying share.
 nested_public: Point,
}

fn world(rng: &mut OsRng) -> World {
 let secret = <Scalar as CurveScalar>::random(rng);
 let a1 = <Scalar as CurveScalar>::random(rng);
 let eval = |x: u32| {
 let xs = <Scalar as CurveScalar>::from_u32(x);
 secret.add(&a1.mul(&xs))
 };
 let group_pubkey = <Point as CurvePoint>::generator().mul_scalar(&secret);
 let sigma_2 = eval(2);
 let nested_public = <Point as CurvePoint>::generator().mul_scalar(&sigma_2);
 let pieces = split(&sigma_2, 5, 3, rng);
 World {
 group_pubkey,
 share_1: SecretShare::new(1, eval(1)).unwrap(),
 inner_shares: pieces[..3].to_vec(),
 quorum: vec![1, 2, 3],
 nested_public,
 }
}

/// Round 0: every holder's hash commitment to its round-1 reveal.
fn precommits(cs: &[InnerCommitments<Point>]) -> Vec<(u32, [u8; 32])> {
 cs.iter()
 .map(|c| (c.holder_index, inner_precommit::<Point>(c)))
 .collect()
}

fn public_shares(shares: &[SecretShare<Scalar>]) -> Vec<(u32, Point)> {
 shares
 .iter()
 .map(|s| {
 (
 s.index,
 <Point as CurvePoint>::generator().mul_scalar(s.scalar()),
 )
 })
 .collect()
}

/// (High, FIXED) — a malicious coordinator can no longer obtain a
/// signature on a message the inner group never authorised.
///
/// `inner_sign_v2` now takes the message the holder approved and the full
/// public commitment set, recomputes the outer binding factor and challenge
/// itself, and refuses to produce a share when the package carries a different
/// message. The coordinator still derives its own context honestly — that was
/// never the weak point — but it cannot get the holders to answer for it.
#[test]
fn coordinator_cannot_swap_the_message_under_the_inner_group() {
 let mut rng = OsRng;
 let w = world(&mut rng);

 const APPROVED: &[u8] = b"release 10 ZEC to alice";
 const UNAPPROVED: &[u8] = b"release 10000 ZEC to mallory";

 // Inner round: the holders commit, for an agreed session id.
 let mut nonces = Vec::new();
 let mut commitments = Vec::new();
 for &k in &w.quorum {
 let (n, c) = inner_commit::<Point, _>(k, SESSION, &mut rng);
 nonces.push(n);
 commitments.push(c);
 }
 let (d_nested, e_nested) =
 aggregate_inner_commitment_pair::<Point>(&SESSION, &precommits(&commitments), &commitments).unwrap();

 // The coordinator is the other outer signer. It builds an outer package
 // over UNAPPROVED, using the jury's real commitment pair.
 let (nonces_1, commits_1) = zf_commit(&mut rng);
 let commits_2 = zf_commitments(d_nested, e_nested);
 let evil_package =
 zf_package(UNAPPROVED, vec![(1, commits_1), (2, commits_2)]);

 let pre = precommits(&commitments);
 let request = NestedSigningRequest {
 package: &evil_package,
 nested_index: 2,
 session_id: SESSION,
 inner_precommits: &pre,
 inner_commitments: &commitments,
 active_indices: &w.quorum,
 inner_threshold: 3,
 };

 // The jury approved APPROVED. Every holder refuses, at the API.
 for (n, s) in nonces.into_iter().zip(w.inner_shares.iter()) {
 assert_eq!(
 inner_sign_v2::<C>(n, s, &vk(w.group_pubkey), APPROVED, &request).unwrap_err(),
 Error::MessageMismatch,
 "a holder must not sign a package over a message it did not approve"
 );
 }

 // And nothing the coordinator can do with its own share alone produces a
 // signature: position 2 never responded.
 let kp1 = zf_key_package(1, &w.share_1, w.group_pubkey, 2);
 let _ = round2::sign(&evil_package, &nonces_1, &kp1).unwrap();
}

/// The same holders, signing the message they actually approved, still
/// produce a signature that verifies. The fix is a check, not a wall.
#[test]
fn the_approved_message_still_signs() {
 let mut rng = OsRng;
 let w = world(&mut rng);
 const APPROVED: &[u8] = b"release 10 ZEC to alice";

 let mut nonces = Vec::new();
 let mut commitments = Vec::new();
 for &k in &w.quorum {
 let (n, c) = inner_commit::<Point, _>(k, SESSION, &mut rng);
 nonces.push(n);
 commitments.push(c);
 }
 let (d_nested, e_nested) =
 aggregate_inner_commitment_pair::<Point>(&SESSION, &precommits(&commitments), &commitments).unwrap();

 let (nonces_1, commits_1) = zf_commit(&mut rng);
 let commits_2 = zf_commitments(d_nested, e_nested);
 let package =
 zf_package(APPROVED, vec![(1, commits_1), (2, commits_2)]);
 let pre = precommits(&commitments);
 let request = NestedSigningRequest {
 package: &package,
 nested_index: 2,
 session_id: SESSION,
 inner_precommits: &pre,
 inner_commitments: &commitments,
 active_indices: &w.quorum,
 inner_threshold: 3,
 };

 let mut sigs = Vec::new();
 for (n, s) in nonces.into_iter().zip(w.inner_shares.iter()) {
 sigs.push(inner_sign_v2::<C>(n, s, &vk(w.group_pubkey), APPROVED, &request).unwrap());
 }

 let params =
 frostito::zf::inner_params_from_zf::<C>(&package, &vk(w.group_pubkey), 2).unwrap();
 let z_nested = aggregate_inner_shares_verified::<Point>(
 &sigs,
 &commitments,
 &public_shares(&w.inner_shares),
 &params,
 &w.quorum,
 )
 .expect("every share verifies");

 let kp1 = zf_key_package(1, &w.share_1, w.group_pubkey, 2);
 let sig_1 = round2::sign(&package, &nonces_1, &kp1).unwrap();
 // `SignatureShare` has no public constructor, so the nested position's
 // scalar enters through the wire format — which is how it would arrive
 // from the inner group in a deployment anyway.
 let sig_2 = frost_core::round2::SignatureShare::<C>::deserialize(
 &<Scalar as CurveScalar>::to_bytes(&z_nested),
 )
 .unwrap();

 let mut shares = BTreeMap::new();
 shares.insert(id(1), sig_1);
 shares.insert(id(2), sig_2);

 let mut verifying = BTreeMap::new();
 verifying.insert(id(1), VerifyingShare::new(<Point as CurvePoint>::generator().mul_scalar(w.share_1.scalar())));
 verifying.insert(id(2), VerifyingShare::new(w.nested_public));
 let pubkeys = PublicKeyPackage::<C>::new(verifying, vk(w.group_pubkey), Some(2));

 let signature = frost_core::aggregate(&package, &shares, &pubkeys).unwrap();
 assert!(pubkeys.verifying_key().verify(APPROVED, &signature).is_ok());
}

/// (Medium, FIXED) — the nested position's commitment pair in the outer
/// package is now tied to the inner commitment round.
///
/// `inner_sign_v2` recomputes `(Sum D_k, Sum E_k)` over the round-1 set for the
/// session the nonces were committed to, and compares it to the package's
/// entry for the nested position. A substituted entry is named, not silently
/// signed over.
#[test]
fn substituted_nested_commitment_is_rejected_by_the_holder() {
 let mut rng = OsRng;
 let w = world(&mut rng);
 let msg = b"settlement";

 let mut nonces = Vec::new();
 let mut commitments = Vec::new();
 for &k in &w.quorum {
 let (n, c) = inner_commit::<Point, _>(k, SESSION, &mut rng);
 nonces.push(n);
 commitments.push(c);
 }
 let (d_nested, e_nested) =
 aggregate_inner_commitment_pair::<Point>(&SESSION, &precommits(&commitments), &commitments).unwrap();

 // The coordinator publishes a DIFFERENT pair for position 2.
 let (_, foreign) = zf_commit(&mut rng);
 assert_ne!(foreign.hiding().value(), d_nested);
 assert_ne!(foreign.binding().value(), e_nested);

 let (_, commits_1) = zf_commit(&mut rng);
 let package =
 zf_package(msg, vec![(1, commits_1), (2, foreign)]);

 let pre = precommits(&commitments);
 let request = NestedSigningRequest {
 package: &package,
 nested_index: 2,
 session_id: SESSION,
 inner_precommits: &pre,
 inner_commitments: &commitments,
 active_indices: &w.quorum,
 inner_threshold: 3,
 };

 for (n, s) in nonces.into_iter().zip(w.inner_shares.iter()) {
 assert_eq!(
 inner_sign_v2::<C>(n, s, &vk(w.group_pubkey), msg, &request).unwrap_err(),
 Error::UnexpectedCommitment,
 "the holder must notice that the outer package is not over its own round"
 );
 }
}

/// second half — nonces from one inner round cannot be replayed into
/// another, even when the coordinator's package is otherwise well formed.
#[test]
fn nonces_from_another_session_are_rejected() {
 let mut rng = OsRng;
 let w = world(&mut rng);
 let msg = b"settlement";

 // Round A: the nonces the holders actually hold.
 let mut nonces_a = Vec::new();
 let mut commits_a = Vec::new();
 for &k in &w.quorum {
 let (n, c) = inner_commit::<Point, _>(k, SESSION, &mut rng);
 nonces_a.push(n);
 commits_a.push(c);
 }

 // Round B: a different session id, same holders.
 const OTHER: [u8; 32] = [0x11u8; 32];
 let mut commits_b = Vec::new();
 for &k in &w.quorum {
 let (_, c) = inner_commit::<Point, _>(k, OTHER, &mut rng);
 commits_b.push(c);
 }
 let (d_b, e_b) = aggregate_inner_commitment_pair::<Point>(&OTHER, &precommits(&commits_b), &commits_b).unwrap();

 let (_, commits_1) = zf_commit(&mut rng);
 let package = zf_package(msg, vec![(1, commits_1), (2, zf_commitments(d_b, e_b))]);

 let pre = precommits(&commits_b);
 let request = NestedSigningRequest {
 package: &package,
 nested_index: 2,
 session_id: OTHER,
 inner_precommits: &pre,
 inner_commitments: &commits_b,
 active_indices: &w.quorum,
 inner_threshold: 3,
 };

 // Holder 1 still holds round A's nonces; it must not answer round B.
 let n = nonces_a.remove(0);
 assert_eq!(
 inner_sign_v2::<C>(n, &w.inner_shares[0], &vk(w.group_pubkey), msg, &request).unwrap_err(),
 Error::SessionMismatch
 );

 // Mixing the two commitment sets is rejected at the aggregate as well.
 let mut mixed = commits_b.clone();
 mixed[0] = commits_a[0].clone();
 assert_eq!(
 aggregate_inner_commitment_pair::<Point>(&OTHER, &precommits(&mixed), &mixed).unwrap_err(),
 Error::SessionMismatch
 );
}

/// (Low, FIXED) — `aggregate_inner_shares_verified` requires the quorum to
/// be covered exactly.
///
/// The multiset of `holder_index` must equal `active_indices`: a short quorum
/// names its missing holders, and a duplicated share names the duplicate,
/// rather than aggregating to a wrong scalar and reporting success.
#[test]
fn incomplete_quorum_is_rejected() {
 let mut rng = OsRng;
 let w = world(&mut rng);
 let msg = b"m";

 let mut nonces = Vec::new();
 let mut commitments = Vec::new();
 for &k in &w.quorum {
 let (n, c) = inner_commit::<Point, _>(k, SESSION, &mut rng);
 nonces.push(n);
 commitments.push(c);
 }
 let (d_nested, e_nested) =
 aggregate_inner_commitment_pair::<Point>(&SESSION, &precommits(&commitments), &commitments).unwrap();

 let (_, commits_1) = zf_commit(&mut rng);
 let package = zf_package(msg, vec![(1, commits_1), (2, zf_commitments(d_nested, e_nested))]);
 let pre = precommits(&commitments);
 let request = NestedSigningRequest {
 package: &package,
 nested_index: 2,
 session_id: SESSION,
 inner_precommits: &pre,
 inner_commitments: &commitments,
 active_indices: &w.quorum,
 inner_threshold: 3,
 };
 let params =
 frostito::zf::inner_params_from_zf::<C>(&package, &vk(w.group_pubkey), 2).unwrap();

 let mut sigs = Vec::new();
 for (n, s) in nonces.into_iter().zip(w.inner_shares.iter()) {
 sigs.push(inner_sign_v2::<C>(n, s, &vk(w.group_pubkey), msg, &request).unwrap());
 }
 let pubs = public_shares(&w.inner_shares);

 // Drop holder 3 entirely. active_indices still says the quorum is {1,2,3}.
 assert_eq!(
 aggregate_inner_shares_verified::<Point>(
 &sigs[..2],
 &commitments,
 &pubs,
 &params,
 &w.quorum,
 )
 .unwrap_err(),
 vec![3],
 "a missing holder must be named, not silently tolerated"
 );

 // Duplicate holder 1 instead.
 let dup = vec![
 frostito::nested::InnerSignatureShare {
 holder_index: sigs[0].holder_index,
 response: sigs[0].response,
 },
 frostito::nested::InnerSignatureShare {
 holder_index: sigs[0].holder_index,
 response: sigs[0].response,
 },
 frostito::nested::InnerSignatureShare {
 holder_index: sigs[1].holder_index,
 response: sigs[1].response,
 },
 ];
 assert_eq!(
 aggregate_inner_shares_verified::<Point>(&dup, &commitments, &pubs, &params, &w.quorum)
 .unwrap_err(),
 vec![1, 3],
 "a duplicated share and the still-missing holder are both named"
 );
}

/// (Info) — the v2 equivalence claim holds on honest inputs.
///
/// A nested position's response is bit-for-bit what a flat FROST signer
/// holding sigma_2 with nonces (Sum d_k, Sum e_k) produces. Note what this
/// establishes: honest-transcript equality, not a reduction (see the report's
/// §1.2 and the correction to the v1 writeup).
#[test]
fn v2_response_equals_the_flat_frost_response() {
 let mut rng = OsRng;
 let secret = <Scalar as CurveScalar>::random(&mut rng);
 let a1 = <Scalar as CurveScalar>::random(&mut rng);
 let eval = |x: u32| {
 let xs = <Scalar as CurveScalar>::from_u32(x);
 secret.add(&a1.mul(&xs))
 };
 let group_pubkey = <Point as CurvePoint>::generator().mul_scalar(&secret);
 let sigma_2 = eval(2);
 let pieces = split(&sigma_2, 5, 3, &mut rng);
 let quorum = vec![1u32, 2, 3];
 let inner: Vec<SecretShare<Scalar>> = pieces[..3].to_vec();

 let mut nonces = Vec::new();
 let mut commitments = Vec::new();
 for &k in &quorum {
 let (n, c) = inner_commit::<Point, _>(k, SESSION, &mut rng);
 nonces.push(n);
 commitments.push(c);
 }
 let (d_nested, e_nested) =
 aggregate_inner_commitment_pair::<Point>(&SESSION, &precommits(&commitments), &commitments).unwrap();

 let (_, commits_1) = zf_commit(&mut rng);
 let commits_2 = zf_commitments(d_nested, e_nested);
 let package =
 zf_package(b"m", vec![(1, commits_1), (2, commits_2)]);
 let params = frostito::zf::inner_params_from_zf::<C>(&package, &vk(group_pubkey), 2).unwrap();
 let pre = precommits(&commitments);
 let request = NestedSigningRequest {
 package: &package,
 nested_index: 2,
 session_id: SESSION,
 inner_precommits: &pre,
 inner_commitments: &commitments,
 active_indices: &quorum,
 inner_threshold: 3,
 };

 let mut sigs = Vec::new();
 for (n, s) in nonces.into_iter().zip(inner.iter()) {
 sigs.push(inner_sign_v2::<C>(n, s, &vk(group_pubkey), b"m", &request).unwrap());
 }
 let mut z_nested = <Scalar as CurveScalar>::zero();
 for s in &sigs {
 z_nested = z_nested.add(&s.response);
 }

 // z*G == D_nested + rho*E_nested + lambda*c*(sigma_2*G).
 let lhs = <Point as CurvePoint>::generator().mul_scalar(&z_nested);
 let w = params.outer_lambda().mul(params.outer_challenge());
 let rhs = d_nested
 .add(&e_nested.mul_scalar(params.outer_binding()))
 .add(&<Point as CurvePoint>::generator().mul_scalar(&sigma_2).mul_scalar(&w));
 assert_eq!(lhs, rhs, "nested response is the flat FROST response");

 // Sanity: the inner quorum really does reconstruct sigma_2.
 let lag = compute_lagrange_coefficients::<Scalar>(&quorum).unwrap();
 let mut recon = <Scalar as CurveScalar>::zero();
 for (i, s) in inner.iter().enumerate() {
 recon = recon.add(&lag[i].mul(s.scalar()));
 }
 assert_eq!(recon, sigma_2);
}


/// — `active_indices` is coordinator-supplied and was unvalidated on the
/// signing side.
///
/// `inner_sign_v2` checked only that this holder appeared somewhere in the
/// list. A set with duplicates, with members that published no round-1
/// commitment, or smaller than `t_in` produced μ_k over a quorum that does not
/// match the ΣD the package committed to, and the share simply failed to
/// aggregate with no indication why. fixed this on the aggregation side
/// (`aggregate_inner_shares_verified`) and left the signing side open.
///
/// Each rejection is an error, never a panic: these values come off the wire.
#[test]
fn a_malformed_quorum_is_rejected_by_the_signer() {
 let mut rng = OsRng;
 let w = world(&mut rng);

 let cases: [(&[u32], u32, frostito::Error); 4] = [
 // duplicate holder: the Lagrange set is degenerate
 (&[1, 2, 2], 3, frostito::Error::DuplicateIndex(2)),
 // a member that published no round-1 commitment
 (&[1, 2, 9], 3, frostito::Error::UnknownQuorumMember(9)),
 // index 0 is not a Shamir index
 (&[1, 2, 0], 3, frostito::Error::InvalidIndex),
 // below the inner threshold the holder's own key material fixes
 (
 &[1, 2],
 3,
 frostito::Error::InsufficientContributions { got: 2, need: 3 },
 ),
 ];

 for (active, t, expected) in cases {
 // a full honest round, so nothing but the quorum is wrong
 let mut nonces = Vec::new();
 let mut commitments = Vec::new();
 for &k in &w.quorum {
 let (n, c) = inner_commit::<Point, _>(k, SESSION, &mut rng);
 nonces.push(n);
 commitments.push(c);
 }
 let (d_nested, e_nested) =
 aggregate_inner_commitment_pair::<Point>(&SESSION, &precommits(&commitments), &commitments).unwrap();
 let (_, commits_1) = zf_commit(&mut rng);
 let commits_2 = zf_commitments(d_nested, e_nested);
 let package =
 zf_package(b"m", vec![(1, commits_1), (2, commits_2)]);

 let pre = precommits(&commitments);
 let request = NestedSigningRequest {
 package: &package,
 nested_index: 2,
 session_id: SESSION,
 inner_precommits: &pre,
 inner_commitments: &commitments,
 active_indices: active,
 inner_threshold: t,
 };

 let err = inner_sign_v2::<C>(
 nonces.remove(0),
 &w.inner_shares[0],
 &vk(w.group_pubkey),
 b"m",
 &request,
 )
 .unwrap_err();
 assert_eq!(err, expected, "quorum {:?} must be rejected", active);
 }
}

/// — the commit–reveal round is no longer caller convention.
///
/// `inner_precommit`/`verify_inner_precommit` existed and nothing called them;
/// the requirement was a doc comment on `aggregate_inner_commitment_pair`. A
/// holder revealing last could therefore choose `D_k` with every other
/// commitment in hand, and nobody would notice a caller that skipped the
/// check — narsild's accumulator is exactly such a caller.
///
/// The precommitments are now an argument, and every reveal must match one.
#[test]
fn a_reveal_without_a_matching_precommit_is_rejected() {
 let mut rng = OsRng;
 let mut commitments = Vec::new();
 for k in 1..=3u32 {
 let (_, c) = inner_commit::<Point, _>(k, SESSION, &mut rng);
 commitments.push(c);
 }
 let good = precommits(&commitments);

 // honest round 0 + round 1 aggregates
 aggregate_inner_commitment_pair::<Point>(&SESSION, &good, &commitments).unwrap();

 // holder 2 precommitted to a different pair and revealed this one
 let (_, other) = inner_commit::<Point, _>(2, SESSION, &mut rng);
 let mut swapped = good.clone();
 swapped[1] = (2, frostito::nested::inner_precommit::<Point>(&other));
 assert_eq!(
 aggregate_inner_commitment_pair::<Point>(&SESSION, &swapped, &commitments).unwrap_err(),
 Error::PrecommitMismatch(2),
 "a reveal that does not match its precommitment names the holder"
 );

 // holder 3 never precommitted at all
 let missing: Vec<(u32, [u8; 32])> = good.iter().copied().filter(|(k, _)| *k != 3).collect();
 assert_eq!(
 aggregate_inner_commitment_pair::<Point>(&SESSION, &missing, &commitments).unwrap_err(),
 Error::PrecommitMismatch(3)
 );

 // extra precommitments for holders that did not reveal are fine: a holder
 // may precommit and then fail to appear
 let mut extra = good.clone();
 extra.push((9, [0u8; 32]));
 aggregate_inner_commitment_pair::<Point>(&SESSION, &extra, &commitments).unwrap();
}

/// — the session id is a mixing guard, not a replay guard, and
/// `inner_sign_v2_spending` is where a caller bolts on the missing half.
///
/// Consuming the nonces by value protects one process. It does not survive a
/// snapshot-restore, which brings the nonces back and lets them sign again
/// under a fresh challenge — two responses under one nonce give up the share.
/// Here the "restore" is a clone of the nonce pair, which is exactly what a
/// restored VM has.
#[test]
fn a_spent_session_cannot_sign_twice_across_a_restore() {
 use frostito::nested::{inner_sign_v2_spending, MemorySpentSessions, SpentSessions};

 let mut rng = OsRng;
 let w = world(&mut rng);

 let mut nonces = Vec::new();
 let mut commitments = Vec::new();
 for &k in &w.quorum {
 let (n, c) = inner_commit::<Point, _>(k, SESSION, &mut rng);
 nonces.push(n);
 commitments.push(c);
 }
 let pre = precommits(&commitments);
 let (d_nested, e_nested) =
 aggregate_inner_commitment_pair::<Point>(&SESSION, &pre, &commitments).unwrap();
 let (_, commits_1) = zf_commit(&mut rng);
 let commits_2 = zf_commitments(d_nested, e_nested);
 let package =
 zf_package(b"m", vec![(1, commits_1), (2, commits_2)]);
 let request = NestedSigningRequest {
 package: &package,
 nested_index: 2,
 session_id: SESSION,
 inner_precommits: &pre,
 inner_commitments: &commitments,
 active_indices: &w.quorum,
 inner_threshold: 3,
 };

 let mut store = MemorySpentSessions::new();
 assert!(!store.is_spent(&SESSION, 1));

 inner_sign_v2_spending::<C, _>(
 &mut store,
 nonces.remove(0),
 &w.inner_shares[0],
 &vk(w.group_pubkey),
 b"m",
 &request,
 )
 .expect("the first share is produced normally");
 assert!(store.is_spent(&SESSION, 1));

 // the restore: the node comes back from a snapshot taken before it
 // signed, re-runs round 1 for the same session, and tries again. Every
 // in-process guard is satisfied — `InnerNonces` is deliberately not
 // `Clone`, and these are genuinely fresh nonces — so only the durable
 // store can tell that this holder already answered this session.
 let (restored, restored_c) = inner_commit::<Point, _>(1, SESSION, &mut rng);
 let mut restored_commitments = commitments.clone();
 restored_commitments[0] = restored_c;
 let restored_pre = precommits(&restored_commitments);
 let (rd, re) = aggregate_inner_commitment_pair::<Point>(
 &SESSION,
 &restored_pre,
 &restored_commitments,
 )
 .unwrap();
 let (_, rc1) = zf_commit(&mut rng);
 let restored_package = zf_package(b"m", vec![(1, rc1), (2, zf_commitments(rd, re))]);
 let restored_request = NestedSigningRequest {
 package: &restored_package,
 nested_index: 2,
 session_id: SESSION,
 inner_precommits: &restored_pre,
 inner_commitments: &restored_commitments,
 active_indices: &w.quorum,
 inner_threshold: 3,
 };
 assert_eq!(
 inner_sign_v2_spending::<C, _>(
 &mut store,
 restored,
 &w.inner_shares[0],
 &vk(w.group_pubkey),
 b"m",
 &restored_request,
 )
 .unwrap_err(),
 Error::SessionSpent,
 "a restored node must not answer the same session twice"
 );

 // another holder in the same session is unaffected: the pair is
 // (session, holder), not the session alone
 assert!(!store.is_spent(&SESSION, 2));
 inner_sign_v2_spending::<C, _>(
 &mut store,
 nonces.remove(0),
 &w.inner_shares[1],
 &vk(w.group_pubkey),
 b"m",
 &request,
 )
 .expect("holder 2 has not signed this session");
 assert_eq!(store.len(), 2);
}

/// Identifiable abort inside the inner group: a tampered inner share is
/// rejected, and the aggregate names the holder that produced it.
///
/// Without this an invalid share folds silently into the sum and the outer
/// signature just fails to verify, with nothing to say who caused it.
#[test]
fn a_dishonest_inner_holder_is_named() {
    use frostito::nested::split_evaluation_for_inner;

    let mut rng = OsRng;
    let msg = b"m";
    let sigma_2 = <Scalar as CurveScalar>::random(&mut rng);
    let quorum: Vec<u32> = vec![1, 2, 3];
    let (pieces, _) = split_evaluation_for_inner::<Point, _>(&sigma_2, 5, 3, &mut rng);
    let inner: Vec<SecretShare<Scalar>> = quorum
        .iter()
        .map(|k| {
            let (_, piece) = pieces.iter().find(|(i, _)| i == k).unwrap();
            SecretShare::new(*k, *piece).unwrap()
        })
        .collect();

    let mut nonces = Vec::new();
    let mut commitments = Vec::new();
    for &k in &quorum {
        let (n, c) = inner_commit::<Point, _>(k, SESSION, &mut rng);
        nonces.push(n);
        commitments.push(c);
    }

    let pre = precommits(&commitments);
    let (d_nested, e_nested) =
        aggregate_inner_commitment_pair::<Point>(&SESSION, &pre, &commitments).unwrap();
    let group_pubkey = <Point as CurvePoint>::generator().mul_scalar(&sigma_2);

    let (_, commits_1) = zf_commit(&mut rng);
    let package = zf_package(msg, vec![(1, commits_1), (2, zf_commitments(d_nested, e_nested))]);
    let params =
        frostito::zf::inner_params_from_zf::<C>(&package, &vk(group_pubkey), 2).unwrap();

    let request = NestedSigningRequest {
        package: &package,
        nested_index: 2,
        session_id: SESSION,
        inner_precommits: &pre,
        inner_commitments: &commitments,
        active_indices: &quorum,
        inner_threshold: 3,
    };

    let mut sigs = Vec::new();
    for (n, share) in nonces.into_iter().zip(inner.iter()) {
        sigs.push(inner_sign_v2::<C>(n, share, &vk(group_pubkey), msg, &request).unwrap());
    }

    // holder 2 goes rogue
    sigs[1].response = sigs[1].response.add(&<Scalar as CurveScalar>::one());

    let err = aggregate_inner_shares_verified::<Point>(
        &sigs,
        &commitments,
        &public_shares(&inner),
        &params,
        &quorum,
    )
    .expect_err("a tampered share must be rejected");
    assert_eq!(err, vec![2], "the cheating holder must be identified");
}

/// Spending and epoch-binding at once — which the free functions could not do.
///
/// `inner_sign_v2_spending` and `inner_sign_v2_with_context` each added one
/// concern and there was no third function for both. A caller who wanted a
/// durable spend record *and* an epoch-bound message had to write it, and the
/// order is not obvious: spend first, or bind first? Get it wrong and you
/// record a session you then refuse to sign, or sign one you never recorded.
///
/// As a stack the order is in the composition, and both hold.
#[test]
fn a_stack_composes_spending_and_epoch_binding() {
    use frostito::nested::MemorySpentSessions;
    use frostito::signer::{Bind, Holder, SignRequest, Signer, Spend, Stack};
    use frostito::SigningContext;

    let mut rng = OsRng;
    let w = world(&mut rng);

    let ctx = SigningContext::new(7, [0x5a; 32], b"release the escrow");
    let bound = ctx.encode();

    let mut nonces = Vec::new();
    let mut commitments = Vec::new();
    for &k in &w.quorum {
        let (n, c) = inner_commit::<Point, _>(k, SESSION, &mut rng);
        nonces.push(n);
        commitments.push(c);
    }
    let pre = precommits(&commitments);
    let (d, e) = aggregate_inner_commitment_pair::<Point>(&SESSION, &pre, &commitments).unwrap();

    let (_, commits_1) = zf_commit(&mut rng);
    let package = zf_package(&bound, vec![(1, commits_1), (2, zf_commitments(d, e))]);

    let request = NestedSigningRequest {
        package: &package,
        nested_index: 2,
        session_id: SESSION,
        inner_precommits: &pre,
        inner_commitments: &commitments,
        active_indices: &w.quorum,
        inner_threshold: 3,
    };

    let mut log = MemorySpentSessions::new();
    let share = &w.inner_shares[0];
    let key = vk(w.group_pubkey);

    // Spend outermost, so the session is durable before any signing happens.
    let mut signer = Stack::new(Holder::new(share, &key))
        .layer(Bind::new(&ctx))
        .layer(Spend::new(&mut log))
        .into_inner();

    let first = signer.sign(SignRequest {
        nonces: nonces.remove(0),
        // `Bind` replaces this with ctx.encode(), so a bare payload is fine.
        approved_message: b"release the escrow",
        nested: &request,
    });
    assert!(first.is_ok(), "the composed stack must sign: {first:?}");

    // The epoch binding held: the package carries ctx.encode(), and
    // `inner_sign_v2` refuses a package whose message is not what it signed.
    assert_eq!(package.message(), bound.as_slice());

    // And the spend record went in, so the same nonces cannot answer twice.
    let (n2, _) = inner_commit::<Point, _>(w.quorum[0], SESSION, &mut rng);
    let again = signer.sign(SignRequest {
        nonces: n2,
        approved_message: b"release the escrow",
        nested: &request,
    });
    assert_eq!(
        again.unwrap_err(),
        frostito::Error::SessionSpent,
        "the spend layer must refuse a second answer for the same session"
    );
}
