//! Audit regression tests — canonical point encoding on every backend
//! (2026-09 review).
//!
//! was secp256k1-only: `compress()` returned the bare x-coordinate and
//! `decompress()` always rebuilt the even-y point, so the encoding was neither
//! a round trip nor injective — `P` and `-P` hashed identically, which breaks
//! exactly the injectivity the FROST binding factor depends on.
//!
//! These were `#[ignore]`d PoCs asserting the break. They now assert the
//! property, on every backend the build enables, and none is ignored.

macro_rules! encoding_properties {
 ($name:ident, $point:ty, $scalar:ty, $size:expr) => {
 mod $name {
 use frostito::curve::{CurvePoint, CurveScalar};

 type Point = $point;
 type Scalar = $scalar;

 fn rand_point(rng: &mut rand::rngs::OsRng) -> Point {
 let s = <Scalar as CurveScalar>::random(rng);
 <Point as CurvePoint>::generator().mul_scalar(&s)
 }

 /// `decompress(compress(P)) == P`, for every point, every time.
 #[test]
 fn compress_decompress_round_trips() {
 let mut rng = rand::rngs::OsRng;
 for _ in 0..128 {
 let p = rand_point(&mut rng);
 let bytes = CurvePoint::compress(&p);
 assert_eq!(bytes.as_ref().len(), $size);
 assert_eq!(
 <Point as CurvePoint>::decompress(bytes.as_ref()).expect("decompresses"),
 p,
 "compress/decompress must round-trip for every point"
 );
 }
 }

 /// `compress(P) != compress(-P)`: the encoding separates a point
 /// from its negation, so a hash over it separates a commitment set
 /// from its sign-flipped variants.
 #[test]
 fn compress_is_injective_in_the_sign() {
 let mut rng = rand::rngs::OsRng;
 for _ in 0..128 {
 let s = <Scalar as CurveScalar>::random(&mut rng);
 let p = <Point as CurvePoint>::generator().mul_scalar(&s);
 let neg = <Point as CurvePoint>::generator().mul_scalar(&s.neg());
 assert_ne!(p, neg, "P and -P are different points");
 assert_ne!(
 CurvePoint::compress(&p),
 CurvePoint::compress(&neg),
 "distinct points must have distinct compressed encodings"
 );
 }
 }

 /// The identity is a legal FROST commitment and must survive the
 /// round trip like any other point.
 #[test]
 fn the_identity_round_trips() {
 let id = <Point as CurvePoint>::identity();
 let bytes = CurvePoint::compress(&id);
 assert_eq!(bytes.as_ref().len(), $size);
 assert_eq!(
 <Point as CurvePoint>::decompress(bytes.as_ref()).expect("decompresses"),
 id
 );
 }

 /// Non-canonical encodings are rejected rather than coerced: a
 /// short slice, a long slice, and (on secp256k1) the bare
 /// x-coordinate that 0.3.0 accepted.
 #[test]
 fn non_canonical_encodings_are_rejected() {
 let mut rng = rand::rngs::OsRng;
 let p = rand_point(&mut rng);
 let bytes = CurvePoint::compress(&p);
 let b = bytes.as_ref();

 assert!(<Point as CurvePoint>::decompress(&b[..b.len() - 1]).is_none());
 let mut long = b.to_vec();
 long.push(0);
 assert!(<Point as CurvePoint>::decompress(&long).is_none());
 assert!(<Point as CurvePoint>::decompress(&[]).is_none());
 }
 }
 };
}

#[cfg(feature = "ristretto255")]
encoding_properties!(
 ristretto255,
 curve25519_dalek::ristretto::RistrettoPoint,
 curve25519_dalek::scalar::Scalar,
 32
);

#[cfg(feature = "secp256k1")]
encoding_properties!(secp256k1, k256::ProjectivePoint, k256::Scalar, 33);

#[cfg(feature = "pallas")]
encoding_properties!(
 pallas,
 pasta_curves::pallas::Point,
 pasta_curves::pallas::Scalar,
 32
);

#[cfg(feature = "pallas")]
encoding_properties!(
 orchard_spend_auth,
 frostito::curve::pallas::SpendAuthPoint,
 pasta_curves::pallas::Scalar,
 32
);

#[cfg(feature = "decaf377")]
encoding_properties!(decaf377, decaf377::Element, decaf377::Fr, 32);

/// the second half, stated once against the protocol layer rather than
/// the trait: two commitment sets that differ only by a point negation must
/// produce different binding factors and different challenges.
#[cfg(all(feature = "zf-secp256k1", feature = "std"))]
mod binding_factor_separates_negated_commitments {
 use frost_core::{
 compute_binding_factor_list,
 keys::VerifyingShare,
 round1::{NonceCommitment, SigningCommitments},
 Identifier, SigningPackage, VerifyingKey,
 };
 use frost_secp256k1::Secp256K1Sha256 as C;
 use frostito::curve::{CurvePoint, CurveScalar};
 use k256::{ProjectivePoint as Point, Scalar};
 use std::collections::BTreeMap;

 #[test]
 fn negating_a_commitment_moves_the_binding_factor() {
 let mut rng = rand::rngs::OsRng;
 let d = <Scalar as CurveScalar>::random(&mut rng);
 let e = <Scalar as CurveScalar>::random(&mut rng);
 let g = <Point as CurvePoint>::generator();
 let id: Identifier<C> = 1u16.try_into().unwrap();

 let commitments = |hiding: Point| {
 let mut m = BTreeMap::new();
 m.insert(
 id,
 SigningCommitments::<C>::new(
 NonceCommitment::new(hiding),
 NonceCommitment::new(g.mul_scalar(&e)),
 ),
 );
 m
 };

 let y = VerifyingKey::<C>::new(g.mul_scalar(&<Scalar as CurveScalar>::random(&mut rng)));
 let _ = VerifyingShare::<C>::new(g);

 let a = SigningPackage::new(commitments(g.mul_scalar(&d)), b"m");
 let b = SigningPackage::new(commitments(g.mul_scalar(&d.neg())), b"m");

 let fa = compute_binding_factor_list::<C>(&a, &y, &[]).unwrap();
 let fb = compute_binding_factor_list::<C>(&b, &y, &[]).unwrap();
 assert_ne!(
 fa.get(&id).unwrap().serialize(),
 fb.get(&id).unwrap().serialize(),
 "a sign flip in the commitment set must move the binding factor"
 );
 }
}
