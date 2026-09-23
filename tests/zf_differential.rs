//! `frostito::frost` against ZF `frost-core`, on identical inputs.
//!
//! For ristretto255 the element and scalar types are literally the same on
//! both sides (`curve25519_dalek::RistrettoPoint`/`Scalar`), so both
//! implementations can be driven from one set of key material and one set of
//! nonces, and their outputs compared byte for byte.
//!
//! # What this establishes
//!
//! **Key material is interchangeable.** A share dealt here loads into a ZF
//! `KeyPackage`, signs under `frost-core`, and verifies under the same group
//! key. That is the property a migration to `frost-core` depends on, and it
//! holds today.
//!
//! **Signatures are not.** `frostito::frost` implements FROST's *structure*
//! faithfully — the challenge is `H(R || Y || msg)` exactly as RFC 9591 §4.6
//! specifies — but under its own context strings (`"frost-challenge-v1"`,
//! `"frost-binding-v2"`) rather than the registered
//! `"FROST-RISTRETTO255-SHA512-v1"` with the `"chal"` and `"rho"` separators.
//! It is therefore a non-standard ciphersuite: correct FROST, but not
//! FROST(ristretto255, SHA-512), and nothing outside this crate verifies it.
//!
//! The consequence for rooting this crate in `frost-core`: it is not a
//! refactor. Every signature the crate produces changes, on every backend.
//! Keys survive; signatures and anything mid-flight do not. This test pins
//! both halves of that so neither is discovered by accident.

#![cfg(all(feature = "zf-ristretto255", feature = "std"))]

use std::collections::BTreeMap;

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use frost_core::{
 keys::{KeyPackage, PublicKeyPackage, SigningShare, VerifyingShare},
 round1::{Nonce, SigningNonces},
 round2 as zf_round2, Identifier, SigningPackage as ZfPackage, VerifyingKey,
};
use frost_ristretto255::Ristretto255Sha512 as C;
use frostito::curve::{CurvePoint, CurveScalar};
use frostito::frost::{self, Nonces, SigningCommitments, SigningPackage};
use frostito::SecretShare;
use rand::rngs::OsRng;

type Point = RistrettoPoint;

const MSG: &[u8] = b"differential: frostito::frost vs frost-core";

/// A t-of-n Shamir sharing plus the public material both sides need.
struct Group {
 shares: Vec<SecretShare<Scalar>>,
 verifying: BTreeMap<u32, Point>,
 group_pubkey: Point,
 t: u16,
}

fn deal(n: u32, t: u32, rng: &mut OsRng) -> Group {
 let mut coeffs = vec![<Scalar as CurveScalar>::random(rng)];
 for _ in 1..t {
 coeffs.push(<Scalar as CurveScalar>::random(rng));
 }
 let group_pubkey = <Point as CurvePoint>::generator().mul_scalar(&coeffs[0]);

 let mut shares = Vec::new();
 let mut verifying = BTreeMap::new();
 for i in 1..=n {
 let x = <Scalar as CurveScalar>::from_u32(i);
 let mut y = <Scalar as CurveScalar>::zero();
 let mut xp = <Scalar as CurveScalar>::one();
 for c in &coeffs {
 y = y.add(&c.mul(&xp));
 xp = xp.mul(&x);
 }
 verifying.insert(i, <Point as CurvePoint>::generator().mul_scalar(&y));
 shares.push(SecretShare::new(i, y).unwrap());
 }
 Group { shares, verifying, group_pubkey, t: t as u16 }
}

fn id(i: u32) -> Identifier<C> {
 (i as u16).try_into().unwrap()
}

/// The same `(hiding, binding)` scalars, as both crates' nonce types.
fn paired_nonces(h: Scalar, b: Scalar) -> (Nonces<Scalar>, SigningNonces<C>) {
 (
 Nonces::from_scalars(h, b),
 SigningNonces::from_nonces(Nonce::<C>::from_scalar(h), Nonce::<C>::from_scalar(b)),
 )
}

#[test]
fn key_material_is_interchangeable_but_signatures_are_not() {
 let mut rng = OsRng;
 let g = deal(3, 2, &mut rng);
 let signers = [1u32, 2u32];

 // One set of nonces, handed to both implementations.
 let mut ours_nonces = BTreeMap::new();
 let mut zf_nonces = BTreeMap::new();
 let mut ours_commitments = Vec::new();
 let mut zf_commitments = BTreeMap::new();

 for &i in &signers {
 let h = <Scalar as CurveScalar>::random(&mut rng);
 let b = <Scalar as CurveScalar>::random(&mut rng);
 let (ours, zf) = paired_nonces(h, b);

 ours_commitments.push(SigningCommitments {
 index: i,
 hiding: <Point as CurvePoint>::generator().mul_scalar(&h),
 binding: <Point as CurvePoint>::generator().mul_scalar(&b),
 });
 zf_commitments.insert(id(i), *zf.commitments());

 ours_nonces.insert(i, ours);
 zf_nonces.insert(i, zf);
 }

 let ours_package = SigningPackage::new(MSG.to_vec(), ours_commitments)
 .expect("osst signing package");
 let zf_package = ZfPackage::new(zf_commitments, MSG);

 // --- signature shares: structurally FROST, different ciphersuite -----
 let mut ours_shares = Vec::new();
 let mut zf_shares = BTreeMap::new();

 for &i in &signers {
 let share = &g.shares[(i - 1) as usize];

 let ours = frost::sign::<Point>(
 &ours_package,
 ours_nonces.remove(&i).unwrap(),
 share,
 &g.group_pubkey,
 )
 .expect("osst sign");

 // The same secret share, as ZF key material.
 let key_package = KeyPackage::<C>::new(
 id(i),
 SigningShare::new(*share.scalar()),
 VerifyingShare::new(g.verifying[&i]),
 VerifyingKey::new(g.group_pubkey),
 g.t,
 );
 let zf = zf_round2::sign(&zf_package, &zf_nonces[&i], &key_package).expect("zf sign");

 assert_ne!(
 <Scalar as CurveScalar>::to_bytes(&ours.response).to_vec(),
 zf.serialize(),
 "index {i}: the two ciphersuites must not silently coincide — if this \
 ever passes, the domain separation has been lost"
 );

 ours_shares.push(ours);
 zf_shares.insert(id(i), zf);
 }

 // --- the key material is interchangeable; the signature verifies -------
 let pubkeys = PublicKeyPackage::<C>::new(
 g.verifying.iter().map(|(i, v)| (id(*i), VerifyingShare::new(*v))).collect(),
 VerifyingKey::new(g.group_pubkey),
 Some(g.t),
 );
 let zf_sig = frost_core::aggregate(&zf_package, &zf_shares, &pubkeys).expect("zf aggregate");

 assert!(
 pubkeys.verifying_key().verify(MSG, &zf_sig).is_ok(),
 "shares dealt by this crate must sign and verify under frost-core"
 );

 // And ours verifies under ours, over the same key.
 let ours_sig = frost::aggregate::<Point>(&ours_package, &ours_shares, &g.group_pubkey, None)
 .expect("osst aggregate");
 assert!(
 frost::verify_signature::<Point>(&g.group_pubkey, MSG, &ours_sig),
 "frostito::frost must verify its own signature"
 );

 // Neither verifier accepts the other's signature: the ciphersuites are
 // distinct, which is the whole point of domain separation.
 let ours_bytes: Vec<u8> = <Point as CurvePoint>::compress(&ours_sig.r)
 .iter()
 .copied()
 .chain(<Scalar as CurveScalar>::to_bytes(&ours_sig.z))
 .collect();
 if let Ok(parsed) = frost_core::Signature::<C>::deserialize(&ours_bytes) {
 assert!(
 pubkeys.verifying_key().verify(MSG, &parsed).is_err(),
 "frost-core must reject a signature from a different ciphersuite"
 );
 }
}

/// The nested arithmetic, checked against `frost-core`'s own signature share.
///
/// `frostito::zf::inner_params_from_zf` hands an inner holder the outer
/// context — ρ, c, λ — recomputed from a ZF signing package. If those are
/// right, then the flat FROST response
///
/// ```text
/// z_i = d_i + ρ_i·e_i + λ_i·c·σ_i
/// ```
///
/// assembled by hand from them must equal the share `frost_core::round2::sign`
/// produces for that participant. That is the equivalence nested FROST rests
/// on — a nested position is indistinguishable from a flat signer — checked
/// against the audited implementation rather than against our own.
#[test]
fn zf_derived_outer_context_reproduces_the_signature_share() {
        use frostito::zf::inner_params_from_zf;

    let mut rng = OsRng;
    let g = deal(3, 2, &mut rng);
    let signers = [1u32, 2u32];

    let mut nonce_scalars = BTreeMap::new();
    let mut zf_nonces = BTreeMap::new();
    let mut zf_commitments = BTreeMap::new();

    for &i in &signers {
        let h = <Scalar as CurveScalar>::random(&mut rng);
        let b = <Scalar as CurveScalar>::random(&mut rng);
        let (_, zf) = paired_nonces(h, b);
        zf_commitments.insert(id(i), *zf.commitments());
        nonce_scalars.insert(i, (h, b));
        zf_nonces.insert(i, zf);
    }

    let package = ZfPackage::new(zf_commitments, MSG);
    let verifying_key = VerifyingKey::new(g.group_pubkey);

    for &i in &signers {
        let share = &g.shares[(i - 1) as usize];

        // what frost-core computes
        let key_package = KeyPackage::<C>::new(
            id(i),
            SigningShare::new(*share.scalar()),
            VerifyingShare::new(g.verifying[&i]),
            verifying_key,
            g.t,
        );
        let zf_share = zf_round2::sign(&package, &zf_nonces[&i], &key_package).expect("zf sign");

        // what an inner holder assembles from the bridged outer context
        let params = inner_params_from_zf::<C>(&package, &verifying_key, i).expect("bridge");
        let (d, e) = nonce_scalars[&i];
        let ours = d.add(
            &params
                .outer_binding()
                .mul(&e)
                .add(&params.outer_lambda().mul(params.outer_challenge()).mul(share.scalar())),
        );

        assert_eq!(
            <Scalar as CurveScalar>::to_bytes(&ours).to_vec(),
            zf_share.serialize(),
            "index {i}: d + rho*e + lambda*c*sigma must equal frost-core's share"
        );
    }
}
