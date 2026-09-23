//! The nested arithmetic, against `frost-core`'s own signature share.
//!
//! `frostito::zf::inner_params_from_zf` hands an inner holder the outer
//! context — rho, c, lambda — recomputed from a ZF signing package. If those
//! are right, the flat FROST response assembled from them must equal the share
//! `frost_core::round2::sign` produces for that participant.
//!
//! That is the equivalence nested FROST rests on — a nested position is
//! indistinguishable from a flat signer — checked against the audited
//! implementation rather than against ourselves.

#![cfg(all(feature = "zf-ristretto255", feature = "std"))]

use std::collections::BTreeMap;

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use frost_core::{
 keys::{KeyPackage, SigningShare, VerifyingShare},
 round1::{Nonce, SigningNonces},
 round2 as zf_round2, Identifier, SigningPackage as ZfPackage, VerifyingKey,
};
use frost_ristretto255::Ristretto255Sha512 as C;
use frostito::curve::{CurvePoint, CurveScalar};
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

/// A ZF `SigningNonces` from scalars the caller keeps, so the same values can
/// be used to reassemble the response by hand.
fn zf_nonces(h: Scalar, b: Scalar) -> SigningNonces<C> {
 SigningNonces::from_nonces(Nonce::<C>::from_scalar(h), Nonce::<C>::from_scalar(b))
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
    let mut held_nonces = BTreeMap::new();
    let mut zf_commitments = BTreeMap::new();

    for &i in &signers {
        let h = <Scalar as CurveScalar>::random(&mut rng);
        let b = <Scalar as CurveScalar>::random(&mut rng);
        let zf = zf_nonces(h, b);
        zf_commitments.insert(id(i), *zf.commitments());
        nonce_scalars.insert(i, (h, b));
        held_nonces.insert(i, zf);
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
        let zf_share = zf_round2::sign(&package, &held_nonces[&i], &key_package).expect("zf sign");

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
