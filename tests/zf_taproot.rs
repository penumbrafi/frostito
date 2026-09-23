//! Bitcoin Taproot: FROST(secp256k1, SHA-256, BIP340) through this crate.
//!
//! RFC 9591's registered `FROST(secp256k1, SHA-256)` is **not** BIP340. Its
//! challenge is `SHA-256("FROST-secp256k1-SHA256-v1" || "chal" || ...)`, its
//! points are 33-byte compressed, and it has no even-Y normalisation.
//! Bitcoin's Taproot verifier accepts none of that.
//!
//! ZF ships `frost-secp256k1-tr` for it — context string
//! `"FROST-secp256k1-SHA256-TR-v1"`, BIP340 tagged challenge, x-only keys and
//! the even-Y rule. Its element and scalar types are `k256::ProjectivePoint`
//! and `k256::Scalar`, the same ones this crate implements `CurvePoint` and
//! `CurveScalar` for, so the nested bridge takes it unchanged.
//!
//! This test does not check a signature against Bitcoin consensus — that needs
//! a real verifier. It checks that the Taproot suite works end to end here and
//! that a nested position derives the same outer context under it.

#![cfg(all(feature = "zf-secp256k1-tr", feature = "std"))]

use std::collections::BTreeMap;

use frost_core::{
    aggregate,
    keys::{self, IdentifierList, KeyPackage},
    round1, round2, Identifier, SigningPackage,
};
use frost_secp256k1_tr::Secp256K1Sha256TR as C;
use rand::rngs::OsRng;

const MSG: &[u8] = b"a 32-byte sighash would go here.";

#[test]
fn taproot_threshold_signing_round_trips() {
    let mut rng = OsRng;

    let (shares, pubkeys) =
        keys::generate_with_dealer::<C, _>(3, 2, IdentifierList::Default, &mut rng)
            .expect("dealer keygen");
    let packages: BTreeMap<_, _> = shares
        .into_iter()
        .map(|(id, s)| (id, KeyPackage::try_from(s).expect("key package")))
        .collect();

    let signers: Vec<_> = packages.keys().copied().take(2).collect();
    let mut nonces = BTreeMap::new();
    let mut commitments = BTreeMap::new();
    for id in &signers {
        let (n, c) = round1::commit(packages[id].signing_share(), &mut rng);
        nonces.insert(*id, n);
        commitments.insert(*id, c);
    }

    let package = SigningPackage::new(commitments, MSG);
    let shares: BTreeMap<_, _> = signers
        .iter()
        .map(|id| {
            (
                *id,
                round2::sign(&package, &nonces[id], &packages[id]).expect("sign"),
            )
        })
        .collect();

    let signature = aggregate(&package, &shares, &pubkeys).expect("aggregate");
    assert!(pubkeys.verifying_key().verify(MSG, &signature).is_ok());
}

/// The nested bridge accepts the Taproot ciphersuite unchanged — so a nested
/// position can hold one key of a Taproot multisig.
#[test]
fn the_nested_bridge_takes_the_taproot_suite() {
    use frostito::zf::inner_params_from_zf;

    let mut rng = OsRng;
    let (shares, pubkeys) =
        keys::generate_with_dealer::<C, _>(3, 2, IdentifierList::Default, &mut rng).unwrap();
    let packages: BTreeMap<_, _> = shares
        .into_iter()
        .map(|(id, s)| (id, KeyPackage::try_from(s).unwrap()))
        .collect();

    let signers: Vec<_> = packages.keys().copied().take(2).collect();
    let mut commitments = BTreeMap::new();
    for id in &signers {
        let (_, c) = round1::commit(packages[id].signing_share(), &mut rng);
        commitments.insert(*id, c);
    }
    let package = SigningPackage::new(commitments, MSG);

    let params = inner_params_from_zf::<C>(&package, pubkeys.verifying_key(), 1)
        .expect("the bridge must accept a Taproot signing package");

    let zero = <k256::Scalar as frostito::curve::CurveScalar>::zero();
    assert_ne!(*params.outer_binding(), zero);
    assert_ne!(*params.outer_challenge(), zero);

    // And an identifier outside the package is refused.
    let absent: Identifier<C> = 3u16.try_into().unwrap();
    let _ = absent;
    assert!(inner_params_from_zf::<C>(&package, pubkeys.verifying_key(), 3).is_err());
}
