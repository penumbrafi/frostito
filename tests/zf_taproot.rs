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

/// Does the nested composition survive BIP340's parity rules?
///
/// Under Taproot, `compute_signature_share` negates the signer's nonces when
/// the group commitment `R` has odd Y, and `into_even_y` negates the key
/// package when the group key has odd Y. A nested position's outer nonce is
/// the sum of its inner holders' nonces, and its outer share is spread across
/// them — so both negations have to reach inside the group.
///
/// This drives the flat response `d + rho*e + lambda*c*sigma` from the bridged
/// context, exactly as an inner holder assembles it, and compares against what
/// `round2::sign` produces. Run over many samples so both parities are hit.
///
/// # Known gap — this is a PoC, not a regression test
///
/// It fails, and it is supposed to until `nested` learns BIP340's parity
/// rules. `Ciphersuite` exposes `pre_sign` and `compute_signature_share` as
/// overridable hooks precisely so a suite can normalise; Taproot uses both,
/// and `inner_sign_v2` assembles its response by hand, bypassing them.
///
/// Agreement rose from 0/24 to roughly 9/24 once the bridge dispatched
/// through `C::challenge` instead of `frost_core::challenge`. What remains is
/// the two negations, each independent and each hit about half the time:
///
/// - `R` has odd Y  -> every inner holder must negate its own `(d_k, e_k)`
/// - the group key has odd Y -> every inner holder must negate its `sigma_k`
///
/// Both are derivable locally by each holder from public data, so the fix
/// keeps the property that no coordinator asserts anything. It needs a small
/// trait — `Ciphersuite` has no generic way to ask "does this suite normalise
/// parity", because x-only encoding is a secp256k1 notion.
///
/// Until then: a nested position cannot hold a key in a Taproot multisig.
/// Flat FROST under this suite is unaffected and is covered above.
#[ignore = "known gap: nested does not apply BIP340 parity normalisation"]
#[test]
fn nested_assembly_matches_taproot_signing_across_parities() {
    use frost_core::round1::{Nonce, SigningNonces};
    use frostito::curve::CurveScalar;
    use frostito::zf::inner_params_from_zf;
    use k256::Scalar;

    let mut rng = OsRng;
    let mut agreed = 0usize;
    let mut differed = 0usize;

    for _ in 0..24 {
        let (shares, pubkeys) =
            keys::generate_with_dealer::<C, _>(2, 2, IdentifierList::Default, &mut rng).unwrap();
        let packages: BTreeMap<_, _> = shares
            .into_iter()
            .map(|(i, s)| (i, KeyPackage::try_from(s).unwrap()))
            .collect();

        let mut held = BTreeMap::new();
        let mut commitments = BTreeMap::new();
        for id in packages.keys() {
            let h = <Scalar as CurveScalar>::random(&mut rng);
            let b = <Scalar as CurveScalar>::random(&mut rng);
            let n = SigningNonces::from_nonces(
                Nonce::<C>::from_scalar(h),
                Nonce::<C>::from_scalar(b),
            );
            commitments.insert(*id, *n.commitments());
            held.insert(*id, (h, b, n));
        }

        let package = SigningPackage::new(commitments, MSG);
        let vk = pubkeys.verifying_key();

        let target = *packages.keys().next().unwrap();
        let zf_share = round2::sign(&package, &held[&target].2, &packages[&target]).unwrap();

        let params = inner_params_from_zf::<C>(&package, vk, 1).unwrap();
        let (h, b, _) = &held[&target];
        let sigma = packages[&target].signing_share().to_scalar();
        let ours = h.add(
            &params.outer_binding().mul(b).add(
                &params
                    .outer_lambda()
                    .mul(params.outer_challenge())
                    .mul(&sigma),
            ),
        );

        if <Scalar as CurveScalar>::to_bytes(&ours).to_vec() == zf_share.serialize() {
            agreed += 1;
        } else {
            differed += 1;
        }
    }

    assert_eq!(
        differed, 0,
        "the nested assembly diverges from Taproot signing in {differed} of {} samples \
         (agreed in {agreed}): BIP340 negates the signer's nonces when R has odd Y and \
         negates the key package when the group key has odd Y, and neither negation \
         currently reaches the inner group",
        agreed + differed
    );
}
