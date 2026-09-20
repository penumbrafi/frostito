//! End-to-end: shares dealt by ZF `frost-core` (via `reddsa`'s
//! FROST(Pallas, BLAKE2b-512)) are reshared with `osst::reshare` to a
//! different member set, the new members rebuild ZF `KeyPackage`s and
//! `PublicKeyPackage`, and sign with the *original* group key.
//!
//! This is the integration the validator custody design depends on: the
//! reshare math lives in frostito, the signing lives in ZF frost, and the
//! group key never changes.
//!
//! Uses the `OrchardSpendAuthCurve` backend: ZF's FROST(Pallas) operates in
//! the Orchard spend-auth basepoint group, not under the Pallas generator,
//! and Feldman commitments only verify in the same group as the shares.
#![cfg(feature = "pallas")]

use std::collections::BTreeMap;

use osst::curve::{OsstCurve, OsstPoint, OsstScalar};
use osst::reshare::{Aggregator, Dealer, SharePolynomial};
use osst::OrchardSpendAuthCurve;
use rand::rngs::OsRng;
use reddsa::frost::redpallas::{self as zf, keys, round1, round2, Identifier};

type P = <OrchardSpendAuthCurve as OsstCurve>::Point;
type S = <OrchardSpendAuthCurve as OsstCurve>::Scalar;

fn id(i: u32) -> Identifier {
    Identifier::try_from(i as u16).unwrap()
}

/// ZF secret share -> frostito scalar, via the canonical 32-byte encoding
/// both crates use for Pallas scalars.
fn zf_share_to_scalar(share: &keys::SecretShare) -> S {
    let bytes: [u8; 32] = share.signing_share().serialize().try_into().unwrap();
    S::from_canonical_bytes(&bytes).expect("canonical scalar")
}

fn scalar_to_zf(s: &S) -> keys::SigningShare {
    keys::SigningShare::deserialize(&s.to_bytes()).unwrap()
}

fn point_to_zf_share(p: &P) -> keys::VerifyingShare {
    keys::VerifyingShare::deserialize(p.compress().as_ref()).unwrap()
}

/// Rebuild ZF key material for new member `j` from the frostito outputs.
fn rebuild_key_package(
    j: u32,
    share: &S,
    poly: &SharePolynomial<P>,
    group_key: &zf::VerifyingKey,
    new_t: u16,
) -> keys::KeyPackage {
    keys::KeyPackage::new(
        id(j),
        scalar_to_zf(share),
        point_to_zf_share(&poly.verifying_share(j)),
        *group_key,
        new_t,
    )
}

fn rebuild_public_package(
    new_n: u32,
    poly: &SharePolynomial<P>,
    group_key: &zf::VerifyingKey,
) -> keys::PublicKeyPackage {
    let shares = (1..=new_n)
        .map(|j| (id(j), point_to_zf_share(&poly.verifying_share(j))))
        .collect();
    keys::PublicKeyPackage::new(shares, *group_key)
}

/// Full ZF FROST signing round among `signers` with the given packages.
fn zf_sign(
    signers: &[u32],
    key_packages: &BTreeMap<u32, keys::KeyPackage>,
    pubkeys: &keys::PublicKeyPackage,
    message: &[u8],
) -> zf::Signature {
    let mut rng = OsRng;
    let mut nonces = BTreeMap::new();
    let mut commitments = BTreeMap::new();
    for &j in signers {
        let kp = &key_packages[&j];
        let (n, c) = round1::commit(kp.signing_share(), &mut rng);
        nonces.insert(j, n);
        commitments.insert(id(j), c);
    }
    let package = zf::SigningPackage::new(commitments, message);
    let params = zf::RandomizedParams::new(pubkeys.verifying_key(), &package, &mut rng).unwrap();
    let mut shares = BTreeMap::new();
    for &j in signers {
        let s = round2::sign(&package, &nonces[&j], &key_packages[&j], *params.randomizer())
            .unwrap();
        shares.insert(id(j), s);
    }
    let sig = zf::aggregate(&package, &shares, pubkeys, &params).unwrap();
    params
        .randomized_verifying_key()
        .verify(message, &sig)
        .expect("signature verifies under the randomized group key");
    sig
}

#[test]
fn zf_dkg_then_frostito_reshare_then_zf_sign() {
    let mut rng = OsRng;

    // --- Epoch 1: ZF-dealt 3-of-5 under integer identifiers 1..=5 -----------
    let (old_shares, old_pubkeys) =
        keys::generate_with_dealer(5, 3, keys::IdentifierList::Default, &mut rng).unwrap();
    let group_key = *old_pubkeys.verifying_key();

    let old_key_packages: BTreeMap<u32, keys::KeyPackage> = (1..=5u32)
        .map(|i| (i, keys::KeyPackage::try_from(old_shares[&id(i)].clone()).unwrap()))
        .collect();
    zf_sign(&[1, 3, 5], &old_key_packages, &old_pubkeys, b"epoch 1 works");

    // --- Reshare into epoch 2: 6 members, t=3, dealer set S = {2, 4, 5} -------
    let new_n = 6u32;
    let new_t = 3u32;
    let dealer_set = [2u32, 4, 5];

    let dealers: BTreeMap<u32, Dealer<P>> = dealer_set
        .iter()
        .map(|&i| {
            let s = zf_share_to_scalar(&old_shares[&id(i)]);
            (i, Dealer::new(i, s, new_t, &mut rng).unwrap())
        })
        .collect();

    let group_key_point = P::decompress(&group_key.serialize().unwrap()).unwrap();

    let mut new_key_packages = BTreeMap::new();
    let mut polys = Vec::new();
    for j in 1..=new_n {
        let mut agg: Aggregator<P> = Aggregator::new(j, &dealer_set).unwrap();
        for (&i, dealer) in &dealers {
            assert!(agg
                .add_subshare(dealer.generate_subshare(j).unwrap(), dealer.commitment().clone())
                .unwrap());
            let _ = i;
        }
        let (share, poly) = agg.finalize(&group_key_point).unwrap();
        new_key_packages.insert(j, rebuild_key_package(j, &share, &poly, &group_key, new_t as u16));
        polys.push(poly);
    }
    // every member derived the same public polynomial
    assert!(polys.iter().all(|p| p == &polys[0]));
    let new_pubkeys = rebuild_public_package(new_n, &polys[0], &group_key);
    assert_eq!(new_pubkeys.verifying_key(), &group_key, "group key invariant");

    // --- Epoch 2 signs under the SAME group key, with members that did not exist in epoch 1
    zf_sign(&[1, 4, 6], &new_key_packages, &new_pubkeys, b"epoch 2 signs with the old key");
    zf_sign(&[2, 3, 5, 6], &new_key_packages, &new_pubkeys, b"any t-or-more subset");

    // --- Epochs do not mix: an epoch-1 share among epoch-2 signers fails aggregation
    let mut mixed = new_key_packages.clone();
    mixed.insert(3, old_key_packages[&3].clone());
    let mut nonces = BTreeMap::new();
    let mut commitments = BTreeMap::new();
    for &j in &[1u32, 3, 6] {
        let (n, c) = round1::commit(mixed[&j].signing_share(), &mut rng);
        nonces.insert(j, n);
        commitments.insert(id(j), c);
    }
    let package = zf::SigningPackage::new(commitments, b"mixed epochs");
    let params = zf::RandomizedParams::new(&group_key, &package, &mut rng).unwrap();
    let mut shares = BTreeMap::new();
    for &j in &[1u32, 3, 6] {
        shares.insert(
            id(j),
            round2::sign(&package, &nonces[&j], &mixed[&j], *params.randomizer()).unwrap(),
        );
    }
    let err = zf::aggregate(&package, &shares, &new_pubkeys, &params).unwrap_err();
    // identifiable abort: ZF names the share that does not verify against its verifying share
    assert!(
        matches!(err, zf::Error::InvalidSignatureShare { culprit } if culprit == id(3)),
        "expected member 3 to be blamed, got {err:?}"
    );
}
