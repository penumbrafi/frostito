//! FROST(decaf377, SHA-512) end to end through ZF `frost-core`.
//!
//! `frostito::zf::Decaf377Sha512` exists so the decaf377 backend can use the
//! audited signing core like the other three, which ZF already ships
//! ciphersuites for. This exercises the whole path — trusted-dealer keygen,
//! commit, sign, aggregate, verify — entirely inside `frost-core`, with this
//! crate supplying only the ciphersuite.

#![cfg(feature = "decaf377")]

use std::collections::BTreeMap;

use frost_core::{
 aggregate,
 keys::{self, IdentifierList, KeyPackage, PublicKeyPackage},
 round1, round2, Identifier, SigningPackage,
};
use frostito::zf::Decaf377Sha512 as C;
use rand::rngs::OsRng;

const MSG: &[u8] = b"decaf377 through frost-core";

fn dealt(t: u16, n: u16) -> (BTreeMap<Identifier<C>, KeyPackage<C>>, PublicKeyPackage<C>) {
 let mut rng = OsRng;
 let (shares, pubkeys) =
 keys::generate_with_dealer::<C, _>(n, t, IdentifierList::Default, &mut rng)
 .expect("dealer keygen");

 let packages = shares
 .into_iter()
 .map(|(id, share)| (id, KeyPackage::try_from(share).expect("key package")))
 .collect();

 (packages, pubkeys)
}

#[test]
fn threshold_signing_round_trips() {
 let mut rng = OsRng;
 let (packages, pubkeys) = dealt(2, 3);

 // Round 1 — the first two holders commit.
 let signers: Vec<_> = packages.keys().copied().take(2).collect();
 let mut nonces = BTreeMap::new();
 let mut commitments = BTreeMap::new();
 for id in &signers {
 let (n, c) = round1::commit(packages[id].signing_share(), &mut rng);
 nonces.insert(*id, n);
 commitments.insert(*id, c);
 }

 // Round 2 — each produces a signature share over the same package.
 let package = SigningPackage::new(commitments, MSG);
 let shares: BTreeMap<_, _> = signers
 .iter()
 .map(|id| {
 let s = round2::sign(&package, &nonces[id], &packages[id]).expect("sign");
 (*id, s)
 })
 .collect();

 let signature = aggregate(&package, &shares, &pubkeys).expect("aggregate");

 assert!(
 pubkeys.verifying_key().verify(MSG, &signature).is_ok(),
 "aggregated signature must verify under the group key"
 );
}

#[test]
fn signature_does_not_verify_under_a_different_message() {
 let mut rng = OsRng;
 let (packages, pubkeys) = dealt(2, 3);

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
 .map(|id| (*id, round2::sign(&package, &nonces[id], &packages[id]).unwrap()))
 .collect();

 let signature = aggregate(&package, &shares, &pubkeys).unwrap();

 assert!(
 pubkeys.verifying_key().verify(b"a different message", &signature).is_err(),
 "the challenge binds the message"
 );
}

/// Fewer than `t` commitments is refused at signing time, not at verification.
#[test]
fn one_of_two_is_refused_before_a_share_exists() {
 let mut rng = OsRng;
 let (packages, _pubkeys) = dealt(2, 3);

 let id = *packages.keys().next().unwrap();
 let (nonce, commitment) = round1::commit(packages[&id].signing_share(), &mut rng);

 // A package carrying one commitment for a 2-of-3 group.
 let package = SigningPackage::new(BTreeMap::from([(id, commitment)]), MSG);

 assert!(
 matches!(
 round2::sign(&package, &nonce, &packages[&id]),
 Err(frost_core::Error::IncorrectNumberOfCommitments)
 ),
 "a holder must not produce a share against an under-threshold package"
 );
}

// ============================================================================
// DKG through frost-core, with the seams this crate's layer plugs into
// ============================================================================

/// Full ZF DKG on decaf377, then signing with the resulting key packages.
///
/// The two seams that matter for keeping this crate's DKG hardening:
///
/// - **echo round.** `round1::Package` serializes, so every participant can
///   digest the same round-1 set and compare — the `AgreedRound1` /
///   `EchoDigest` construction, over ZF's packages instead of ours.
/// - **sealed round 2.** `round2::Package` also serializes, and frost-core
///   requires the caller to deliver it over a confidential, authenticated
///   channel. That is exactly what `frostito::sealed` is for. Here the bytes
///   round-trip in the clear, standing in for that transport.
#[test]
fn dkg_round_trips_and_the_key_signs() {
 use frost_core::keys::dkg;
 use sha2::{Digest, Sha512};

 let mut rng = OsRng;
 let (max, min) = (3u16, 2u16);
 let ids: Vec<Identifier<C>> = (1..=max).map(|i| i.try_into().unwrap()).collect();

 // --- round 1 -----------------------------------------------------------
 let mut r1_secret = BTreeMap::new();
 let mut r1_public = BTreeMap::new();
 for id in &ids {
 let (secret, package) = dkg::part1::<C, _>(*id, max, min, &mut rng).expect("part1");
 r1_secret.insert(*id, secret);
 r1_public.insert(*id, package);
 }

 // --- echo round: every participant digests the same round-1 set --------
 let digest = |set: &BTreeMap<Identifier<C>, dkg::round1::Package<C>>| {
 let mut h = Sha512::new();
 h.update(b"frostito/dkg-round1-echo/zf");
 for (id, pkg) in set {
 h.update(id.serialize());
 h.update(pkg.serialize().expect("round1 package serializes"));
 }
 h.finalize().to_vec()
 };
 let mine = digest(&r1_public);
 for _ in &ids {
 assert_eq!(mine, digest(&r1_public), "every honest view must agree");
 }

 // --- round 2: packages travel as bytes (sealed, in a deployment) -------
 let mut inbox: BTreeMap<Identifier<C>, BTreeMap<Identifier<C>, dkg::round2::Package<C>>> =
 ids.iter().map(|id| (*id, BTreeMap::new())).collect();
 let mut r2_secret = BTreeMap::new();

 for id in &ids {
 let others: BTreeMap<_, _> = r1_public
 .iter()
 .filter(|(k, _)| *k != id)
 .map(|(k, v)| (*k, v.clone()))
 .collect();
 let (secret, outgoing) =
 dkg::part2(r1_secret.remove(id).unwrap(), &others).expect("part2");
 r2_secret.insert(*id, secret);

 for (recipient, package) in outgoing {
 // The confidentiality boundary: these bytes carry secret key
 // material and must not travel in the clear.
 let wire = package.serialize().expect("round2 package serializes");
 let opened = dkg::round2::Package::<C>::deserialize(&wire).expect("reopens");
 inbox.get_mut(&recipient).unwrap().insert(*id, opened);
 }
 }

 // --- round 3 -----------------------------------------------------------
 let mut packages = BTreeMap::new();
 let mut group_key = None;
 for id in &ids {
 let others: BTreeMap<_, _> = r1_public
 .iter()
 .filter(|(k, _)| *k != id)
 .map(|(k, v)| (*k, v.clone()))
 .collect();
 let (key_package, pubkeys) =
 dkg::part3(&r2_secret[id], &others, &inbox[id]).expect("part3");

 match &group_key {
 None => group_key = Some(pubkeys),
 Some(prev) => assert_eq!(
 prev.verifying_key(),
 pubkeys.verifying_key(),
 "every participant must land on the same group key"
 ),
 }
 packages.insert(*id, key_package);
 }
 let pubkeys = group_key.unwrap();

 // --- the DKG key signs -------------------------------------------------
 let signers: Vec<_> = ids.iter().copied().take(2).collect();
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
 .map(|id| (*id, round2::sign(&package, &nonces[id], &packages[id]).unwrap()))
 .collect();
 let signature = aggregate(&package, &shares, &pubkeys).expect("aggregate");

 assert!(pubkeys.verifying_key().verify(MSG, &signature).is_ok());
}
