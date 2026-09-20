//! Audit PoCs — flat `osst::frost`, `osst::liveness`, and hash domain
//! separation (SECURITY-REVIEW-2026-09.md, findings F-1, L-1, H-1, P-1).

#![cfg(all(feature = "ristretto255", feature = "std"))]

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use osst::curve::{OsstPoint, OsstScalar};
use osst::frost;
use osst::liveness::{CheckpointAnchor, DealerContribution, LivenessProof};
use osst::reshare::Dealer;
use osst::SecretShare;
use rand::rngs::OsRng;

type Point = RistrettoPoint;

/// F-1 (Low) — `frost::sign` never checks that the commitment the package
/// carries under this signer's index is the one derived from the nonces it is
/// about to consume.
///
/// ZF `frost-core` rejects this (`Error::IncorrectCommitment`); osst only checks
/// that the index is present. The effect is that a coordinator chooses the
/// binding factor an honest signer applies to its own binding nonce, with the
/// hiding nonce held fixed. One session yields one equation in three unknowns,
/// so this is not by itself an extraction; it becomes one for any signer whose
/// nonce state survives a process restart (the crate documents that as the
/// caller's problem) and it removes a cheap, standard invariant.
#[test]
#[ignore = "F-1: frost::sign accepts a package carrying a foreign commitment under the signer's own index"]
fn sign_accepts_a_foreign_commitment_for_its_own_index() {
    let mut rng = OsRng;

    let secret = <Scalar as OsstScalar>::random(&mut rng);
    let a1 = <Scalar as OsstScalar>::random(&mut rng);
    let eval = |x: u32| {
        let xs = <Scalar as OsstScalar>::from_u32(x);
        secret.add(&a1.mul(&xs))
    };
    let group_pubkey = <Point as OsstPoint>::generator().mul_scalar(&secret);

    // Signer 1 commits honestly.
    let (nonces_1, _my_commitment) = frost::commit::<Point, _>(1, &mut rng);
    // The coordinator publishes a commitment for index 1 that signer 1 did not make.
    let (_, foreign_for_1) = frost::commit::<Point, _>(1, &mut rng);
    let (_, commits_2) = frost::commit::<Point, _>(2, &mut rng);

    let package =
        frost::SigningPackage::<Point>::new(b"m".to_vec(), vec![foreign_for_1, commits_2]).unwrap();

    let share_1 = SecretShare::new(1, eval(1));
    let result = frost::sign::<Point>(&package, nonces_1, &share_1, &group_pubkey);

    // Desired behaviour: Err. Actual: Ok, with rho chosen by the coordinator.
    assert!(
        result.is_err(),
        "sign() should reject a package whose commitment for this signer is not its own"
    );
}

/// L-1 (Medium) — the liveness contribution signature omits the public key from
/// the challenge, so it is malleable in the key.
///
/// `challenge_hash(R, m) = SHA512(R || m)` has no key prefix and no domain tag.
/// Verification is `g^s == R + e*Y`. Because `e` does not depend on `Y`, a
/// signature `(R, s)` valid under `Y` transforms into `(R, s + e*delta)` valid
/// under `Y + delta*G` for any `delta` the adversary picks, over the SAME
/// message. Any registry that admits a public key without a proof of possession
/// therefore admits a party that can exhibit valid liveness contributions for a
/// key nobody controls, derived from someone else's.
///
/// RFC 8032 and BIP340 both bind the key into the challenge for exactly this
/// reason.
#[test]
#[ignore = "L-1: liveness signature challenge omits the public key (related-key malleability)"]
fn liveness_signature_is_malleable_in_the_public_key() {
    let mut rng = OsRng;

    let sk = <Scalar as OsstScalar>::random(&mut rng);
    let pk = <Point as OsstPoint>::generator().mul_scalar(&sk);

    let dealer: Dealer<Point> = Dealer::new(1, <Scalar as OsstScalar>::random(&mut rng), 3, &mut rng);
    let anchor = CheckpointAnchor::new(100, [1u8; 32], 0);
    let liveness = LivenessProof::new(anchor, vec![1, 2, 3], [2u8; 32]);
    let context = b"epoch-42";

    let contribution =
        DealerContribution::sign(dealer.commitment().clone(), liveness, &sk, context, &mut rng);
    assert!(contribution.verify_signature(&pk, context));

    // e is recomputable by anyone: it depends only on (R, message).
    let message = DealerContribution::<Point>::signing_message(
        &contribution.commitment,
        &contribution.liveness,
        context,
    );
    let e = {
        use sha2::{Digest, Sha512};
        let mut h = Sha512::new();
        h.update(OsstPoint::compress(&contribution.signature.r));
        h.update(message);
        let full: [u8; 64] = h.finalize().into();
        <Scalar as OsstScalar>::from_bytes_wide(&full)
    };

    // Shift the key by delta and the response by e*delta.
    let delta = <Scalar as OsstScalar>::random(&mut rng);
    let pk_shifted = pk.add(&<Point as OsstPoint>::generator().mul_scalar(&delta));
    let forged = DealerContribution {
        commitment: contribution.commitment.clone(),
        liveness: contribution.liveness.clone(),
        signature: osst::liveness::ContributionSignature::new(
            contribution.signature.r,
            contribution.signature.s.add(&e.mul(&delta)),
        ),
    };

    assert!(
        !forged.verify_signature(&pk_shifted, context),
        "a signature must not transfer to a related key"
    );
}

/// H-1 (Low) — the OSST contribution challenge and the liveness signature
/// challenge are the same unlabelled hash, so the two protocols share a
/// challenge space.
///
/// `osst::hash_to_challenge(u, payload) = SHA512(compress(u) || payload)` and
/// `liveness::challenge_hash(R, m) = SHA512(R || m)` are byte-identical
/// functions. A liveness signature `(R, s)` over a 64-byte message `m` IS an
/// OSST contribution `(u = R, s)` over payload `m`, and vice versa. Nothing in
/// the crate stops the two from being instantiated on the same key; a
/// deployment that signs liveness with a key that is also an OSST share hands
/// over OSST contributions for free.
///
/// Not ignored: it is a true statement about the current code and stays true
/// until a domain tag is added, at which point this test should start failing
/// and be deleted.
#[test]
fn osst_and_liveness_challenges_are_the_same_hash() {
    use sha2::{Digest, Sha512};

    let mut rng = OsRng;
    let u = <Point as OsstPoint>::generator()
        .mul_scalar(&<Scalar as OsstScalar>::random(&mut rng));
    let payload = [7u8; 64];

    let osst_c: Scalar = osst::hash_to_challenge::<Scalar, Point>(&u, &payload);

    let liveness_c: Scalar = {
        let mut h = Sha512::new();
        h.update(OsstPoint::compress(&u)); // this is the `r` field of a ContributionSignature
        h.update(payload); // this is the 64-byte `signing_message`
        let full: [u8; 64] = h.finalize().into();
        <Scalar as OsstScalar>::from_bytes_wide(&full)
    };

    assert_eq!(
        osst_c, liveness_c,
        "OSST and liveness use the same undomained SHA-512 challenge"
    );
}

/// P-1 (Low) — adversarial indices panic rather than erroring.
///
/// Several constructors `assert!` on caller input instead of returning
/// `OsstError::InvalidIndex`. In a node that parses indices off the wire — which
/// `narsild` does — an index of 0 aborts the process. These pass today and
/// document the surface; they should be converted to `Result` returns.
#[test]
#[should_panic(expected = "1-indexed")]
fn secret_share_index_zero_panics() {
    let _ = SecretShare::new(0, <Scalar as OsstScalar>::zero());
}

#[test]
#[should_panic(expected = "1-indexed")]
fn frost_commit_index_zero_panics() {
    let mut rng = OsRng;
    let _ = frost::commit::<Point, _>(0, &mut rng);
}

#[test]
#[should_panic(expected = "threshold must be positive")]
fn dkg_dealer_threshold_zero_panics() {
    let mut rng = OsRng;
    let _: osst::dkg::Dealer<Point> = osst::dkg::Dealer::new(1, 0, &mut rng);
}
