//! Audit regression tests — flat `osst::frost`, `osst::liveness`, and hash
//! domain separation (SECURITY-REVIEW-2026-09.md, findings F-1, L-1, H-1,
//! P-1).
//!
//! These were `#[ignore]`d PoCs asserting the break. Each now performs the
//! same attack and asserts that it fails; none is ignored.

#![cfg(all(feature = "ristretto255", feature = "std"))]

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use osst::curve::{OsstPoint, OsstScalar};
use osst::frost;
use osst::liveness::{CheckpointAnchor, DealerContribution, LivenessProof};
use osst::reshare::Dealer;
use osst::SecretShare;
use rand::rngs::OsRng;

type Point = RistrettoPoint;

/// F-1 (Low, FIXED) — `frost::sign` checks that the commitment the package
/// carries under this signer's index is the one derived from the nonces it is
/// about to consume.
///
/// Until 0.4.0 osst only checked that the index was present, so a coordinator
/// chose the binding factor an honest signer applied to its own binding nonce
/// while holding the hiding nonce fixed. One session is one equation in three
/// unknowns, so it was not by itself an extraction; it became one for any
/// signer whose nonce state survived a process restart. ZF `frost-core`
/// rejects this as `Error::IncorrectCommitment`.
#[test]
fn sign_rejects_a_foreign_commitment_for_its_own_index() {
    let mut rng = OsRng;

    let secret = <Scalar as OsstScalar>::random(&mut rng);
    let a1 = <Scalar as OsstScalar>::random(&mut rng);
    let eval = |x: u32| {
        let xs = <Scalar as OsstScalar>::from_u32(x);
        secret.add(&a1.mul(&xs))
    };
    let group_pubkey = <Point as OsstPoint>::generator().mul_scalar(&secret);

    // Signer 1 commits honestly.
    let (nonces_1, my_commitment) = frost::commit::<Point, _>(1, &mut rng).unwrap();
    // The coordinator publishes a commitment for index 1 that signer 1 did not make.
    let (_, foreign_for_1) = frost::commit::<Point, _>(1, &mut rng).unwrap();
    let (_, commits_2) = frost::commit::<Point, _>(2, &mut rng).unwrap();

    let share_1 = SecretShare::new(1, eval(1)).unwrap();

    let package = frost::SigningPackage::<Point>::new(
        b"m".to_vec(),
        vec![foreign_for_1, commits_2.clone()],
    )
    .unwrap();
    assert_eq!(
        frost::sign::<Point>(&package, nonces_1, &share_1, &group_pubkey).unwrap_err(),
        osst::OsstError::UnexpectedCommitment,
        "sign() must reject a package whose commitment for this signer is not its own"
    );

    // The honest package still signs.
    let (nonces_1, my_commitment2) = frost::commit::<Point, _>(1, &mut rng).unwrap();
    let _ = my_commitment;
    let package =
        frost::SigningPackage::<Point>::new(b"m".to_vec(), vec![my_commitment2, commits_2]).unwrap();
    assert!(frost::sign::<Point>(&package, nonces_1, &share_1, &group_pubkey).is_ok());
}

/// L-1 (Medium, FIXED) — the liveness contribution signature binds the public
/// key, so it is no longer malleable in the key.
///
/// The challenge is now
/// `e = H("osst/liveness-sig/v1" || R || Y || message)`. Verification is
/// `g^s == R + e*Y`; because `e` moves with `Y`, the shift that used to carry
/// a signature onto a related key — `(R, s) -> (R, s + e*delta)` under
/// `Y + delta*G` — no longer verifies. RFC 8032 and BIP340 bind the key for
/// exactly this reason.
#[test]
fn liveness_signature_does_not_transfer_to_a_related_key() {
    let mut rng = OsRng;

    let sk = <Scalar as OsstScalar>::random(&mut rng);
    let pk = <Point as OsstPoint>::generator().mul_scalar(&sk);

    let dealer: Dealer<Point> = Dealer::new(1, <Scalar as OsstScalar>::random(&mut rng), 3, &mut rng).unwrap();
    let anchor = CheckpointAnchor::new(100, [1u8; 32], 0);
    let liveness = LivenessProof::new(anchor, vec![1, 2, 3], [2u8; 32]);
    let context = b"epoch-42";

    let contribution =
        DealerContribution::sign(dealer.commitment().clone(), liveness, &sk, context, &mut rng);
    assert!(contribution.verify_signature(&pk, context));

    let message = DealerContribution::<Point>::signing_message(
        &contribution.commitment,
        &contribution.liveness,
        context,
    );

    // The adversary recomputes e with the CURRENT formula — it is public — and
    // applies the related-key shift that used to work.
    let delta = <Scalar as OsstScalar>::random(&mut rng);
    let pk_shifted = pk.add(&<Point as OsstPoint>::generator().mul_scalar(&delta));
    let e = DealerContribution::<Point>::challenge_hash(&contribution.signature.r, &pk, &message);
    let forged = DealerContribution {
        commitment: contribution.commitment.clone(),
        liveness: contribution.liveness.clone(),
        signature: osst::liveness::ContributionSignature::new(
            contribution.signature.r.clone(),
            contribution.signature.s.add(&e.mul(&delta)),
        ),
    };
    assert!(
        !forged.verify_signature(&pk_shifted, context),
        "a signature must not transfer to a related key"
    );

    // Nor does re-deriving e under the shifted key help: that changes the
    // challenge the forged response would have to satisfy.
    let e_shifted =
        DealerContribution::<Point>::challenge_hash(&contribution.signature.r, &pk_shifted, &message);
    let forged2 = DealerContribution {
        commitment: contribution.commitment.clone(),
        liveness: contribution.liveness.clone(),
        signature: osst::liveness::ContributionSignature::new(
            contribution.signature.r.clone(),
            contribution.signature.s.add(&e_shifted.mul(&delta)),
        ),
    };
    assert!(!forged2.verify_signature(&pk_shifted, context));

    // The honest signature still verifies, and only under its own key.
    assert!(contribution.verify_signature(&pk, context));
    assert!(!contribution.verify_signature(&pk_shifted, context));
}

/// H-1 (Low, FIXED) — the OSST contribution challenge and the liveness
/// signature challenge are now separate hashes.
///
/// They used to be byte-identical (`SHA512(R || m)` both), so a liveness
/// signature over a 64-byte message WAS an OSST contribution over that
/// payload. They now carry `"osst/contribution/v1"` and
/// `"osst/liveness-sig/v1"` respectively, and the liveness one also binds the
/// key.
#[test]
fn osst_and_liveness_challenges_are_domain_separated() {
    use sha2::{Digest, Sha512};

    let mut rng = OsRng;
    let u = <Point as OsstPoint>::generator()
        .mul_scalar(&<Scalar as OsstScalar>::random(&mut rng));
    let y = <Point as OsstPoint>::generator()
        .mul_scalar(&<Scalar as OsstScalar>::random(&mut rng));
    let payload = [7u8; 64];

    let osst_c: Scalar = osst::hash_to_challenge::<Scalar, Point>(&u, &payload);
    let liveness_c = DealerContribution::<Point>::challenge_hash(&u, &y, &payload);
    assert_ne!(
        osst_c, liveness_c,
        "the two protocols must not share a challenge space"
    );

    // And the old, undomained hash is now neither of them.
    let legacy: Scalar = {
        let mut h = Sha512::new();
        h.update(OsstPoint::compress(&u));
        h.update(payload);
        let full: [u8; 64] = h.finalize().into();
        <Scalar as OsstScalar>::from_bytes_wide(&full)
    };
    assert_ne!(legacy, osst_c);
    assert_ne!(legacy, liveness_c);
}

/// P-1 (Low, FIXED) — adversarial indices and thresholds error rather than
/// panicking.
///
/// Several constructors used `assert!` on caller input. In a node that parses
/// indices off the wire — which `narsild` does — an index of 0 from a peer
/// aborted the process. They now return `OsstError`.
#[test]
fn wire_parsed_indices_error_rather_than_aborting_the_process() {
    use osst::OsstError;
    let mut rng = OsRng;

    assert_eq!(
        SecretShare::new(0, <Scalar as OsstScalar>::zero()).unwrap_err(),
        OsstError::InvalidIndex
    );
    assert_eq!(
        frost::commit::<Point, _>(0, &mut rng).unwrap_err(),
        OsstError::InvalidIndex
    );
    assert_eq!(
        osst::dkg::Dealer::<Point>::new(0, 3, &mut rng).unwrap_err(),
        OsstError::InvalidIndex
    );
    assert_eq!(
        osst::dkg::Dealer::<Point>::new(1, 0, &mut rng).unwrap_err(),
        OsstError::ThresholdMismatch {
            expected: 1,
            got: 0
        }
    );
    assert_eq!(
        Dealer::<Point>::new(0, <Scalar as OsstScalar>::zero(), 3, &mut rng).unwrap_err(),
        OsstError::InvalidIndex
    );

    let dealer = osst::dkg::Dealer::<Point>::new(1, 2, &mut rng).unwrap();
    assert_eq!(
        dealer.generate_subshare(0).unwrap_err(),
        OsstError::InvalidIndex
    );
    assert_eq!(
        dealer.commitment().evaluate_at(0).unwrap_err(),
        OsstError::InvalidIndex
    );
    assert_eq!(
        osst::reshare::DealerCommitment::<Point>::from_polynomial(1, &[]).unwrap_err(),
        OsstError::EmptyContributions
    );
    assert_eq!(
        osst::reshare::SubShare::new(0, 1, <Scalar as OsstScalar>::zero()).unwrap_err(),
        OsstError::InvalidIndex
    );
}

/// M-24 (A-2, FIXED) — the binding factor now includes the group public key,
/// as RFC 9591 §4.4 does.
///
/// Through 0.4.x one commitment set and one message gave the same ρ under
/// every group key, so a signing transcript was not pinned to the key it was
/// collected for. That is exactly the freedom M-4 hands a coordinator which
/// also gets to assert `Y`: with ρ independent of `Y`, only the challenge
/// moved when the key was substituted. Now both move.
#[test]
fn the_binding_factor_depends_on_the_group_public_key() {
    let mut rng = OsRng;
    let g = <Point as OsstPoint>::generator();
    let (_, commitments) = frost::commit::<Point, _>(1, &mut rng).unwrap();
    let package = frost::SigningPackage::<Point>::new(b"m".to_vec(), vec![commitments]).unwrap();

    let y1 = g.mul_scalar(&Scalar::random(&mut rng));
    let y2 = g.mul_scalar(&Scalar::random(&mut rng));

    assert_ne!(
        package.binding_factor(1, &y1),
        package.binding_factor(1, &y2),
        "substituting the group key must move the binding factor, not only the challenge"
    );
    assert_ne!(
        package.group_commitment(&y1),
        package.group_commitment(&y2),
        "and therefore the group commitment too"
    );
    assert_eq!(
        package.binding_factor(1, &y1),
        package.binding_factor(1, &y1),
        "and it is still deterministic in its inputs"
    );
}
