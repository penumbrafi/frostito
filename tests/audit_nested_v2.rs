//! Audit PoCs — `osst::nested` v2 (SECURITY-REVIEW-2026-09.md, findings N-1..N-4).
//!
//! These are adversarial demonstrations, not regression tests. Each is
//! `#[ignore]`d with the finding it demonstrates so CI stays green while the
//! PoC is preserved. Run them with `cargo test -- --ignored`.
//!
//! No fixes are applied anywhere in `src/`; these only read the public API.

#![cfg(all(feature = "ristretto255", feature = "std"))]

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use osst::curve::{OsstPoint, OsstScalar};
use osst::frost::{self, SigningCommitments};
use osst::nested::{
    aggregate_inner_commitment_pair, aggregate_inner_shares_verified, inner_commit, inner_sign_v2,
    InnerSigningParamsV2,
};
use osst::{compute_lagrange_coefficients, SecretShare};
use rand::rngs::OsRng;

type Point = RistrettoPoint;

/// Shamir-split `secret` into `n` shares with threshold `t`.
fn split(secret: &Scalar, n: u32, t: u32, rng: &mut OsRng) -> Vec<SecretShare<Scalar>> {
    let mut coeffs = vec![*secret];
    for _ in 1..t {
        coeffs.push(<Scalar as OsstScalar>::random(rng));
    }
    (1..=n)
        .map(|i| {
            let x = <Scalar as OsstScalar>::from_u32(i);
            let mut y = <Scalar as OsstScalar>::zero();
            let mut xp = <Scalar as OsstScalar>::one();
            for c in &coeffs {
                y = y.add(&c.mul(&xp));
                xp = xp.mul(&x);
            }
            SecretShare::new(i, y)
        })
        .collect()
}

/// Build the whole outer 2-of-2 world used by the PoCs below.
///
/// Position 1 is an ordinary signer. Position 2 is the nested position, whose
/// outer share sigma_2 is split 3-of-5 among inner holders {1,2,3}.
struct World {
    group_pubkey: Point,
    share_1: SecretShare<Scalar>,
    inner_shares: Vec<SecretShare<Scalar>>,
    quorum: Vec<u32>,
}

fn world(rng: &mut OsRng) -> World {
    let secret = <Scalar as OsstScalar>::random(rng);
    let a1 = <Scalar as OsstScalar>::random(rng);
    let eval = |x: u32| {
        let xs = <Scalar as OsstScalar>::from_u32(x);
        secret.add(&a1.mul(&xs))
    };
    let group_pubkey = <Point as OsstPoint>::generator().mul_scalar(&secret);
    let sigma_2 = eval(2);
    let pieces = split(&sigma_2, 5, 3, rng);
    World {
        group_pubkey,
        share_1: SecretShare::new(1, eval(1)),
        inner_shares: pieces[..3].to_vec(),
        quorum: vec![1, 2, 3],
    }
}

/// N-1 (High) — a malicious coordinator obtains a valid signature on a message
/// the inner group never authorised.
///
/// `inner_sign_v2` takes three scalars and an index list. It takes no message,
/// no `SigningPackage`, and no group public key, so an inner holder has no
/// input from which it could tell which message its share authorises. The
/// coordinator derives the outer context honestly — with `from_outer`, exactly
/// as documented — but for a message of its own choosing.
///
/// Here the jury believes it is authorising `APPROVED`; the coordinator obtains
/// a signature over `UNAPPROVED` that verifies under the group key.
#[test]
#[ignore = "N-1: demonstrates that inner_sign_v2 binds the holder to no message"]
fn coordinator_swaps_the_message_under_the_inner_group() {
    let mut rng = OsRng;
    let w = world(&mut rng);

    const APPROVED: &[u8] = b"release 10 ZEC to alice";
    const UNAPPROVED: &[u8] = b"release 10000 ZEC to mallory";

    // Inner round: the holders commit. Nothing here mentions a message, so the
    // holders have not yet seen (and will never see) what they are signing.
    let mut nonces = Vec::new();
    let mut commitments = Vec::new();
    for &k in &w.quorum {
        let (n, c) = inner_commit::<Point, _>(k, &mut rng);
        nonces.push(n);
        commitments.push(c);
    }
    let (d_nested, e_nested) = aggregate_inner_commitment_pair::<Point>(&commitments);

    // The coordinator is the other outer signer. It builds an outer package
    // over UNAPPROVED, using the jury's real commitment pair.
    let (nonces_1, commits_1) = frost::commit::<Point, _>(1, &mut rng);
    let commits_2 = SigningCommitments {
        index: 2,
        hiding: d_nested,
        binding: e_nested,
    };
    let evil_package =
        frost::SigningPackage::<Point>::new(UNAPPROVED.to_vec(), vec![commits_1, commits_2])
            .unwrap();

    // Derived honestly — `from_outer` is doing exactly what it promises. The
    // trust it moves is from "three scalars" to "this package", and the holder
    // has no independent handle on the package either.
    let params =
        InnerSigningParamsV2::from_outer::<Point>(&evil_package, &w.group_pubkey, 2).unwrap();

    let mut sigs = Vec::new();
    for (n, s) in nonces.into_iter().zip(w.inner_shares.iter()) {
        sigs.push(inner_sign_v2::<Point>(n, s, &params, &w.quorum).unwrap());
    }

    // Every inner share verifies against the coordinator's own params, so the
    // per-share verification in `aggregate_inner_shares_verified` raises nothing.
    let public_shares: Vec<(u32, Point)> = w
        .inner_shares
        .iter()
        .map(|s| (s.index, <Point as OsstPoint>::generator().mul_scalar(s.scalar())))
        .collect();
    let z_nested = aggregate_inner_shares_verified::<Point>(
        &sigs,
        &commitments,
        &public_shares,
        &params,
        &w.quorum,
    )
    .expect("the inner group's own checks do not notice the swapped message");

    let sig_1 = frost::sign::<Point>(&evil_package, nonces_1, &w.share_1, &w.group_pubkey).unwrap();
    let sig_2 = frost::SignatureShare {
        index: 2,
        response: z_nested,
    };
    let signature =
        frost::aggregate::<Point>(&evil_package, &[sig_1, sig_2], &w.group_pubkey, None).unwrap();

    assert!(
        frost::verify_signature::<Point>(&w.group_pubkey, UNAPPROVED, &signature),
        "the unapproved message is signed"
    );
    assert!(
        !frost::verify_signature::<Point>(&w.group_pubkey, APPROVED, &signature),
        "and the approved one is not"
    );
}

/// N-2 (Medium) — the nested position's own commitment pair in the outer
/// package is never checked against the inner commitment round.
///
/// A holder that calls `from_outer` derives rho over whatever commitment set
/// the coordinator supplies, including a nested entry that is not `Sum D_k`.
/// There is no API — no `verify_nested_commitment(package, index, commitments)`
/// — with which a holder could detect the substitution, and the per-share check
/// cannot: it verifies against the same substituted params.
///
/// The consequence is not a forgery (rho moves with the substitution, so the
/// aggregate is simply wrong) but it is a silent, unattributable failure and it
/// lets a coordinator drive holders through rounds whose commitment set they
/// never agreed to.
#[test]
#[ignore = "N-2: no API lets an inner holder bind the outer package to its own commitment round"]
fn substituted_nested_commitment_is_undetectable_by_the_holder() {
    let mut rng = OsRng;
    let w = world(&mut rng);
    let msg = b"settlement";

    let mut nonces = Vec::new();
    let mut commitments = Vec::new();
    for &k in &w.quorum {
        let (n, c) = inner_commit::<Point, _>(k, &mut rng);
        nonces.push(n);
        commitments.push(c);
    }
    let (d_nested, e_nested) = aggregate_inner_commitment_pair::<Point>(&commitments);

    // The coordinator publishes a DIFFERENT pair for position 2.
    let (_, foreign) = frost::commit::<Point, _>(2, &mut rng);
    assert_ne!(foreign.hiding, d_nested);
    assert_ne!(foreign.binding, e_nested);

    let (_, commits_1) = frost::commit::<Point, _>(1, &mut rng);
    let package =
        frost::SigningPackage::<Point>::new(msg.to_vec(), vec![commits_1, foreign]).unwrap();

    // The holder's only "independent verification" path accepts it without a murmur.
    let params = InnerSigningParamsV2::from_outer::<Point>(&package, &w.group_pubkey, 2)
        .expect("from_outer has no way to notice the substitution");

    let mut sigs = Vec::new();
    for (n, s) in nonces.into_iter().zip(w.inner_shares.iter()) {
        sigs.push(inner_sign_v2::<Point>(n, s, &params, &w.quorum).unwrap());
    }
    let public_shares: Vec<(u32, Point)> = w
        .inner_shares
        .iter()
        .map(|s| (s.index, <Point as OsstPoint>::generator().mul_scalar(s.scalar())))
        .collect();

    // Every share verifies. The corruption is invisible at the inner layer.
    assert!(
        aggregate_inner_shares_verified::<Point>(
            &sigs,
            &commitments,
            &public_shares,
            &params,
            &w.quorum,
        )
        .is_ok(),
        "inner verification passes against the substituted context"
    );
}

/// N-3 (Low) — `aggregate_inner_shares_verified` returns `Ok` for a quorum that
/// is not covered.
///
/// It iterates over the shares it was given and never checks that every index in
/// `active_indices` produced one. Two of three holders' shares therefore
/// aggregate to a scalar that is silently not the nested position's response,
/// reported as success. Duplicate `holder_index` values are double-counted the
/// same way.
#[test]
#[ignore = "N-3: aggregate_inner_shares_verified does not require quorum coverage"]
fn incomplete_quorum_aggregates_as_success() {
    let mut rng = OsRng;
    let w = world(&mut rng);

    let mut nonces = Vec::new();
    let mut commitments = Vec::new();
    for &k in &w.quorum {
        let (n, c) = inner_commit::<Point, _>(k, &mut rng);
        nonces.push(n);
        commitments.push(c);
    }

    let params = InnerSigningParamsV2 {
        outer_binding: <Scalar as OsstScalar>::random(&mut rng),
        outer_challenge: <Scalar as OsstScalar>::random(&mut rng),
        outer_lambda: <Scalar as OsstScalar>::random(&mut rng),
    };

    let mut sigs = Vec::new();
    for (n, s) in nonces.into_iter().zip(w.inner_shares.iter()) {
        sigs.push(inner_sign_v2::<Point>(n, s, &params, &w.quorum).unwrap());
    }
    let public_shares: Vec<(u32, Point)> = w
        .inner_shares
        .iter()
        .map(|s| (s.index, <Point as OsstPoint>::generator().mul_scalar(s.scalar())))
        .collect();

    // Drop holder 3 entirely. active_indices still says the quorum is {1,2,3}.
    let short = &sigs[..2];
    let z = aggregate_inner_shares_verified::<Point>(
        short,
        &commitments,
        &public_shares,
        &params,
        &w.quorum,
    );
    assert!(
        z.is_ok(),
        "a 2-of-3 subset of a 3-quorum is reported as a complete aggregation"
    );
}

/// N-4 (Info) — the v2 equivalence claim holds on honest inputs.
///
/// This one is NOT ignored: it is the positive result. A nested position's
/// response is bit-for-bit what a flat FROST signer holding sigma_2 with nonces
/// (Sum d_k, Sum e_k) produces, which is what lets v2's security reduce to
/// FROST's own proof rather than a novel composition argument. The in-crate
/// `nested_v2_equals_flat_frost` asserts the same thing; this re-asserts it
/// from outside the crate, against the public API only.
#[test]
fn v2_response_equals_the_flat_frost_response() {
    let mut rng = OsRng;
    let secret = <Scalar as OsstScalar>::random(&mut rng);
    let a1 = <Scalar as OsstScalar>::random(&mut rng);
    let eval = |x: u32| {
        let xs = <Scalar as OsstScalar>::from_u32(x);
        secret.add(&a1.mul(&xs))
    };
    let group_pubkey = <Point as OsstPoint>::generator().mul_scalar(&secret);
    let sigma_2 = eval(2);
    let pieces = split(&sigma_2, 5, 3, &mut rng);
    let quorum = vec![1u32, 2, 3];
    let inner: Vec<SecretShare<Scalar>> = pieces[..3].to_vec();

    let mut nonces = Vec::new();
    let mut commitments = Vec::new();
    for &k in &quorum {
        let (n, c) = inner_commit::<Point, _>(k, &mut rng);
        nonces.push(n);
        commitments.push(c);
    }
    let (d_nested, e_nested) = aggregate_inner_commitment_pair::<Point>(&commitments);

    let (_, commits_1) = frost::commit::<Point, _>(1, &mut rng);
    let commits_2 = SigningCommitments {
        index: 2,
        hiding: d_nested,
        binding: e_nested,
    };
    let package = frost::SigningPackage::<Point>::new(b"m".to_vec(), vec![commits_1, commits_2])
        .unwrap();
    let params = InnerSigningParamsV2::from_outer::<Point>(&package, &group_pubkey, 2).unwrap();

    let mut sigs = Vec::new();
    for (n, s) in nonces.into_iter().zip(inner.iter()) {
        sigs.push(inner_sign_v2::<Point>(n, s, &params, &quorum).unwrap());
    }
    let mut z_nested = <Scalar as OsstScalar>::zero();
    for s in &sigs {
        z_nested = z_nested.add(&s.response);
    }

    // The inner quorum's shares interpolate to sigma_2, so the response must
    // equal d + rho*e + lambda*c*sigma_2 for the aggregate nonce (d, e). We do
    // not have (d, e) as scalars here, so check the group-element identity
    // instead: z*G == D_nested + rho*E_nested + lambda*c*(sigma_2*G).
    let lhs = <Point as OsstPoint>::generator().mul_scalar(&z_nested);
    let w = params.outer_lambda.mul(&params.outer_challenge);
    let rhs = d_nested
        .add(&e_nested.mul_scalar(&params.outer_binding))
        .add(&<Point as OsstPoint>::generator().mul_scalar(&sigma_2).mul_scalar(&w));
    assert_eq!(lhs, rhs, "nested response is the flat FROST response");

    // Sanity: the inner quorum really does reconstruct sigma_2.
    let lag = compute_lagrange_coefficients::<Scalar>(&quorum).unwrap();
    let mut recon = <Scalar as OsstScalar>::zero();
    for (i, s) in inner.iter().enumerate() {
        recon = recon.add(&lag[i].mul(s.scalar()));
    }
    assert_eq!(recon, sigma_2);
}
