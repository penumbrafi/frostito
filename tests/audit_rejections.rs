//! Audit regression tests — the rejection paths M-23 named as untested.
//!
//! The 0.4.0 suite has the right shape: one un-ignored test per finding,
//! performing the attack and asserting it fails. M-23 of
//! `REVIEW-2026-09-21-maintainer.md` observed that the *negative* half was
//! thin, and listed seven rejection paths with no test in `tests/`. This file
//! completes that list, one module per path, so a reader can see at a glance
//! that each error the crate can return is actually reached by something.
//!
//! Two of the seven turned out to be covered already and are noted where they
//! live rather than duplicated:
//!
//! - the *duplicate* branch of N-3 — `incomplete_quorum_is_rejected` in
//!   `audit_nested_v2.rs` asserts `vec![1, 3]` for a duplicated share
//!   alongside a missing holder, so both branches were covered;
//! - `SessionMismatch` in `aggregate_inner_commitment_pair` as distinct from
//!   in `inner_sign_v2` — `nonces_from_another_session_are_rejected` asserts
//!   both, the second over a mixed commitment set.
//!
//! The rest existed only as `#[cfg(test)]` unit tests inside `src/`, which is
//! where they are exercised but not where the audit suite records them. Each
//! is restated here against the public API, which is the surface a caller
//! actually has.

#![cfg(all(feature = "ristretto255", feature = "std"))]

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use osst::curve::OsstPoint;

use osst::dkg::{Dealer, DkgState};
use osst::OsstError;
use rand::rngs::OsRng;

type Point = RistrettoPoint;

/// (1) `ChallengeMismatch` from `from_coordinator_checked`.
///
/// The legacy wire path recomputes all three scalars and rejects any that
/// differs. Note what this does *not* buy — see
/// `a_substituted_group_key_passes_from_coordinator_checked` in
/// `audit_nested_v2.rs`, which is the other half of M-4.
mod coordinator_supplied_scalars_are_recomputed {
    use super::*;
    use osst::frost::{self, SigningCommitments};
    use osst::nested::InnerSigningParamsV2;

    #[test]
    fn a_wrong_scalar_is_rejected() {
        let mut rng = OsRng;
        let g = <Point as OsstPoint>::generator();
        let y = g.mul_scalar(&Scalar::random(&mut rng));

        let (_, c1) = frost::commit::<Point, _>(1, &mut rng).unwrap();
        let (_, c2) = frost::commit::<Point, _>(2, &mut rng).unwrap();
        let package =
            frost::SigningPackage::<Point>::new(b"m".to_vec(), vec![c1, c2]).unwrap();

        let indices = package.signer_indices();
        let lagrange = osst::compute_lagrange_coefficients::<Scalar>(&indices).unwrap();
        let pos = indices.iter().position(|&i| i == 2).unwrap();
        let r = package.group_commitment(&y);
        let rho = package.binding_factor(2, &y);
        let c = package.challenge(&r, &y);

        // the honest triple is accepted
        #[allow(deprecated)]
        let ok = InnerSigningParamsV2::from_coordinator_checked::<Point>(
            &rho,
            &c,
            &lagrange[pos],
            &package,
            &y,
            2,
        );
        assert!(ok.is_ok());

        // each of the three, perturbed on its own, is rejected
        let wrong = Scalar::random(&mut rng);
        for (a, b, l) in [
            (&wrong, &c, &lagrange[pos]),
            (&rho, &wrong, &lagrange[pos]),
            (&rho, &c, &wrong),
        ] {
            #[allow(deprecated)]
            let got = InnerSigningParamsV2::from_coordinator_checked::<Point>(
                a, b, l, &package, &y, 2,
            );
            assert!(matches!(got, Err(OsstError::ChallengeMismatch)));
        }

        // an index that is not in the package is an index error, not a
        // mismatch — the caller is asking about a signer that does not exist
        #[allow(deprecated)]
        let absent = InnerSigningParamsV2::from_coordinator_checked::<Point>(
            &rho,
            &c,
            &lagrange[pos],
            &package,
            &y,
            7,
        );
        assert!(matches!(absent, Err(OsstError::InvalidIndex)));

        // unused, but keeps the commitment type in scope for readers
        let _ = core::mem::size_of::<SigningCommitments<Point>>();
    }
}

/// (2) `InvalidProofOfKnowledge` from a forged `Round1Package` (K-1).
///
/// A dealer that publishes a constant-term commitment it did not choose — a
/// rogue-key setup — is refused at submission, before the commitment is
/// recorded, so it never reaches the group key.
mod a_forged_round1_package_is_refused {
    use super::*;

    #[test]
    fn the_proof_is_checked_before_the_commitment_is_recorded() {
        let mut rng = OsRng;
        let epoch = 4u64;
        let honest: Dealer<Point> = Dealer::new(1, 2, &mut rng).unwrap();
        let other: Dealer<Point> = Dealer::new(2, 2, &mut rng).unwrap();

        // dealer 2 claims dealer 1's constant term, with its own proof
        let mut forged = other.round1_package(epoch, &mut rng);
        forged.commitment = honest.commitment().clone();
        forged.commitment.dealer_index = 2;

        assert_eq!(
            forged.verify(epoch).unwrap_err(),
            OsstError::InvalidProofOfKnowledge(2),
            "the package is self-checkable, and the error names the dealer"
        );

        let mut state = DkgState::<Point>::new(epoch, 2, 3);
        assert_eq!(
            state.submit_commitment(forged).unwrap_err(),
            OsstError::InvalidProofOfKnowledge(2)
        );
        assert_eq!(state.commitment_count(), 0, "nothing was recorded");

        // an honest package for the same epoch is accepted; a replay of it
        // into another epoch is not (the epoch is in the PoK challenge)
        let good = honest.round1_package(epoch, &mut rng);
        let mut wrong_epoch = DkgState::<Point>::new(epoch + 1, 2, 3);
        assert_eq!(
            wrong_epoch.submit_commitment(good.clone()).unwrap_err(),
            OsstError::InvalidProofOfKnowledge(1)
        );
        assert!(state.submit_commitment(good).unwrap());
    }
}

/// (3) `DkgAborted` when disqualification takes the ceremony below threshold.
///
/// The ceremony cannot produce a usable key and must be restarted; it says so
/// rather than deriving a key over too few dealers.
mod over_disqualification_aborts {
    use super::*;

    #[test]
    fn the_ceremony_refuses_to_continue_below_threshold() {
        let mut rng = OsRng;
        let epoch = 1u64;
        let dealers: Vec<Dealer<Point>> =
            (1..=3).map(|i| Dealer::new(i, 3, &mut rng).unwrap()).collect();
        let mut state = DkgState::<Point>::new(epoch, 3, 3);
        for d in &dealers {
            state.submit_commitment(d.round1_package(epoch, &mut rng)).unwrap();
        }

        assert_eq!(
            state.disqualify(2).unwrap_err(),
            OsstError::DkgAborted {
                qualified: 2,
                need: 3
            }
        );
        // and the dealer really is gone, so a caller that ignores the error
        // cannot accidentally derive a key over the full set
        assert_eq!(state.disqualified(), &[2]);
        assert_eq!(state.qualified_dealers(), vec![1, 3]);

        // a disqualified dealer cannot re-enter
        assert_eq!(
            state
                .submit_commitment(dealers[1].round1_package(epoch, &mut rng))
                .unwrap_err(),
            OsstError::UnexpectedDealer(2)
        );
    }
}

/// (4)–(7) The four sealed rejection paths: wrong prologue, wrong sender,
/// wrong recipient, and a commitment digest that does not match.
///
/// `SealedOpenFailed` is deliberately uninformative — which of wrong-sender,
/// wrong-recipient or wrong-ceremony caused it is not reported, so the error
/// is not a which-check-failed oracle. `InvalidSubShare` is reported
/// separately, because by then the package has authenticated and the dealer
/// really is at fault.
#[cfg(feature = "sealed")]
mod the_four_sealed_rejection_paths {
    use super::*;
    use osst::sealed::{
        open_subshare, seal_subshare, x25519_public_from_seed, x25519_secret_from_seed,
        SealedRoster,
    };

    const SEED_1: [u8; 32] = [21u8; 32];
    const SEED_2: [u8; 32] = [22u8; 32];
    const SEED_3: [u8; 32] = [23u8; 32];
    const SESSION: [u8; 32] = [0x77u8; 32];
    const ROUND: u8 = 2;

    fn roster(session: [u8; 32]) -> SealedRoster {
        SealedRoster::new(
            &[
                (1, x25519_public_from_seed(&SEED_1)),
                (2, x25519_public_from_seed(&SEED_2)),
                (3, x25519_public_from_seed(&SEED_3)),
            ],
            session,
        )
        .unwrap()
    }

    #[test]
    fn each_of_the_four_is_refused() {
        let mut rng = OsRng;
        let r = roster(SESSION);
        let dealer: Dealer<Point> = Dealer::new(1, 2, &mut rng).unwrap();
        let subshare = dealer.generate_subshare(2).unwrap();
        let sealed = seal_subshare::<Point>(
            &x25519_secret_from_seed(&SEED_1),
            &r,
            ROUND,
            &subshare,
            dealer.commitment(),
        )
        .unwrap();

        // the honest open, as a control
        open_subshare::<Point>(
            &x25519_secret_from_seed(&SEED_2),
            2,
            &r,
            ROUND,
            &sealed,
            dealer.commitment(),
        )
        .expect("the honest path works");

        // (4) wrong prologue — another round of the same ceremony
        assert_eq!(
            open_subshare::<Point>(
                &x25519_secret_from_seed(&SEED_2),
                2,
                &r,
                ROUND + 1,
                &sealed,
                dealer.commitment(),
            )
            .unwrap_err(),
            OsstError::SealedOpenFailed(1)
        );

        // ... and another ceremony entirely
        let elsewhere = roster([0x11u8; 32]);
        assert_eq!(
            open_subshare::<Point>(
                &x25519_secret_from_seed(&SEED_2),
                2,
                &elsewhere,
                ROUND,
                &sealed,
                dealer.commitment(),
            )
            .unwrap_err(),
            OsstError::SealedOpenFailed(1)
        );

        // (5) wrong sender — relabel the package as coming from dealer 3
        let mut reattributed = sealed.clone();
        reattributed.dealer_index = 3;
        assert_eq!(
            open_subshare::<Point>(
                &x25519_secret_from_seed(&SEED_2),
                2,
                &r,
                ROUND,
                &reattributed,
                dealer.commitment(),
            )
            .unwrap_err(),
            OsstError::SealedOpenFailed(3),
            "Noise_K binds the initiator's static key: dealer 3 did not send this"
        );

        // (6) wrong recipient — participant 3 holds a roster key, and still
        // cannot open a package addressed to 2
        assert_eq!(
            open_subshare::<Point>(
                &x25519_secret_from_seed(&SEED_3),
                3,
                &r,
                ROUND,
                &sealed,
                dealer.commitment(),
            )
            .unwrap_err(),
            OsstError::SealedOpenFailed(1)
        );
        // and a participant not on the roster at all is named as such
        let off_roster = SealedRoster::new(&[(1, x25519_public_from_seed(&SEED_1))], SESSION)
            .unwrap();
        let mut from_stranger = sealed.clone();
        from_stranger.dealer_index = 9;
        assert_eq!(
            open_subshare::<Point>(
                &x25519_secret_from_seed(&SEED_2),
                2,
                &off_roster,
                ROUND,
                &from_stranger,
                dealer.commitment(),
            )
            .unwrap_err(),
            OsstError::UnknownParticipant(9)
        );

        // (7) digest mismatch (D-2) — the package opens, but the commitment it
        // is checked against is not the one it was sealed with
        let another: Dealer<Point> = Dealer::new(1, 2, &mut rng).unwrap();
        assert_eq!(
            open_subshare::<Point>(
                &x25519_secret_from_seed(&SEED_2),
                2,
                &r,
                ROUND,
                &sealed,
                another.commitment(),
            )
            .unwrap_err(),
            OsstError::InvalidSubShare(1),
            "a sub-share and a commitment from different dealings do not pair"
        );

        // tampering with the ciphertext is caught by the AEAD tag, not by any
        // check of ours
        let mut tampered = sealed.clone();
        let last = tampered.ciphertext.len() - 1;
        tampered.ciphertext[last] ^= 1;
        assert_eq!(
            open_subshare::<Point>(
                &x25519_secret_from_seed(&SEED_2),
                2,
                &r,
                ROUND,
                &tampered,
                dealer.commitment(),
            )
            .unwrap_err(),
            OsstError::SealedOpenFailed(1)
        );
    }
}
