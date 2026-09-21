//! Audit regression tests — canonical point encoding on every backend
//! (SECURITY-REVIEW-2026-09.md, finding C-1).
//!
//! C-1 was secp256k1-only: `compress()` returned the bare x-coordinate and
//! `decompress()` always rebuilt the even-y point, so the encoding was neither
//! a round trip nor injective — `P` and `-P` hashed identically, which breaks
//! exactly the injectivity the FROST binding factor depends on.
//!
//! These were `#[ignore]`d PoCs asserting the break. They now assert the
//! property, on every backend the build enables, and none is ignored.

macro_rules! encoding_properties {
    ($name:ident, $point:ty, $scalar:ty, $size:expr) => {
        mod $name {
            use osst::curve::{OsstPoint, OsstScalar};

            type Point = $point;
            type Scalar = $scalar;

            fn rand_point(rng: &mut rand::rngs::OsRng) -> Point {
                let s = <Scalar as OsstScalar>::random(rng);
                <Point as OsstPoint>::generator().mul_scalar(&s)
            }

            /// `decompress(compress(P)) == P`, for every point, every time.
            #[test]
            fn compress_decompress_round_trips() {
                let mut rng = rand::rngs::OsRng;
                for _ in 0..128 {
                    let p = rand_point(&mut rng);
                    let bytes = OsstPoint::compress(&p);
                    assert_eq!(bytes.as_ref().len(), $size);
                    assert_eq!(
                        <Point as OsstPoint>::decompress(bytes.as_ref()).expect("decompresses"),
                        p,
                        "compress/decompress must round-trip for every point"
                    );
                }
            }

            /// `compress(P) != compress(-P)`: the encoding separates a point
            /// from its negation, so a hash over it separates a commitment set
            /// from its sign-flipped variants.
            #[test]
            fn compress_is_injective_in_the_sign() {
                let mut rng = rand::rngs::OsRng;
                for _ in 0..128 {
                    let s = <Scalar as OsstScalar>::random(&mut rng);
                    let p = <Point as OsstPoint>::generator().mul_scalar(&s);
                    let neg = <Point as OsstPoint>::generator().mul_scalar(&s.neg());
                    assert_ne!(p, neg, "P and -P are different points");
                    assert_ne!(
                        OsstPoint::compress(&p),
                        OsstPoint::compress(&neg),
                        "distinct points must have distinct compressed encodings"
                    );
                }
            }

            /// The identity is a legal FROST commitment and must survive the
            /// round trip like any other point.
            #[test]
            fn the_identity_round_trips() {
                let id = <Point as OsstPoint>::identity();
                let bytes = OsstPoint::compress(&id);
                assert_eq!(bytes.as_ref().len(), $size);
                assert_eq!(
                    <Point as OsstPoint>::decompress(bytes.as_ref()).expect("decompresses"),
                    id
                );
            }

            /// Non-canonical encodings are rejected rather than coerced: a
            /// short slice, a long slice, and (on secp256k1) the bare
            /// x-coordinate that 0.3.0 accepted.
            #[test]
            fn non_canonical_encodings_are_rejected() {
                let mut rng = rand::rngs::OsRng;
                let p = rand_point(&mut rng);
                let bytes = OsstPoint::compress(&p);
                let b = bytes.as_ref();

                assert!(<Point as OsstPoint>::decompress(&b[..b.len() - 1]).is_none());
                let mut long = b.to_vec();
                long.push(0);
                assert!(<Point as OsstPoint>::decompress(&long).is_none());
                assert!(<Point as OsstPoint>::decompress(&[]).is_none());
            }
        }
    };
}

#[cfg(feature = "ristretto255")]
encoding_properties!(
    ristretto255,
    curve25519_dalek::ristretto::RistrettoPoint,
    curve25519_dalek::scalar::Scalar,
    32
);

#[cfg(feature = "secp256k1")]
encoding_properties!(secp256k1, k256::ProjectivePoint, k256::Scalar, 33);

#[cfg(feature = "pallas")]
encoding_properties!(
    pallas,
    pasta_curves::pallas::Point,
    pasta_curves::pallas::Scalar,
    32
);

#[cfg(feature = "pallas")]
encoding_properties!(
    orchard_spend_auth,
    osst::curve::pallas::SpendAuthPoint,
    pasta_curves::pallas::Scalar,
    32
);

#[cfg(feature = "decaf377")]
encoding_properties!(decaf377, decaf377::Element, decaf377::Fr, 32);

/// C-1, the second half, stated once against the protocol layer rather than
/// the trait: two commitment sets that differ only by a point negation must
/// produce different binding factors and different challenges.
#[cfg(all(feature = "secp256k1", feature = "std"))]
mod binding_factor_separates_negated_commitments {
    use k256::{ProjectivePoint as Point, Scalar};
    use osst::curve::{OsstPoint, OsstScalar};
    use osst::frost::{SigningCommitments, SigningPackage};

    #[test]
    fn negating_a_commitment_moves_the_binding_factor() {
        let mut rng = rand::rngs::OsRng;
        let d = <Scalar as OsstScalar>::random(&mut rng);
        let e = <Scalar as OsstScalar>::random(&mut rng);
        let g = <Point as OsstPoint>::generator();

        let honest = SigningCommitments {
            index: 1,
            hiding: g.mul_scalar(&d),
            binding: g.mul_scalar(&e),
        };
        let flipped = SigningCommitments {
            index: 1,
            hiding: g.mul_scalar(&d.neg()),
            binding: g.mul_scalar(&e),
        };

        let a = SigningPackage::<Point>::new(b"m".to_vec(), vec![honest]).unwrap();
        let b = SigningPackage::<Point>::new(b"m".to_vec(), vec![flipped]).unwrap();
        assert_ne!(
            a.binding_factor(1),
            b.binding_factor(1),
            "a sign flip in the commitment set must move the binding factor"
        );
    }
}

/// M-22: `compress()` no longer reaches the all-zero output by falling off the
/// end of a length check. Both named branches are exercised here — the
/// identity, which SEC1 encodes as one `0x00` byte and which this crate widens
/// to 33 zero bytes, and an ordinary point, which is 33 bytes already.
#[cfg(feature = "secp256k1")]
mod compress_has_no_silent_failure_path {
    use k256::elliptic_curve::sec1::ToEncodedPoint;
    use k256::ProjectivePoint as Point;
    use osst::curve::{OsstPoint, OsstScalar};

    #[test]
    fn identity_compresses_to_the_zero_encoding() {
        let id = <Point as OsstPoint>::identity();
        assert_eq!(
            OsstPoint::compress(&id),
            [0u8; 33],
            "the identity must keep the fixed-width all-zero form"
        );
        assert_eq!(
            <Point as OsstPoint>::decompress(&[0u8; 33]).expect("decompresses"),
            id,
            "and it must decompress back to the identity"
        );
    }

    /// The premise of the infallibility argument, asserted rather than assumed:
    /// k256's own encoder emits exactly 1 byte for the identity and exactly 33
    /// for every other point, so the `match` in `compress` is exhaustive.
    #[test]
    fn k256_emits_only_the_two_lengths_compress_handles() {
        let id = <Point as OsstPoint>::identity();
        assert_eq!(id.to_affine().to_encoded_point(true).as_bytes().len(), 1);

        let mut rng = rand::rngs::OsRng;
        for _ in 0..64 {
            let s = <k256::Scalar as OsstScalar>::random(&mut rng);
            let p = <Point as OsstPoint>::generator().mul_scalar(&s);
            assert_eq!(p.to_affine().to_encoded_point(true).as_bytes().len(), 33);
        }
    }
}
