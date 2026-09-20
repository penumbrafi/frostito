//! Audit PoC — the secp256k1 backend's 32-byte point encoding is lossy
//! (SECURITY-REVIEW-2026-09.md, finding C-1).
//!
//! Build with `cargo test --features secp256k1 --test audit_secp_encoding -- --ignored`.
//! Under default features this file compiles to nothing.

#![cfg(feature = "secp256k1")]

use k256::ProjectivePoint;
use osst::curve::{OsstPoint, OsstScalar};

/// C-1 (High, secp256k1 backend only) — `OsstPoint::compress` for
/// `ProjectivePoint` returns only the x-coordinate and `decompress` always
/// reconstructs the even-y point.
///
/// Two consequences, both load-bearing:
///
/// 1. `compress`/`decompress` is not a round trip. Every fixed-width
///    serializer in the crate — `Contribution::to_bytes`, `Signature::to_bytes`,
///    `SigningCommitments::to_bytes`, `DealerCommitment::to_bytes` — silently
///    maps `P` to `-P` for half of all points.
/// 2. `compress` is the encoding fed to `encode_commitments`, the binding
///    factor and the challenge. `P` and `-P` hash identically, so the FROST
///    binding factor does not separate a commitment set from its
///    sign-flipped variants — the exact coupling the binding factor exists to
///    create.
#[test]
#[ignore = "C-1: secp256k1 compress() drops the y parity; decompress() is not its inverse"]
fn secp_compress_decompress_round_trips() {
    let mut rng = rand::rngs::OsRng;

    let mut found_broken = None;
    for _ in 0..64 {
        let s = <k256::Scalar as OsstScalar>::random(&mut rng);
        let p = <ProjectivePoint as OsstPoint>::generator().mul_scalar(&s);
        let bytes = OsstPoint::compress(&p);
        let back = <ProjectivePoint as OsstPoint>::decompress(&bytes).expect("decompresses");
        if back != p {
            found_broken = Some(p);
            break;
        }
    }

    assert!(
        found_broken.is_none(),
        "compress/decompress must round-trip for every point; it does not for odd-y points"
    );
}

/// C-1, second half: `P` and `-P` share a compressed encoding, so any hash over
/// `compress()` cannot tell them apart.
#[test]
#[ignore = "C-1: secp256k1 compress() collides P with -P, breaking binding-factor injectivity"]
fn secp_compress_is_injective() {
    let mut rng = rand::rngs::OsRng;
    let s = <k256::Scalar as OsstScalar>::random(&mut rng);
    let p = <ProjectivePoint as OsstPoint>::generator().mul_scalar(&s);
    let neg = <ProjectivePoint as OsstPoint>::generator().mul_scalar(&s.neg());

    assert_ne!(p, neg, "P and -P are different points");
    assert_ne!(
        OsstPoint::compress(&p),
        OsstPoint::compress(&neg),
        "distinct points must have distinct compressed encodings"
    );
}
