//! frostito — threshold Schnorr for custodial groups.
//!
//! Distributed key generation, FROST signing, nested FROST, and proactive
//! resharing, over ristretto255, Pallas, secp256k1 and decaf377.
//!
//! # What is here, and what is not
//!
//! The signing math is being rooted in ZF [`frost-core`], which implements
//! RFC 9591 and has been audited. What this crate adds is the part frost-core
//! deliberately leaves to the caller:
//!
//! - [`sealed`] — confidential, authenticated DKG round 2 over Noise_K.
//!   `frost_core::keys::dkg::part2` requires the caller to supply that
//!   channel and provides none.
//! - [`dkg`] — an echo round over the round-1 set, so an equivocating dealer
//!   cannot hand two participants different commitments, plus signed,
//!   ceremony-bound complaints and a quorum-gated tally.
//! - [`reshare`] — dealerless rotation to a *different* committee with a
//!   *different* threshold, group key preserved. `frost_core::keys::refresh`
//!   is trusted-dealer, cannot grow the set, and cannot change the threshold.
//! - [`nested`] — one outer FROST position held distributively by an inner
//!   group, the outer share never materialized as a scalar.
//!
//! [`frost-core`]: https://github.com/ZcashFoundation/frost
//!
//! # Curve backends
//!
//! `ristretto255` (default), `pallas` (including the Orchard spend-auth
//! group), `secp256k1`, `decaf377`. ZF ships FROST ciphersuites for the first
//! three; [`zf`] supplies the fourth.
//!
//! # Caller obligations
//!
//! Three things this crate cannot do for you, each of which has been got
//! wrong in practice: reliable broadcast (the echo round compares digests, it
//! does not deliver them), agreement on complaints across nodes, and durable
//! spent-nonce state. See the module docs for each.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;


pub mod context;
pub mod curve;
pub mod dkg;
mod error;
pub mod frost;
mod lagrange;
pub mod liveness;
pub mod nested;
pub mod reshare;
#[cfg(all(feature = "zf-decaf377", feature = "decaf377"))]
pub mod zf;
#[cfg(feature = "sealed")]
pub mod sealed;
#[cfg(all(test, feature = "pallas"))]
pub(crate) mod test_rng;

pub use context::{SigningContext, SIGNING_CONTEXT_DOMAIN};
pub use curve::{Curve, CurvePoint, CurveScalar};
pub use error::Error;
pub use lagrange::compute_lagrange_coefficients;

#[cfg(feature = "ristretto255")]
pub use curve::ristretto::Ristretto255;

#[cfg(feature = "pallas")]
pub use curve::pallas::{OrchardSpendAuthCurve, PallasCurve};

#[cfg(feature = "secp256k1")]
pub use curve::secp256k1::Secp256k1Curve;

#[cfg(feature = "decaf377")]
pub use curve::decaf377::Decaf377Curve;

/// Sample a uniform scalar for any backend curve, from a `rand_core` 0.6 RNG.
///
/// Sugar over [`CurveScalar::random`] for callers that would otherwise
/// hand-roll nonce sampling. Reach for it when a backend's own `Field::random`
/// is out of reach: the pallas backend rides on `ff` 0.14 (Zakura Common 1.0),
/// which moved `Field::random` onto rand_core 0.10's `Rng` trait, so a
/// rand_core 0.6 `OsRng` cannot call it. This crate keeps its whole public API
/// on rand_core 0.6 and samples by wide reduction internally; external callers
/// should use this rather than re-deriving that bridge and risking a different
/// distribution.
///
/// ```ignore
/// use frostito::random_scalar;
/// use pasta_curves::pallas::Scalar;
///
/// let nonce: Scalar = random_scalar(&mut rand_core::OsRng);
/// ```
#[inline]
pub fn random_scalar<S: CurveScalar, R: rand_core::RngCore + rand_core::CryptoRng>(
 rng: &mut R,
) -> S {
 S::random(rng)
}


/// A secret share from DKG
///
/// # Security
///
/// This struct holds secret key material. It implements `ZeroizeOnDrop`
/// to ensure the scalar is zeroed when the share goes out of scope.
#[derive(Clone)]
pub struct SecretShare<S: CurveScalar> {
 /// Shareholder index (1-indexed, as per Shamir convention)
 pub index: u32,
 /// The secret scalar x_i
 scalar: S,
}

impl<S: CurveScalar> core::fmt::Debug for SecretShare<S> {
 fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
 f.debug_struct("SecretShare")
 .field("index", &self.index)
 .field("scalar", &"[REDACTED]")
 .finish()
 }
}

impl<S: CurveScalar> Drop for SecretShare<S> {
 fn drop(&mut self) {
 // Zero the scalar bytes via the CurveScalar trait
 self.scalar.zeroize();
 }
}

impl<S: CurveScalar> SecretShare<S> {
 /// Construct a share.
 ///
 /// # Errors
 ///
 /// [`Error::InvalidIndex`] if `index` is 0 — Shamir indices are
 /// 1-indexed, and index 0 is the secret itself. This returns rather than
 /// panicking: a node parsing an index off the wire must not be
 /// abortable by a peer.
 pub fn new(index: u32, scalar: S) -> Result<Self, Error> {
 if index == 0 {
 return Err(Error::InvalidIndex);
 }
 Ok(Self { index, scalar })
 }

 /// Access the secret scalar (use sparingly, avoid logging/debugging)
 #[inline]
 pub fn scalar(&self) -> &S {
 &self.scalar
 }


 /// Derive public key share y_i = g^{x_i}
 pub fn public_share<P: CurvePoint<Scalar = S>>(&self) -> P {
 P::generator().mul_scalar(&self.scalar)
 }
}


// ============================================================================
// Ristretto255-specific convenience exports (default)
// ============================================================================


// ============================================================================
// Pallas-specific convenience exports
// ============================================================================


// ============================================================================
// Tests (Pallas)
// ============================================================================





