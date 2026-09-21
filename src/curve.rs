//! Curve abstraction for OSST
//!
//! Defines traits for curve operations, allowing OSST to work with different
//! elliptic curve backends:
//! - ristretto255 (Polkadot/sr25519 compatible)
//! - pallas (Zcash Orchard compatible)
//! - secp256k1 (Bitcoin compatible)
//! - decaf377 (Penumbra compatible)

use core::fmt::Debug;

/// Scalar field element trait
///
/// # Security
///
/// Implementors must ensure `zeroize()` overwrites the scalar's memory
/// representation with zeros. This is critical for secret key material.
pub trait OsstScalar: Clone + Debug + Sized + PartialEq + Send + Sync {
    /// Overwrite this scalar's memory with zeros
    ///
    /// # Security
    ///
    /// This method MUST overwrite the scalar's internal representation, and
    /// has no default: until 0.4.0 the default was a plain `*self =
    /// Self::zero()`, which three of the four backends inherited (Z-1). That
    /// is a non-volatile assignment to a value the compiler can see is dead in
    /// every `Drop` impl that calls it, so it is entitled to elide the store —
    /// on the pallas (Zcash) and decaf377 (Penumbra) backends, i.e. the two
    /// that carry value.
    ///
    /// Implement with `zeroize::Zeroize` where the backend's scalar provides
    /// it, or with a volatile write plus a compiler fence.
    fn zeroize(&mut self);
    /// The zero element
    fn zero() -> Self;

    /// The one element
    fn one() -> Self;

    /// Create from u32
    fn from_u32(v: u32) -> Self;

    /// Addition
    fn add(&self, other: &Self) -> Self;

    /// Subtraction
    fn sub(&self, other: &Self) -> Self;

    /// Multiplication
    fn mul(&self, other: &Self) -> Self;

    /// Negation
    fn neg(&self) -> Self;

    /// Compute multiplicative inverse
    fn invert(&self) -> Self;

    /// Generate random scalar
    fn random<R: rand_core::RngCore + rand_core::CryptoRng>(rng: &mut R) -> Self;

    /// Create from 64-byte wide hash output (reduction mod order)
    fn from_bytes_wide(bytes: &[u8; 64]) -> Self;

    /// Serialize to bytes
    fn to_bytes(&self) -> [u8; 32];

    /// Deserialize from canonical bytes
    fn from_canonical_bytes(bytes: &[u8; 32]) -> Option<Self>;
}

/// Curve point trait
pub trait OsstPoint: Clone + Debug + Sized + PartialEq + Send + Sync {
    type Scalar: OsstScalar;

    /// Compressed point size in bytes (32 for pallas/ristretto, 33 for secp256k1)
    const COMPRESSED_SIZE: usize;

    /// The canonical compressed encoding of a point.
    ///
    /// `[u8; 32]` for the prime-order-group backends, `[u8; 33]` for secp256k1
    /// (SEC1 compressed, parity byte included). Always exactly
    /// [`COMPRESSED_SIZE`](Self::COMPRESSED_SIZE) bytes.
    ///
    /// # Security
    ///
    /// The encoding MUST be injective: `compress(P) == compress(Q)` implies
    /// `P == Q`. Everything the protocol binds — the FROST binding factor, the
    /// Schnorr challenge, the inner precommitment — is a hash over these
    /// bytes, so an encoding that identifies `P` with `-P` destroys the
    /// coupling those hashes exist to create.
    type Compressed: AsRef<[u8]> + Copy + PartialEq + Debug + Send + Sync;

    /// The identity element
    fn identity() -> Self;

    /// The generator point
    fn generator() -> Self;

    /// Scalar multiplication
    fn mul_scalar(&self, scalar: &Self::Scalar) -> Self;

    /// Point addition
    fn add(&self, other: &Self) -> Self;

    /// Multiscalar multiplication (optimized)
    fn multiscalar_mul(scalars: &[Self::Scalar], points: &[Self]) -> Self;

    /// Compress to this curve's canonical encoding.
    fn compress(&self) -> Self::Compressed;

    /// Decompress from a canonical encoding.
    ///
    /// Returns `None` for any input that is not exactly
    /// [`COMPRESSED_SIZE`](Self::COMPRESSED_SIZE) bytes of a canonical
    /// encoding of a point in the group. Non-canonical encodings — a
    /// short/long slice, a bad SEC1 prefix, an x-coordinate with no
    /// y-coordinate supplied — are rejected rather than coerced.
    fn decompress(bytes: &[u8]) -> Option<Self>;

    /// Compress to an owned byte vector.
    fn compress_vec(&self) -> alloc::vec::Vec<u8> {
        self.compress().as_ref().to_vec()
    }
}

extern crate alloc;

/// Complete curve backend
pub trait OsstCurve: Clone + Debug + Default {
    type Scalar: OsstScalar;
    type Point: OsstPoint<Scalar = Self::Scalar>;
}

// ============================================================================
// Ristretto255 implementation
// ============================================================================

#[cfg(feature = "ristretto255")]
pub mod ristretto {
    use super::*;
    use curve25519_dalek::{
        constants::RISTRETTO_BASEPOINT_POINT,
        ristretto::{CompressedRistretto, RistrettoPoint},
        scalar::Scalar,
        traits::MultiscalarMul,
    };
    use zeroize::Zeroize;

    impl OsstScalar for Scalar {
        fn zeroize(&mut self) {
            // Use curve25519-dalek's constant-time zeroize implementation
            Zeroize::zeroize(self);
        }
        fn zero() -> Self {
            Scalar::ZERO
        }

        fn one() -> Self {
            Scalar::ONE
        }

        fn from_u32(v: u32) -> Self {
            Scalar::from(v)
        }

        fn add(&self, other: &Self) -> Self {
            self + other
        }

        fn sub(&self, other: &Self) -> Self {
            self - other
        }

        fn mul(&self, other: &Self) -> Self {
            self * other
        }

        fn neg(&self) -> Self {
            -self
        }

        fn invert(&self) -> Self {
            Scalar::invert(self)
        }

        fn random<R: rand_core::RngCore + rand_core::CryptoRng>(rng: &mut R) -> Self {
            Scalar::random(rng)
        }

        fn from_bytes_wide(bytes: &[u8; 64]) -> Self {
            Scalar::from_bytes_mod_order_wide(bytes)
        }

        fn to_bytes(&self) -> [u8; 32] {
            Scalar::to_bytes(self)
        }

        fn from_canonical_bytes(bytes: &[u8; 32]) -> Option<Self> {
            Scalar::from_canonical_bytes(*bytes).into_option()
        }
    }

    impl OsstPoint for RistrettoPoint {
        type Scalar = Scalar;

        const COMPRESSED_SIZE: usize = 32;

        type Compressed = [u8; 32];

        fn identity() -> Self {
            curve25519_dalek::traits::Identity::identity()
        }

        fn generator() -> Self {
            RISTRETTO_BASEPOINT_POINT
        }

        fn mul_scalar(&self, scalar: &Self::Scalar) -> Self {
            self * scalar
        }

        fn add(&self, other: &Self) -> Self {
            self + other
        }

        fn multiscalar_mul(scalars: &[Self::Scalar], points: &[Self]) -> Self {
            <RistrettoPoint as MultiscalarMul>::multiscalar_mul(scalars, points)
        }

        fn compress(&self) -> Self::Compressed {
            RistrettoPoint::compress(self).to_bytes()
        }

        fn decompress(bytes: &[u8]) -> Option<Self> {
            let arr: [u8; 32] = bytes.try_into().ok()?;
            CompressedRistretto::from_slice(&arr).ok()?.decompress()
        }
    }

    /// Ristretto255 curve backend
    #[derive(Clone, Debug, Default)]
    pub struct Ristretto255;

    impl OsstCurve for Ristretto255 {
        type Scalar = Scalar;
        type Point = RistrettoPoint;
    }
}

// ============================================================================
// Pallas implementation (Zcash Orchard)
// ============================================================================

#[cfg(feature = "pallas")]
pub mod pallas {
    use super::*;
    use pasta_curves::{
        group::{
            ff::{Field, FromUniformBytes, PrimeField},
            Group, GroupEncoding,
        },
        pallas::{Point, Scalar},
    };

    impl OsstScalar for Scalar {
        fn zeroize(&mut self) {
            // Volatile so the compiler may not elide the store as dead: every
            // caller is a `Drop` impl, where it provably is (Z-1).
            unsafe { core::ptr::write_volatile(self, Self::zero()) };
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        }

        fn zero() -> Self {
            Scalar::ZERO
        }

        fn one() -> Self {
            Scalar::ONE
        }

        fn from_u32(v: u32) -> Self {
            Scalar::from(v as u64)
        }

        fn add(&self, other: &Self) -> Self {
            *self + *other
        }

        fn sub(&self, other: &Self) -> Self {
            *self - *other
        }

        fn mul(&self, other: &Self) -> Self {
            *self * *other
        }

        fn neg(&self) -> Self {
            -(*self)
        }

        fn invert(&self) -> Self {
            Field::invert(self).unwrap_or(Scalar::ZERO)
        }

        fn random<R: rand_core::RngCore + rand_core::CryptoRng>(rng: &mut R) -> Self {
            // ff 0.14 (Zakura Common 1.0) moved `Field::random` onto rand_core
            // 0.10's `Rng` trait, which is incompatible with the rand_core 0.6
            // RNG this API is generic over. Sample uniformly ourselves via
            // fill_bytes + wide reduction to keep osst on rand_core 0.6.
            let mut bytes = [0u8; 64];
            rng.fill_bytes(&mut bytes);
            <Scalar as FromUniformBytes<64>>::from_uniform_bytes(&bytes)
        }

        fn from_bytes_wide(bytes: &[u8; 64]) -> Self {
            <Scalar as FromUniformBytes<64>>::from_uniform_bytes(bytes)
        }

        fn to_bytes(&self) -> [u8; 32] {
            self.to_repr()
        }

        fn from_canonical_bytes(bytes: &[u8; 32]) -> Option<Self> {
            Scalar::from_repr(*bytes).into_option()
        }
    }

    impl OsstPoint for Point {
        type Scalar = Scalar;

        const COMPRESSED_SIZE: usize = 32;

        type Compressed = [u8; 32];

        fn identity() -> Self {
            <Point as Group>::identity()
        }

        fn generator() -> Self {
            <Point as Group>::generator()
        }

        fn mul_scalar(&self, scalar: &Self::Scalar) -> Self {
            self * scalar
        }

        fn add(&self, other: &Self) -> Self {
            *self + *other
        }

        fn multiscalar_mul(scalars: &[Self::Scalar], points: &[Self]) -> Self {
            // Basic implementation - could use more optimized version
            scalars
                .iter()
                .zip(points.iter())
                .fold(<Point as Group>::identity(), |acc, (s, p)| {
                    acc + p.mul_scalar(s)
                })
        }

        fn compress(&self) -> Self::Compressed {
            self.to_bytes()
        }

        fn decompress(bytes: &[u8]) -> Option<Self> {
            let arr: [u8; 32] = bytes.try_into().ok()?;
            Point::from_bytes(&arr).into_option()
        }
    }

    /// Pallas curve backend using the *curve* generator.
    ///
    /// Not Zcash-compatible on its own: Orchard spend authorization
    /// (RedPallas `SpendAuth`) uses a hash-to-curve basepoint, not the Pallas
    /// generator. Use [`OrchardSpendAuthCurve`] for anything that must agree
    /// with ZF `reddsa` / `frost-core` FROST(Pallas) key material.
    #[derive(Clone, Debug, Default)]
    pub struct PallasCurve;

    impl OsstCurve for PallasCurve {
        type Scalar = Scalar;
        type Point = Point;
    }

    /// Byte encoding of the Orchard `SpendAuthSig` basepoint.
    /// Reproducible by `pallas::Point::hash_to_curve("z.cash:Orchard")(b"G").to_bytes()`.
    /// Same constant as `reddsa::orchard::ORCHARD_SPENDAUTHSIG_BASEPOINT_BYTES`.
    pub const ORCHARD_SPENDAUTHSIG_BASEPOINT_BYTES: [u8; 32] = [
        99, 201, 117, 184, 132, 114, 26, 141, 12, 161, 112, 123, 227, 12, 127, 12, 95, 68, 95,
        62, 124, 24, 141, 59, 6, 214, 241, 40, 179, 35, 85, 183,
    ];

    /// A Pallas point whose group generator is the Orchard spend-auth
    /// basepoint. This is the group ZF `reddsa` FROST(Pallas, BLAKE2b-512)
    /// operates in, so shares, commitments and verifying shares produced with
    /// this backend load directly into `frost-core` key packages.
    ///
    /// Byte encoding is the plain Pallas point encoding, so values convert to
    /// and from the `PallasCurve` backend and ZF types losslessly.
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub struct SpendAuthPoint(pub Point);

    impl SpendAuthPoint {
        pub fn basepoint() -> Self {
            SpendAuthPoint(
                Point::from_bytes(&ORCHARD_SPENDAUTHSIG_BASEPOINT_BYTES)
                    .expect("constant is a valid Pallas point"),
            )
        }

        pub fn inner(&self) -> &Point {
            &self.0
        }
    }

    impl OsstPoint for SpendAuthPoint {
        type Scalar = Scalar;

        const COMPRESSED_SIZE: usize = 32;

        type Compressed = [u8; 32];

        fn identity() -> Self {
            SpendAuthPoint(<Point as Group>::identity())
        }

        fn generator() -> Self {
            Self::basepoint()
        }

        fn mul_scalar(&self, scalar: &Self::Scalar) -> Self {
            SpendAuthPoint(self.0 * scalar)
        }

        fn add(&self, other: &Self) -> Self {
            SpendAuthPoint(self.0 + other.0)
        }

        fn multiscalar_mul(scalars: &[Self::Scalar], points: &[Self]) -> Self {
            scalars
                .iter()
                .zip(points.iter())
                .fold(Self::identity(), |acc, (s, p)| acc.add(&p.mul_scalar(s)))
        }

        fn compress(&self) -> Self::Compressed {
            self.0.to_bytes()
        }

        fn decompress(bytes: &[u8]) -> Option<Self> {
            let arr: [u8; 32] = bytes.try_into().ok()?;
            Point::from_bytes(&arr).into_option().map(SpendAuthPoint)
        }
    }

    /// Pallas backend in the Orchard spend-auth group. Zcash-compatible.
    #[derive(Clone, Debug, Default)]
    pub struct OrchardSpendAuthCurve;

    impl OsstCurve for OrchardSpendAuthCurve {
        type Scalar = Scalar;
        type Point = SpendAuthPoint;
    }
}

// ============================================================================
// secp256k1 implementation (Bitcoin)
// ============================================================================

#[cfg(feature = "secp256k1")]
pub mod secp256k1 {
    use super::*;
    use k256::{
        elliptic_curve::{
            bigint::U512,
            ops::Reduce,
            sec1::{FromEncodedPoint, ToEncodedPoint},
            Field, PrimeField,
        },
        ProjectivePoint, Scalar,
    };

    impl OsstScalar for Scalar {
        fn zeroize(&mut self) {
            // Volatile so the compiler may not elide the store as dead: every
            // caller is a `Drop` impl, where it provably is (Z-1).
            unsafe { core::ptr::write_volatile(self, Self::zero()) };
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        }

        fn zero() -> Self {
            Scalar::ZERO
        }

        fn one() -> Self {
            Scalar::ONE
        }

        fn from_u32(v: u32) -> Self {
            Scalar::from(v as u64)
        }

        fn add(&self, other: &Self) -> Self {
            *self + *other
        }

        fn sub(&self, other: &Self) -> Self {
            *self - *other
        }

        fn mul(&self, other: &Self) -> Self {
            *self * *other
        }

        fn neg(&self) -> Self {
            -(*self)
        }

        fn invert(&self) -> Self {
            <Scalar as Field>::invert(self).unwrap_or(Scalar::ZERO)
        }

        fn random<R: rand_core::RngCore + rand_core::CryptoRng>(rng: &mut R) -> Self {
            <Scalar as Field>::random(rng)
        }

        fn from_bytes_wide(bytes: &[u8; 64]) -> Self {
            // reduce full 512-bit value modulo curve order
            // this preserves the full entropy from the hash
            let wide = U512::from_be_slice(bytes);
            <Scalar as Reduce<U512>>::reduce(wide)
        }

        fn to_bytes(&self) -> [u8; 32] {
            self.to_bytes().into()
        }

        fn from_canonical_bytes(bytes: &[u8; 32]) -> Option<Self> {
            let arr: &k256::FieldBytes = bytes.into();
            Scalar::from_repr(*arr).into_option()
        }
    }

    impl OsstPoint for ProjectivePoint {
        type Scalar = Scalar;

        // secp256k1 uses 33-byte compressed points
        const COMPRESSED_SIZE: usize = 33;

        type Compressed = [u8; 33];

        fn identity() -> Self {
            Self::IDENTITY
        }

        fn generator() -> Self {
            Self::GENERATOR
        }

        fn mul_scalar(&self, scalar: &Self::Scalar) -> Self {
            self * scalar
        }

        fn add(&self, other: &Self) -> Self {
            *self + *other
        }

        fn multiscalar_mul(scalars: &[Self::Scalar], points: &[Self]) -> Self {
            scalars
                .iter()
                .zip(points.iter())
                .fold(Self::IDENTITY, |acc, (s, p)| acc + p.mul_scalar(s))
        }

        /// SEC1 compressed: `0x02`/`0x03` parity byte followed by the
        /// x-coordinate. The identity encodes as 33 zero bytes (SEC1 gives it
        /// a single `0x00`, which is not a fixed-width encoding).
        ///
        /// Until 0.4.0 this returned the bare x-coordinate, which is neither a
        /// round trip nor injective: `P` and `-P` had the same 32 bytes, so
        /// binding factors and challenges could not separate a commitment set
        /// from its sign-flipped variants (C-1).
        ///
        /// # Infallibility (M-22)
        ///
        /// `compress` returns `[u8; 33]` and cannot report an error, so the
        /// only honest options are a total function or a panic. It is total,
        /// and the case analysis is exhaustive rather than a fallthrough:
        /// SEC1 compressed encoding of a curve point over a 256-bit field is
        /// `0x02`/`0x03` followed by 32 x-coordinate bytes — 33 bytes — and
        /// the sole other output `k256`'s encoder can produce is the identity,
        /// which SEC1 gives the single byte `0x00`. Both are named branches
        /// below, so a silently all-zero result is no longer reachable by
        /// falling off the end of an `if`.
        ///
        /// Until 0.5.0 an unexpected length left `out` all-zero, which
        /// `decompress` maps to the identity: a wrong hash input rather than a
        /// loud failure, in the function whose lossiness was C-1.
        ///
        /// The remaining `unreachable!` is over `k256`'s own encoder, not over
        /// wire input, so P-1 ("never abort on parsed bytes") does not apply —
        /// nothing an attacker sends reaches this branch, and if a future
        /// `k256` reached it the all-zero alternative would be a silently
        /// wrong binding factor. `identity_compresses_to_the_zero_encoding`
        /// in `tests/audit_secp_encoding.rs` pins both named branches.
        fn compress(&self) -> Self::Compressed {
            let affine = self.to_affine();
            let encoded = affine.to_encoded_point(true);
            let bytes = encoded.as_bytes();
            match bytes.len() {
                33 => {
                    let mut out = [0u8; 33];
                    out.copy_from_slice(bytes);
                    out
                }
                // identity: SEC1 emits a single 0x00 byte; keep the all-zero
                // fixed-width form, which `decompress` maps back to the
                // identity.
                1 if bytes[0] == 0 => [0u8; 33],
                other => unreachable!(
                    "k256 emitted a {}-byte compressed point; SEC1 admits only 33 (a point) or 1 (the identity)",
                    other
                ),
            }
        }

        fn decompress(bytes: &[u8]) -> Option<Self> {
            use k256::EncodedPoint;
            if bytes.len() != 33 {
                return None;
            }
            if bytes == [0u8; 33] {
                return Some(Self::IDENTITY);
            }
            // EncodedPoint::from_bytes rejects anything but a 0x02/0x03
            // prefix at this length, and from_encoded_point rejects an
            // x-coordinate that is not on the curve.
            let encoded = EncodedPoint::from_bytes(bytes).ok()?;
            let affine = k256::AffinePoint::from_encoded_point(&encoded);
            if affine.is_some().into() {
                Some(ProjectivePoint::from(affine.unwrap()))
            } else {
                None
            }
        }
    }

    /// secp256k1 curve backend (Bitcoin)
    #[derive(Clone, Debug, Default)]
    pub struct Secp256k1Curve;

    impl OsstCurve for Secp256k1Curve {
        type Scalar = Scalar;
        type Point = ProjectivePoint;
    }
}

// ============================================================================
// decaf377 implementation (Penumbra)
// ============================================================================

#[cfg(feature = "decaf377")]
pub mod decaf377 {
    use super::*;
    use ::decaf377::{Element, Fr};

    impl OsstScalar for Fr {
        fn zeroize(&mut self) {
            // Volatile so the compiler may not elide the store as dead: every
            // caller is a `Drop` impl, where it provably is (Z-1).
            unsafe { core::ptr::write_volatile(self, Self::zero()) };
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        }

        fn zero() -> Self {
            Fr::ZERO
        }

        fn one() -> Self {
            Fr::ONE
        }

        fn from_u32(v: u32) -> Self {
            Fr::from(v as u64)
        }

        fn add(&self, other: &Self) -> Self {
            *self + *other
        }

        fn sub(&self, other: &Self) -> Self {
            *self - *other
        }

        fn mul(&self, other: &Self) -> Self {
            *self * *other
        }

        fn neg(&self) -> Self {
            -(*self)
        }

        fn invert(&self) -> Self {
            self.inverse().unwrap_or(Fr::ZERO)
        }

        fn random<R: rand_core::RngCore + rand_core::CryptoRng>(rng: &mut R) -> Self {
            let mut bytes = [0u8; 32];
            rng.fill_bytes(&mut bytes);
            Fr::from_le_bytes_mod_order(&bytes)
        }

        fn from_bytes_wide(bytes: &[u8; 64]) -> Self {
            // reduce full 512-bit value mod field order
            // decaf377's from_le_bytes_mod_order accepts arbitrary length slices
            Fr::from_le_bytes_mod_order(bytes)
        }

        fn to_bytes(&self) -> [u8; 32] {
            Fr::to_bytes(self)
        }

        fn from_canonical_bytes(bytes: &[u8; 32]) -> Option<Self> {
            Fr::from_bytes_checked(bytes).ok()
        }
    }

    impl OsstPoint for Element {
        type Scalar = Fr;

        const COMPRESSED_SIZE: usize = 32;

        type Compressed = [u8; 32];

        fn identity() -> Self {
            Element::IDENTITY
        }

        fn generator() -> Self {
            Element::GENERATOR
        }

        fn mul_scalar(&self, scalar: &Self::Scalar) -> Self {
            *self * *scalar
        }

        fn add(&self, other: &Self) -> Self {
            *self + *other
        }

        fn multiscalar_mul(scalars: &[Self::Scalar], points: &[Self]) -> Self {
            scalars
                .iter()
                .zip(points.iter())
                .fold(Element::IDENTITY, |acc, (s, p)| acc + (*p * *s))
        }

        fn compress(&self) -> Self::Compressed {
            self.vartime_compress().0
        }

        fn decompress(bytes: &[u8]) -> Option<Self> {
            let arr: [u8; 32] = bytes.try_into().ok()?;
            ::decaf377::Encoding(arr).vartime_decompress().ok()
        }
    }

    /// decaf377 curve backend (Penumbra)
    #[derive(Clone, Debug, Default)]
    pub struct Decaf377Curve;

    impl OsstCurve for Decaf377Curve {
        type Scalar = Fr;
        type Point = Element;
    }
}
