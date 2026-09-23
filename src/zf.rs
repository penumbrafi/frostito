//! ZF `frost-core` integration.
//!
//! The signing math in this crate is a reimplementation of FROST. ZF's
//! `frost-core` is the same protocol, audited, and it ships ciphersuites for
//! three of our four backends (`frost-ristretto255`, `frost-secp256k1`, and
//! `reddsa` / `frost-rerandomized` for Pallas). This module supplies the
//! fourth — decaf377 — so every backend can be rooted in their implementation
//! rather than ours.
//!
//! # decaf377 is not a standardized ciphersuite
//!
//! RFC 9591 registers ristretto255, Ed25519, Ed448, P-256 and secp256k1.
//! decaf377 is not among them, so [`Decaf377Sha512`] is our construction, not
//! a standard one, and nothing else will interoperate with it. It follows the
//! FROST(ristretto255, SHA-512) ciphersuite structurally — SHA-512, the same
//! five context-separated hashes, the same `H4`/`H5` byte outputs — with the
//! group swapped and its own context string, so a signature under this suite
//! can never be reinterpreted under another.

#![cfg(all(feature = "zf-decaf377", feature = "decaf377"))]

use core::ops::{Add, Mul, Sub};

use decaf377::{Element, Encoding, Fr};
use frost_core::{Ciphersuite, Field, FieldError, Group, GroupError};
use rand_core::{CryptoRng, RngCore};
use sha2::{Digest, Sha512};

/// The decaf377 scalar field, as a `frost-core` [`Field`].
#[derive(Clone, Copy)]
pub struct Decaf377ScalarField;

impl Field for Decaf377ScalarField {
 type Scalar = Fr;
 type Serialization = [u8; 32];

 fn zero() -> Self::Scalar {
 Fr::ZERO
 }

 fn one() -> Self::Scalar {
 Fr::ONE
 }

 fn invert(scalar: &Self::Scalar) -> Result<Self::Scalar, FieldError> {
 scalar.inverse().ok_or(FieldError::InvalidZeroScalar)
 }

 fn random<R: RngCore + CryptoRng>(rng: &mut R) -> Self::Scalar {
 // Wide reduction: 64 bytes down to the field, so the result is
 // statistically uniform rather than biased by a 32-byte truncation.
 let mut bytes = [0u8; 64];
 rng.fill_bytes(&mut bytes);
 Fr::from_le_bytes_mod_order(&bytes)
 }

 fn serialize(scalar: &Self::Scalar) -> Self::Serialization {
 Fr::to_bytes(scalar)
 }

 fn deserialize(buf: &Self::Serialization) -> Result<Self::Scalar, FieldError> {
 Fr::from_bytes_checked(buf).map_err(|_| FieldError::MalformedScalar)
 }

 fn little_endian_serialize(scalar: &Self::Scalar) -> Self::Serialization {
 // decaf377's canonical scalar encoding is already little-endian.
 Self::serialize(scalar)
 }
}

/// `decaf377::Element` with an `Eq` impl.
///
/// `frost-core`'s [`Group::Element`] requires `Eq`; decaf377 derives only
/// `PartialEq`. The missing impl is a marker, not behaviour — decaf377's
/// equality is equality in the prime-order quotient group, which is an
/// equivalence relation — so asserting it here is sound. Everything else is
/// arithmetic forwarded to the inner element.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct Decaf377Element(pub Element);

// Sound: decaf377 equality is equality in the prime-order quotient group, so
// it is reflexive. `Eq` cannot be derived because the inner type does not
// declare it.
impl Eq for Decaf377Element {}

impl Decaf377Element {
 /// The wrapped element.
 #[inline]
 pub fn into_inner(self) -> Element {
 self.0
 }
}

impl From<Element> for Decaf377Element {
 #[inline]
 fn from(e: Element) -> Self {
 Self(e)
 }
}

impl Add for Decaf377Element {
 type Output = Self;
 #[inline]
 fn add(self, rhs: Self) -> Self {
 Self(self.0 + rhs.0)
 }
}

impl Sub for Decaf377Element {
 type Output = Self;
 #[inline]
 fn sub(self, rhs: Self) -> Self {
 Self(self.0 - rhs.0)
 }
}

impl Mul<Fr> for Decaf377Element {
 type Output = Self;
 #[inline]
 fn mul(self, rhs: Fr) -> Self {
 Self(self.0 * rhs)
 }
}

/// The decaf377 group, as a `frost-core` [`Group`].
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Decaf377Group;

impl Group for Decaf377Group {
 type Field = Decaf377ScalarField;
 type Element = Decaf377Element;
 type Serialization = [u8; 32];

 fn cofactor() -> <Self::Field as Field>::Scalar {
 // decaf377 is a prime-order group by construction.
 Fr::ONE
 }

 fn identity() -> Self::Element {
 Decaf377Element(Element::IDENTITY)
 }

 fn generator() -> Self::Element {
 Decaf377Element(Element::GENERATOR)
 }

 fn serialize(element: &Self::Element) -> Result<Self::Serialization, GroupError> {
 if *element == Self::identity() {
 return Err(GroupError::InvalidIdentityElement);
 }
 Ok(element.0.vartime_compress().0)
 }

 fn deserialize(buf: &Self::Serialization) -> Result<Self::Element, GroupError> {
 let element = Decaf377Element(
 Encoding(*buf)
 .vartime_decompress()
 .map_err(|_| GroupError::MalformedElement)?,
 );
 if element == Self::identity() {
 Err(GroupError::InvalidIdentityElement)
 } else {
 Ok(element)
 }
 }
}

fn hash_to_array(inputs: &[&[u8]]) -> [u8; 64] {
 let mut h = Sha512::new();
 for i in inputs {
 h.update(i);
 }
 let mut output = [0u8; 64];
 output.copy_from_slice(h.finalize().as_ref());
 output
}

fn hash_to_scalar(inputs: &[&[u8]]) -> Fr {
 Fr::from_le_bytes_mod_order(&hash_to_array(inputs))
}

/// Context string for this ciphersuite.
///
/// Not an RFC 9591 registered suite — see the module docs. The `-v1` suffix is
/// the version of *this* construction.
const CONTEXT_STRING: &str = "FROST-decaf377-SHA512-v1";

/// FROST(decaf377, SHA-512).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Decaf377Sha512;

impl Ciphersuite for Decaf377Sha512 {
 const ID: &'static str = CONTEXT_STRING;

 type Group = Decaf377Group;
 type HashOutput = [u8; 64];
 type SignatureSerialization = [u8; 64];

 /// H1, the binding factor hash.
 fn H1(m: &[u8]) -> <<Self::Group as Group>::Field as Field>::Scalar {
 hash_to_scalar(&[CONTEXT_STRING.as_bytes(), b"rho", m])
 }

 /// H2, the challenge hash.
 fn H2(m: &[u8]) -> <<Self::Group as Group>::Field as Field>::Scalar {
 hash_to_scalar(&[CONTEXT_STRING.as_bytes(), b"chal", m])
 }

 /// H3, the nonce generation hash.
 fn H3(m: &[u8]) -> <<Self::Group as Group>::Field as Field>::Scalar {
 hash_to_scalar(&[CONTEXT_STRING.as_bytes(), b"nonce", m])
 }

 /// H4, the message hash.
 fn H4(m: &[u8]) -> Self::HashOutput {
 hash_to_array(&[CONTEXT_STRING.as_bytes(), b"msg", m])
 }

 /// H5, the commitment hash.
 fn H5(m: &[u8]) -> Self::HashOutput {
 hash_to_array(&[CONTEXT_STRING.as_bytes(), b"com", m])
 }

 /// HDKG, the DKG proof-of-knowledge hash.
 fn HDKG(m: &[u8]) -> Option<<<Self::Group as Group>::Field as Field>::Scalar> {
 Some(hash_to_scalar(&[CONTEXT_STRING.as_bytes(), b"dkg", m]))
 }

 /// HID, the identifier derivation hash.
 fn HID(m: &[u8]) -> Option<<<Self::Group as Group>::Field as Field>::Scalar> {
 Some(hash_to_scalar(&[CONTEXT_STRING.as_bytes(), b"id", m]))
 }
}
