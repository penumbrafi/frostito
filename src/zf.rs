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



#[cfg(feature = "decaf377")]
mod decaf377_suite {
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
}

#[cfg(feature = "decaf377")]
pub use decaf377_suite::{
    Decaf377Element, Decaf377Group, Decaf377ScalarField, Decaf377Sha512,
};

// ============================================================================
// Driving `crate::nested` from a ZF signing package
// ============================================================================

use alloc::vec::Vec;

use crate::curve::{CurvePoint, CurveScalar};
use crate::error::Error as FrostitoError;
use crate::lagrange::compute_lagrange_coefficients;
use crate::nested::InnerSigningParamsV2;
use frost_core::{
    challenge, Field, Group, compute_binding_factor_list, compute_group_commitment, Ciphersuite as Cs,
    Element as ZfElement, Identifier, Scalar as CScalar, SigningPackage, VerifyingKey,
};

/// This crate's `u32` share index, from a ZF [`Identifier`].
///
/// Identifiers are field elements; this crate indexes shares by `u32`. For the
/// identifiers an implementation actually deals — small integers, canonically
/// little-endian — the two agree, and anything that does not fit is refused
/// rather than silently truncated to a different share.
pub fn identifier_to_index<C: Cs>(id: &Identifier<C>) -> Result<u32, FrostitoError> {
    let bytes = id.serialize();
    if bytes.len() < 4 || bytes[4..].iter().any(|b| *b != 0) {
        return Err(FrostitoError::InvalidIndex);
    }
    let v = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    if v == 0 {
        return Err(FrostitoError::InvalidIndex);
    }
    Ok(v)
}

/// The outer FROST context an inner holder needs, recomputed from a ZF
/// [`SigningPackage`] rather than from this crate's own FROST.
///
/// This is [`InnerSigningParamsV2::from_parts`] over `frost-core`: same three
/// values, same local derivation, so a coordinator still asserts none of them.
/// It is what lets a nested position sit inside a real RFC 9591 group.
///
/// Available for the backends whose element and scalar types this crate and
/// `frost-core` share — ristretto255 and secp256k1 — which the bounds express
/// directly rather than through a marker trait.
///
/// # Errors
///
/// [`FrostitoError::InvalidIndex`] if `nested_index` is not in the package or
/// an identifier does not fit a `u32`; [`FrostitoError::LagrangeError`] if the
/// coefficients cannot be formed.
pub fn inner_params_from_zf<C>(
    package: &SigningPackage<C>,
    verifying_key: &VerifyingKey<C>,
    nested_index: u32,
) -> Result<InnerSigningParamsV2<CScalar<C>>, FrostitoError>
where
    C: Cs,
    ZfElement<C>: CurvePoint<Scalar = CScalar<C>>,
    CScalar<C>: CurveScalar,
{
    let mut indices = Vec::with_capacity(package.signing_commitments().len());
    for id in package.signing_commitments().keys() {
        indices.push(identifier_to_index::<C>(id)?);
    }
    indices.sort_unstable();

    let pos = indices
        .iter()
        .position(|&i| i == nested_index)
        .ok_or(FrostitoError::InvalidIndex)?;
    let lagrange = compute_lagrange_coefficients::<CScalar<C>>(&indices)?;

    let nested_id: Identifier<C> = u16::try_from(nested_index)
        .map_err(|_| FrostitoError::InvalidIndex)?
        .try_into()
        .map_err(|_| FrostitoError::InvalidIndex)?;

    let factors = compute_binding_factor_list::<C>(package, verifying_key, &[])
        .map_err(|_| FrostitoError::InvalidCommitment)?;
    // `BindingFactor` exposes only its serialization, so the scalar comes
    // back through the field rather than out of the wrapper.
    let rho_bytes = factors
        .get(&nested_id)
        .ok_or(FrostitoError::InvalidIndex)?
        .serialize();
    let rho_ser = <<<C as Cs>::Group as Group>::Field as Field>::Serialization::try_from(
        &rho_bytes[..],
    )
    .map_err(|_| FrostitoError::InvalidResponse)?;
    let rho = <<<C as Cs>::Group as Group>::Field as Field>::deserialize(&rho_ser)
        .map_err(|_| FrostitoError::InvalidResponse)?;

    let r = compute_group_commitment::<C>(package, &factors)
        .map_err(|_| FrostitoError::InvalidCommitment)?;
    let c = challenge::<C>(&r.to_element(), verifying_key, package.message())
        .map_err(|_| FrostitoError::InvalidCommitment)?;

    Ok(InnerSigningParamsV2::from_parts(
        rho,
        c.to_scalar(),
        lagrange[pos],
    ))
}
