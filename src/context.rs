//! Epoch-bound signing contexts.
//!
//! A [`SigningContext`] is the thing a threshold group actually signs over.
//! Instead of handing the raw application message to
//! [`frost::SigningPackage`](crate::frost::SigningPackage), every signer binds
//! it to
//!
//! - the **epoch** the group's shares belong to, and
//! - a **manifest hash** committing to the group's membership/policy for that
//!   epoch,
//!
//! and signs the canonical encoding of the triple. The encoding is recomputed
//! independently by each signer from values it already holds, so a coordinator
//! cannot silently swap the epoch or the manifest out from under the group.
//!
//! # Why epoch binding
//!
//! [`reshare`](crate::reshare) is *key-preserving*: after a reshare the group
//! public key is unchanged, so a signature made with pre-rotation shares is
//! still a valid signature under the same key. That is the point of key
//! preservation, but it also means a rotation alone does not retire the old
//! shares — a quorum of stale shareholders could keep signing.
//!
//! Binding the epoch into the signed bytes closes that gap: a verifier that
//! knows the group is in epoch `n` reconstructs the context with `epoch = n`,
//! and a signature produced by an epoch `n-1` quorum over `epoch = n-1` bytes
//! simply does not verify against it.
//!
//! # Scope — read this before relying on it
//!
//! This mechanism works only where the **verifier is osst-aware**, i.e. where
//! the bytes being signed are chosen by this protocol: custody authorization,
//! escrow release, narsil-style spend approval, internal attestations.
//!
//! It does **not** apply to protocol-defined signatures, where the message is
//! fixed by an external consensus rule — a Zcash/Orchard `SpendAuthSig` over a
//! sighash, a Penumbra spend auth, a Bitcoin sighash. Those verifiers hash the
//! transaction, not our encoding, so there is nowhere to put the epoch, and a
//! key-preserving reshare leaves old shares able to produce valid spend
//! authorizations. Retiring shares for that case needs an on-chain key
//! rotation (a *new* group key), not a context wrapper.

use alloc::vec::Vec;
use sha2::{Digest, Sha256};

/// Domain separation tag for the canonical [`SigningContext`] encoding.
pub const SIGNING_CONTEXT_DOMAIN: &[u8] = b"frostito/signing-context/v1";

/// A message bound to the epoch and manifest it was authorized under.
///
/// Borrowing the message keeps this usable in `no_std` builds without an
/// allocation; [`SigningContext::encode`] is the only allocating operation.
///
/// ```
/// use frostito::context::SigningContext;
///
/// let ctx = SigningContext::new(7, [0xab; 32], b"release escrow 42");
/// let signed_bytes = ctx.encode();
///
/// // A verifier that believes the group is in epoch 7 rebuilds the same bytes.
/// assert_eq!(signed_bytes, SigningContext::new(7, [0xab; 32], b"release escrow 42").encode());
/// // One that believes it is in epoch 8 does not.
/// assert_ne!(signed_bytes, SigningContext::new(8, [0xab; 32], b"release escrow 42").encode());
/// ```
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SigningContext<'a> {
 /// Reshare epoch the signing shares belong to. Incremented by every
 /// reshare; see [`reshare`](crate::reshare).
 pub epoch: u64,
 /// Hash committing to the group manifest (membership, threshold, policy)
 /// in force for `epoch`.
 pub manifest_hash: [u8; 32],
 /// The application message being authorized.
 pub message: &'a [u8],
}

impl<'a> SigningContext<'a> {
 /// Bind `message` to `epoch` and `manifest_hash`.
 #[inline]
 pub fn new(epoch: u64, manifest_hash: [u8; 32], message: &'a [u8]) -> Self {
 Self {
 epoch,
 manifest_hash,
 message,
 }
 }

 /// Canonical encoding — the bytes the group signs.
 ///
 /// ```text
 /// len(domain) : u64 LE
 /// domain : SIGNING_CONTEXT_DOMAIN
 /// epoch : u64 LE
 /// manifest : 32 bytes
 /// len(message): u64 LE
 /// message : len(message) bytes
 /// ```
 ///
 /// Every variable-length field is length-prefixed, so the encoding is
 /// injective: distinct `(epoch, manifest_hash, message)` triples always
 /// produce distinct byte strings, and no message can be crafted to make
 /// one context's encoding collide with another's.
 pub fn encode(&self) -> Vec<u8> {
 let mut out = Vec::with_capacity(8 + SIGNING_CONTEXT_DOMAIN.len() + 8 + 32 + 8 + self.message.len());
 self.encode_into(&mut out);
 out
 }

 /// [`encode`](Self::encode), appending into an existing buffer.
 pub fn encode_into(&self, out: &mut Vec<u8>) {
 out.extend_from_slice(&(SIGNING_CONTEXT_DOMAIN.len() as u64).to_le_bytes());
 out.extend_from_slice(SIGNING_CONTEXT_DOMAIN);
 out.extend_from_slice(&self.epoch.to_le_bytes());
 out.extend_from_slice(&self.manifest_hash);
 out.extend_from_slice(&(self.message.len() as u64).to_le_bytes());
 out.extend_from_slice(self.message);
 }

 /// SHA-256 of the canonical encoding.
 ///
 /// A fixed-size stand-in for the full encoding, for callers that want to
 /// log, index or compare contexts without carrying the message around.
 /// Sign over [`encode`](Self::encode), not over this.
 pub fn digest(&self) -> [u8; 32] {
 let mut h = Sha256::new();
 h.update(self.encode());
 h.finalize().into()
 }
}

#[cfg(test)]
mod tests {
 use super::*;

 #[test]
 fn encoding_is_deterministic() {
 let a = SigningContext::new(3, [1u8; 32], b"pay alice");
 let b = SigningContext::new(3, [1u8; 32], b"pay alice");
 assert_eq!(a.encode(), b.encode());
 assert_eq!(a.digest(), b.digest());
 }

 #[test]
 fn epoch_changes_the_signed_bytes() {
 let m = [7u8; 32];
 assert_ne!(
 SigningContext::new(1, m, b"same message").encode(),
 SigningContext::new(2, m, b"same message").encode()
 );
 }

 #[test]
 fn manifest_changes_the_signed_bytes() {
 assert_ne!(
 SigningContext::new(1, [7u8; 32], b"same message").encode(),
 SigningContext::new(1, [8u8; 32], b"same message").encode()
 );
 }

 #[test]
 fn encoding_is_injective_across_field_boundaries() {
 // Without the message length prefix, a message could absorb bytes that
 // belong to a neighbouring field and two distinct contexts would encode
 // identically. Walk the message boundary and confirm they do not.
 let a = SigningContext::new(1, [0u8; 32], b"ab");
 let b = SigningContext::new(1, [0u8; 32], b"a");
 let c = SigningContext::new(1, [0u8; 32], b"");
 assert_ne!(a.encode(), b.encode());
 assert_ne!(b.encode(), c.encode());

 // A message that literally spells out another context's tail must not
 // collide with it either.
 let mut forged = Vec::new();
 forged.extend_from_slice(&2u64.to_le_bytes());
 forged.extend_from_slice(&[9u8; 32]);
 forged.extend_from_slice(&4u64.to_le_bytes());
 forged.extend_from_slice(b"evil");
 assert_ne!(
 SigningContext::new(1, [0u8; 32], &forged).encode(),
 SigningContext::new(2, [9u8; 32], b"evil").encode()
 );
 }

 #[test]
 fn encode_into_matches_encode() {
 let ctx = SigningContext::new(9, [4u8; 32], b"buffered");
 let mut buf = Vec::from(&b"prefix"[..]);
 ctx.encode_into(&mut buf);
 assert_eq!(&buf[..6], b"prefix");
 assert_eq!(&buf[6..], &ctx.encode()[..]);
 }

 #[test]
 fn encoding_layout_is_stable() {
 let ctx = SigningContext::new(0x0102_0304_0506_0708, [0xaa; 32], b"hi");
 let e = ctx.encode();
 let d = SIGNING_CONTEXT_DOMAIN.len();
 assert_eq!(&e[..8], &(d as u64).to_le_bytes());
 assert_eq!(&e[8..8 + d], SIGNING_CONTEXT_DOMAIN);
 assert_eq!(&e[8 + d..16 + d], &0x0102_0304_0506_0708u64.to_le_bytes());
 assert_eq!(&e[16 + d..48 + d], &[0xaa; 32]);
 assert_eq!(&e[48 + d..56 + d], &2u64.to_le_bytes());
 assert_eq!(&e[56 + d..], b"hi");
 assert_eq!(e.len(), 56 + d + 2);
 }
}

// The end-to-end property the type exists for: a signature produced by an
// epoch-n quorum does not verify as an epoch-n+1 authorization.
#[cfg(all(test, feature = "ristretto255", feature = "std"))]
mod frost_tests {
 use super::*;
 use crate::frost::{self, Signature, SigningPackage};
 use crate::{CurvePoint, CurveScalar, SecretShare};
 use alloc::vec::Vec;
 use curve25519_dalek::{ristretto::RistrettoPoint, scalar::Scalar};

 /// Deal a 2-of-3 sharing and sign `message` with signers 1 and 2.
 fn sign_2_of_3(message: &[u8]) -> (RistrettoPoint, Signature<RistrettoPoint>) {
 use rand::rngs::OsRng;
 let mut rng = OsRng;

 // Shamir polynomial f(x) = secret + a1·x, threshold 2.
 let secret = <Scalar as CurveScalar>::random(&mut rng);
 let a1 = <Scalar as CurveScalar>::random(&mut rng);
 let eval = |x: u32| {
 let xs = <Scalar as CurveScalar>::from_u32(x);
 secret.add(&a1.mul(&xs))
 };
 let group_pubkey = RistrettoPoint::generator().mul_scalar(&secret);

 let active: [u32; 2] = [1, 2];

 // Round 1.
 let mut nonces = Vec::new();
 let mut commitments = Vec::new();
 for &i in &active {
 let (n, c) = frost::commit::<RistrettoPoint, _>(i, &mut rng).expect("index is 1-indexed by construction");
 nonces.push((i, n));
 commitments.push(c);
 }

 // Round 2 — every signer independently builds the package over the
 // same context bytes.
 let package =
 SigningPackage::<RistrettoPoint>::new(message.to_vec(), commitments).unwrap();

 let mut sig_shares = Vec::new();
 for (i, n) in nonces {
 let share = SecretShare::new(i, eval(i)).expect("index is 1-indexed by construction");
 sig_shares
 .push(frost::sign::<RistrettoPoint>(&package, n, &share, &group_pubkey).unwrap());
 }

 let sig =
 frost::aggregate::<RistrettoPoint>(&package, &sig_shares, &group_pubkey, None).unwrap();
 (group_pubkey, sig)
 }

 #[test]
 fn signature_is_bound_to_its_epoch() {
 let manifest = [0x5a; 32];
 let msg = b"release the escrow";

 let epoch_7 = SigningContext::new(7, manifest, msg).encode();
 let (pubkey, sig) = sign_2_of_3(&epoch_7);

 // Verifies as what it is: an epoch-7 authorization.
 assert!(frost::verify_signature::<RistrettoPoint>(&pubkey, &epoch_7, &sig));

 // After a key-preserving reshare to epoch 8 the group key is unchanged,
 // so this signature is still a valid signature *under that key* — but
 // it is not a valid epoch-8 authorization, which is the point.
 let epoch_8 = SigningContext::new(8, manifest, msg).encode();
 assert!(!frost::verify_signature::<RistrettoPoint>(&pubkey, &epoch_8, &sig));

 // Swapping the manifest underneath it fails the same way.
 let other_manifest = SigningContext::new(7, [0x5b; 32], msg).encode();
 assert!(!frost::verify_signature::<RistrettoPoint>(&pubkey, &other_manifest, &sig));

 // And the raw message, unbound, is not what was signed at all.
 assert!(!frost::verify_signature::<RistrettoPoint>(&pubkey, msg, &sig));
 }
}
