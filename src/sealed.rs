//! Confidential, authenticated delivery of DKG round-2 sub-shares.
//!
//! # Why this exists
//!
//! [`dkg::Dealer::generate_subshare`](crate::dkg::Dealer::generate_subshare)
//! returns a plaintext scalar, and the module docs have always said "sends
//! sub-share f_i(j) to participant j (encrypted)" — while nothing in the crate
//! encrypted anything and `SubShare::to_bytes` handed out the 40-byte
//! plaintext. That is a defensible boundary for a `no_std` core. It is not
//! defensible with no sealed alternative, because the failure is silent and
//! total: a dealer's polynomial has degree `t-1` and is pinned down by `t`
//! points, so round 2 puts `n-1` evaluations of every dealer's polynomial on
//! the wire and for any `n > t` — 2-of-3 included — an observer interpolates
//! them and holds the group signing key. RFC 9591 requires round 2 to be
//! confidential as well as authenticated.
//!
//! This is a critical finding of the 2026-09 review, observed in
//! `narsild`, which sent sub-shares as plaintext JSON over HTTP *and*
//! broadcast each one to every peer.
//!
//! # Why Noise_K, and why `snow`
//!
//! This is lifted from `/steam/rotko/zcli/crates/frost-spend/src/sealed.rs`,
//! which solved the same problem for the same reason and whose rationale is
//! the argument above, arrived at independently. It uses
//! **`Noise_K_25519_ChaChaPoly_BLAKE2s`** via `snow`, which is also what ZF's
//! `frost-client` uses for FROST DKG round 2 — so this is the ecosystem's
//! transport rather than one of our own devising. That matters more than any
//! property below: a reviewer can ask "is Noise_K used correctly", which is
//! answerable, instead of "is this bespoke construction sound", which is not.
//! Hand-rolling X25519 + HKDF + ChaCha20-Poly1305 would have bound the same
//! three things through associated data and left the argument ours to defend,
//! so `snow` it is — the same version zcli pins.
//!
//! `K` is what makes it usable here: both parties' static keys are known in
//! advance, so the handshake is a SINGLE message with no round trip. Round 1
//! already broadcasts each participant's static key.
//!
//! # What it binds
//!
//! - **recipient** — it is the responder's static key; nobody else opens it;
//! - **sender** — the `ss` mix puts the sender's static key into the key
//!   schedule itself, not merely into a signature wrapped around the
//!   ciphertext. A MITM cannot substitute a sub-share, because it cannot
//!   produce a message that opens under the pair;
//! - **ceremony** — the roster, session id and round number are the Noise
//!   prologue, so both sides must agree on the full participant set or the
//!   message does not open. This is what stops a package being replayed into
//!   another ceremony, and it closes round 1's last-write-wins problem along
//!   with it;
//! - **the commitment the sub-share belongs to** — the sealed plaintext
//!   carries a digest of the dealer's Feldman commitment, checked on open.
//!   Verifying a value against a commitment the attacker also chose proves
//!   nothing; here the pair is bound together and to the sender.
//!
//! # What it does not do
//!
//! It is not a transport. A deployment still needs an index→peer map so a
//! sealed package reaches one recipient rather than all of them, and a signed
//! roster so the static keys are the right ones. What this module guarantees
//! is that broadcasting a sealed package to the wrong peer, or to everyone,
//! discloses nothing.

use alloc::vec;
use alloc::vec::Vec;

use hkdf::Hkdf;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::curve::{CurvePoint, CurveScalar};
use crate::dkg::BadSubShareEvidence;
use crate::error::Error;
use crate::reshare::{DealerCommitment, SubShare};

/// The Noise pattern. Identical to ZF `frost-client`'s and zcli's,
/// deliberately.
pub const NOISE_PATTERN: &str = "Noise_K_25519_ChaChaPoly_BLAKE2s";

/// Separation tag for deriving a participant's X25519 static key from its
/// existing identity seed.
///
/// frostito-specific rather than zcli's tag: a node may link both, and the two
/// ceremonies must not share a key.
pub const X25519_DERIVE_INFO: &[u8] = b"frostito/sealed/x25519/v1";

/// Domain tag for the ceremony transcript.
pub const TRANSCRIPT_DOMAIN: &[u8] = b"frostito/sealed/transcript/v1";

/// Domain tag for the Noise prologue.
pub const PROLOGUE_DOMAIN: &[u8] = b"frostito/sealed/prologue/v1";

/// Domain tag for the sealed-ciphertext digest carried in complaint evidence.
pub const SEALED_DIGEST_DOMAIN: &[u8] = b"frostito/sealed/ciphertext/v1";

/// Domain tag for the commitment digest carried in a sealed package.
///
/// Re-exported from [`crate::dkg`], where it lives so that
/// [`crate::dkg::Complaint::verify`] — which is compiled without this feature
/// — can recompute the same digest.
pub use crate::dkg::COMMITMENT_DIGEST_DOMAIN;

/// Derive a participant's X25519 static secret from its identity seed.
///
/// Deriving rather than storing means no new key has to be distributed: the
/// participant advertises [`x25519_public_from_seed`] in round 1 alongside its
/// Feldman commitment. This is a KDF, not key reuse — the signing key is the
/// seed, the decryption key is HKDF(seed); they share an ancestor, not an
/// exponent.
pub fn x25519_secret_from_seed(seed: &[u8; 32]) -> [u8; 32] {
 let hk = Hkdf::<Sha256>::new(None, seed);
 let mut out = [0u8; 32];
 hk.expand(X25519_DERIVE_INFO, &mut out)
 .expect("32 bytes is a valid HKDF-SHA256 length");
 out
}

/// The X25519 public key a participant advertises in round 1.
pub fn x25519_public_from_seed(seed: &[u8; 32]) -> [u8; 32] {
 let sk = StaticSecret::from(x25519_secret_from_seed(seed));
 PublicKey::from(&sk).to_bytes()
}

/// The participant set of one DKG ceremony: every participant's identifier and
/// static X25519 key, plus the session id.
///
/// Fixed when round 1 closes and identical on every node. It is hashed into
/// the Noise prologue, so two nodes that disagree about who is in the ceremony
/// — or about which ceremony this is — cannot exchange a sealed package at all.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedRoster {
 participants: Vec<(u32, [u8; 32])>,
 session_id: [u8; 32],
}

impl SealedRoster {
 /// Build a roster. Participants are sorted by index, so the transcript does
 /// not depend on the order round-1 broadcasts happened to arrive in.
 ///
 /// # Errors
 ///
 /// [`Error::EmptyContributions`] for an empty set,
 /// [`Error::InvalidIndex`] for index 0, and
 /// [`Error::DuplicateIndex`] for a repeated identifier.
 pub fn new(
 participants: &[(u32, [u8; 32])],
 session_id: [u8; 32],
 ) -> Result<Self, Error> {
 if participants.is_empty() {
 return Err(Error::EmptyContributions);
 }
 let mut sorted = participants.to_vec();
 sorted.sort_by_key(|(i, _)| *i);
 if sorted[0].0 == 0 {
 return Err(Error::InvalidIndex);
 }
 for w in sorted.windows(2) {
 if w[0].0 == w[1].0 {
 return Err(Error::DuplicateIndex(w[0].0));
 }
 }
 Ok(Self {
 participants: sorted,
 session_id,
 })
 }

 /// Participants, sorted by index.
 #[inline]
 pub fn participants(&self) -> &[(u32, [u8; 32])] {
 &self.participants
 }

 /// The ceremony's session id.
 #[inline]
 pub fn session_id(&self) -> &[u8; 32] {
 &self.session_id
 }

 /// A participant's advertised static key.
 pub fn public_key(&self, index: u32) -> Result<&[u8; 32], Error> {
 self.participants
 .iter()
 .find(|(i, _)| *i == index)
 .map(|(_, k)| k)
 .ok_or(Error::UnknownParticipant(index))
 }

 /// Hash over the whole participant set — the ceremony's fingerprint.
 ///
 /// Length-prefixed rather than concatenated: without the prefixes, two
 /// different rosters could hash alike and a participant who chooses part
 /// of the input could exploit it.
 pub fn transcript(&self) -> [u8; 32] {
 let mut h = Sha256::new();
 h.update(TRANSCRIPT_DOMAIN);
 h.update((self.participants.len() as u64).to_le_bytes());
 for (index, key) in &self.participants {
 h.update(index.to_le_bytes());
 h.update(key);
 }
 h.update(self.session_id);
 h.finalize().into()
 }

 /// The Noise prologue for one round of this ceremony.
 pub fn prologue(&self, round: u8) -> Vec<u8> {
 let mut out = Vec::with_capacity(PROLOGUE_DOMAIN.len() + 65);
 out.extend_from_slice(PROLOGUE_DOMAIN);
 out.extend_from_slice(&self.transcript());
 out.extend_from_slice(&self.session_id);
 out.push(round);
 out
 }
}

/// A sub-share sealed to one recipient.
///
/// The indices are in the clear because a transport needs them to route; they
/// are also inside the ciphertext, and the two are checked to agree on open,
/// so relabelling a package achieves nothing.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealedSubShare {
 pub dealer_index: u32,
 pub recipient_index: u32,
 /// Noise_K message: ephemeral ‖ ciphertext ‖ tag.
 pub ciphertext: Vec<u8>,
}

/// Digest of a dealer's Feldman commitment, carried inside the sealed
/// plaintext so the sub-share and the commitment it is verified against cannot
/// be sourced separately.
///
/// Re-exported from [`crate::dkg`]: a complaint's evidence names the agreed
/// commitment by this digest, and the complaint verifier is compiled with or
/// without the `sealed` feature.
pub use crate::dkg::commitment_digest;

/// SHA-256 of a sealed package's ciphertext, as delivered.
///
/// Carried in [`crate::dkg::BadSubShareEvidence`] so a verdict names one
/// delivered package rather than a claim in the abstract.
pub fn sealed_ciphertext_digest(ciphertext: &[u8]) -> [u8; 32] {
 let mut h = Sha256::new();
 h.update(SEALED_DIGEST_DOMAIN);
 h.update((ciphertext.len() as u64).to_le_bytes());
 h.update(ciphertext);
 h.finalize().into()
}

fn noise_seal(
 local_private: &[u8; 32],
 remote_public: &[u8; 32],
 prologue: &[u8],
 plaintext: &[u8],
) -> Option<Vec<u8>> {
 let mut noise = snow::Builder::new(NOISE_PATTERN.parse().ok()?)
 .prologue(prologue)
 .local_private_key(local_private)
 .remote_public_key(remote_public)
 .build_initiator()
 .ok()?;
 let mut out = vec![0u8; plaintext.len() + 128];
 let n = noise.write_message(plaintext, &mut out).ok()?;
 out.truncate(n);
 Some(out)
}

fn noise_open(
 local_private: &[u8; 32],
 remote_public: &[u8; 32],
 prologue: &[u8],
 message: &[u8],
) -> Option<Vec<u8>> {
 let mut noise = snow::Builder::new(NOISE_PATTERN.parse().ok()?)
 .prologue(prologue)
 .local_private_key(local_private)
 .remote_public_key(remote_public)
 .build_responder()
 .ok()?;
 let mut out = vec![0u8; message.len() + 128];
 let n = noise.read_message(message, &mut out).ok()?;
 out.truncate(n);
 Some(out)
}

/// Seal one sub-share from a dealer to one recipient.
///
/// `dealer_x25519_secret` is the dealer's static secret
/// ([`x25519_secret_from_seed`]); the recipient's public key comes from the
/// roster. `commitment` is the dealer's own Feldman commitment — its digest
/// travels inside the ciphertext.
///
/// # Errors
///
/// [`Error::UnknownParticipant`] if the recipient is not on the roster;
/// [`Error::InvalidIndex`] if the sub-share does not address that
/// recipient or does not come from `commitment`'s dealer;
/// [`Error::SealedOpenFailed`] if Noise refuses the key material.
pub fn seal_subshare<P: CurvePoint>(
 dealer_x25519_secret: &[u8; 32],
 roster: &SealedRoster,
 round: u8,
 subshare: &SubShare<P::Scalar>,
 commitment: &DealerCommitment<P>,
) -> Result<SealedSubShare, Error> {
 if subshare.dealer_index != commitment.dealer_index {
 return Err(Error::InvalidIndex);
 }
 let recipient = roster.public_key(subshare.player_index)?;
 roster.public_key(subshare.dealer_index)?;

 let mut plaintext = Vec::with_capacity(72);
 plaintext.extend_from_slice(&subshare.encode_plaintext());
 plaintext.extend_from_slice(&commitment_digest(commitment));

 let ciphertext = noise_seal(
 dealer_x25519_secret,
 recipient,
 &roster.prologue(round),
 &plaintext,
 )
 .ok_or(Error::SealedOpenFailed(subshare.dealer_index))?;

 Ok(SealedSubShare {
 dealer_index: subshare.dealer_index,
 recipient_index: subshare.player_index,
 ciphertext,
 })
}

/// Open a sealed sub-share and verify it against the dealer's commitment.
///
/// The Feldman check runs here, inside, so a caller cannot forget it and the
/// failure names the dealer. Four things must hold: the package opens under
/// (this recipient's static key, the named dealer's static key, this
/// ceremony's prologue); the indices inside match the indices outside; the
/// commitment digest inside matches the commitment supplied; and the sub-share
/// verifies against that commitment.
///
/// # Errors
///
/// [`Error::SealedOpenFailed`] — deliberately uninformative — when the
/// package does not open or its indices disagree with its envelope;
/// [`Error::InvalidSubShare`] when it opens but the commitment digest or
/// the Feldman check fails; [`Error::UnknownParticipant`] for a dealer the
/// roster does not name.
pub fn open_subshare<P: CurvePoint>(
 recipient_x25519_secret: &[u8; 32],
 recipient_index: u32,
 roster: &SealedRoster,
 round: u8,
 sealed: &SealedSubShare,
 commitment: &DealerCommitment<P>,
) -> Result<SubShare<P::Scalar>, Error> {
 let dealer = roster.public_key(sealed.dealer_index)?;
 if sealed.recipient_index != recipient_index {
 return Err(Error::SealedOpenFailed(sealed.dealer_index));
 }

 let plaintext = noise_open(
 recipient_x25519_secret,
 dealer,
 &roster.prologue(round),
 &sealed.ciphertext,
 )
 .ok_or(Error::SealedOpenFailed(sealed.dealer_index))?;

 if plaintext.len() != 72 {
 return Err(Error::SealedOpenFailed(sealed.dealer_index));
 }
 let subshare_bytes: [u8; 40] = plaintext[..40].try_into().unwrap();
 let subshare = SubShare::<P::Scalar>::decode_plaintext(&subshare_bytes)?;

 if subshare.dealer_index != sealed.dealer_index
 || subshare.player_index != sealed.recipient_index
 {
 return Err(Error::SealedOpenFailed(sealed.dealer_index));
 }

 // the sub-share and the commitment it is checked against must be the
 // pair the dealer sent, not two values an attacker sourced separately.
 if subshare.dealer_index != commitment.dealer_index
 || plaintext[40..] != commitment_digest(commitment)
 {
 return Err(Error::InvalidSubShare(sealed.dealer_index));
 }

 if !commitment.verify_subshare(recipient_index, subshare.value()) {
 return Err(Error::InvalidSubShare(sealed.dealer_index));
 }

 Ok(subshare)
}

/// [`open_subshare`], with the dealer's commitment taken from the agreed
/// round-1 set instead of from the caller.
///
/// `open_subshare` asks the caller for the commitment to check against, and
/// the caller's obvious source is whatever arrived alongside the sub-share —
/// which is exactly what a malicious dealer controls. A confirmed
/// [`AgreedRound1`](crate::dkg::AgreedRound1) is the set every participant
/// echoed and agreed on, so
/// looking the commitment up in it closes the equivocation gap left open:
/// a dealer that sent Alice `C_A` and Bob `C_B` cannot have both in the agreed
/// set, and the echo round refuses to start round 2 at all when they disagree.
///
/// This is the round-2 entry point a caller with a reliable broadcast should
/// use. `open_subshare` remains for callers that manage the commitment set
/// themselves, and [`open_subshare_agreed_with_evidence`] is this function
/// keeping the rejected plaintext so the recipient can raise a complaint
/// anyone else can re-check.
///
/// # Errors
///
/// [`Error::UnexpectedDealer`] if the agreed set has no commitment for the
/// package's dealer — it was disqualified, or it never entered the ceremony —
/// plus every error of [`open_subshare`].
pub fn open_subshare_agreed<P: CurvePoint>(
 recipient_x25519_secret: &[u8; 32],
 recipient_index: u32,
 roster: &SealedRoster,
 round: u8,
 sealed: &SealedSubShare,
 agreed: &crate::dkg::AgreedRound1<P>,
) -> Result<SubShare<P::Scalar>, Error> {
 open_subshare_agreed_with_evidence::<P>(
 recipient_x25519_secret,
 recipient_index,
 roster,
 round,
 sealed,
 agreed,
 )
 .map_err(OpenFailure::into_error)
}

/// Why [`open_subshare_agreed_with_evidence`] refused a package.
///
/// The split matters: only [`BadSubShare`](Self::BadSubShare) is an accusation
/// anyone else can check. Everything else is local — a package that did not
/// open could as easily be a corrupted byte on the wire as a hostile dealer,
/// and a node that broadcast an accusation for it would be the denial-of-
/// service channel is about.
#[derive(Debug)]
pub enum OpenFailure {
 /// Not an accusation: the package did not open under this ceremony's keys
 /// and prologue, its envelope disagreed with its contents, the dealer is
 /// not in the agreed set, or the plaintext was malformed. Handle locally.
 Local(Error),
 /// The package opened, and the scalar inside fails the Feldman check
 /// against the dealer's commitment in the agreed round-1 set.
 ///
 /// The evidence is transferable as far as "this scalar is not a valid
 /// sub-share for that commitment" and no further — see
 /// [`crate::dkg::BadSubShareEvidence`]. Sign it into a
 /// [`Complaint`](crate::dkg::Complaint), broadcast it, and require `t`
 /// independent upheld complaints ([`crate::dkg::ComplaintTally`]) before
 /// disqualifying the dealer.
 BadSubShare { evidence: BadSubShareEvidence },
}

impl OpenFailure {
 /// The equivalent [`Error`], discarding any evidence — what
 /// [`open_subshare_agreed`] returns.
 pub fn into_error(self) -> Error {
 match self {
 Self::Local(e) => e,
 Self::BadSubShare { evidence } => Error::InvalidSubShare(evidence.dealer_index),
 }
 }
}

impl From<Error> for OpenFailure {
 fn from(e: Error) -> Self {
 Self::Local(e)
 }
}

impl core::fmt::Display for OpenFailure {
 fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
 match self {
 Self::Local(e) => write!(f, "{}", e),
 Self::BadSubShare { evidence } => write!(
 f,
 "sub-share from dealer {} fails the Feldman check against the agreed commitment",
 evidence.dealer_index
 ),
 }
 }
}

impl std::error::Error for OpenFailure {}

/// [`open_subshare_agreed`], keeping the rejected plaintext as complaint
/// evidence.
///
/// # Why this exists
///
/// `open_subshare_agreed` drops the decrypted scalar the moment the Feldman
/// check fails, which is the right default for a value that is secret until it
/// is proven not to be — but it leaves a recipient that has just been cheated
/// with nothing to say. It can abort, and the others finalize: the split-group
/// outcome. Nothing it could broadcast would be checkable by anyone else.
///
/// This entry point hands back
/// [`BadSubShareEvidence`] instead, which
/// every other participant re-checks against **its own**
/// [`AgreedRound1`](crate::dkg::AgreedRound1). The check is exact; the
/// attribution is not. Read
/// [`ComplaintEvidence`](crate::dkg::ComplaintEvidence) before acting on a
/// verdict, and gate disqualification on
/// [`ComplaintTally`](crate::dkg::ComplaintTally).
///
/// # What is and is not evidence
///
/// Only a Feldman failure is. A package that does not open, or whose indices
/// disagree with its envelope, is [`OpenFailure::Local`]: unauthenticated
/// bytes, and an accusation built from them would be an accusation anyone
/// could manufacture against anyone.
///
/// The commitment-digest field inside the sealed plaintext is checked
/// *after* the Feldman equation, deliberately. A scalar that fails Feldman is
/// accusable however the digest came out; a scalar that passes it but arrived
/// with the wrong digest is a protocol error with no evidentiary value, and
/// returns [`Error::InvalidSubShare`] as before.
///
/// # Errors
///
/// See [`OpenFailure`].
// The evidence is ~140 bytes, over clippy's `result_large_err` threshold. It is
// carried by value deliberately: it goes straight into a `ComplaintEvidence`,
// and a `Box` here would only move the allocation, not remove it.
#[allow(clippy::result_large_err)]
pub fn open_subshare_agreed_with_evidence<P: CurvePoint>(
 recipient_x25519_secret: &[u8; 32],
 recipient_index: u32,
 roster: &SealedRoster,
 round: u8,
 sealed: &SealedSubShare,
 agreed: &crate::dkg::AgreedRound1<P>,
) -> Result<SubShare<P::Scalar>, OpenFailure> {
 let commitment = agreed.commitment(sealed.dealer_index)?;
 let dealer = roster.public_key(sealed.dealer_index)?;
 if sealed.recipient_index != recipient_index {
 return Err(Error::SealedOpenFailed(sealed.dealer_index).into());
 }

 let plaintext = noise_open(
 recipient_x25519_secret,
 dealer,
 &roster.prologue(round),
 &sealed.ciphertext,
 )
 .ok_or(Error::SealedOpenFailed(sealed.dealer_index))?;

 if plaintext.len() != 72 {
 return Err(Error::SealedOpenFailed(sealed.dealer_index).into());
 }
 let subshare_bytes: [u8; 40] = plaintext[..40].try_into().unwrap();
 let subshare = SubShare::<P::Scalar>::decode_plaintext(&subshare_bytes)?;

 if subshare.dealer_index != sealed.dealer_index
 || subshare.player_index != sealed.recipient_index
 {
 return Err(Error::SealedOpenFailed(sealed.dealer_index).into());
 }

 // The accusable check, run against the *agreed* commitment.
 if !commitment.verify_subshare(recipient_index, subshare.value()) {
 return Err(OpenFailure::BadSubShare {
 evidence: BadSubShareEvidence {
 dealer_index: sealed.dealer_index,
 recipient_index,
 session_id: *roster.session_id(),
 round,
 subshare: subshare.value().to_bytes(),
 agreed_digest: commitment_digest(commitment),
 sealed_digest: sealed_ciphertext_digest(&sealed.ciphertext),
 },
 });
 }

 // the sub-share and the commitment must be the pair the dealer sent.
 // It passed the Feldman check, so there is nothing to accuse anyone of;
 // the package is still refused.
 if plaintext[40..] != commitment_digest(commitment) {
 return Err(Error::InvalidSubShare(sealed.dealer_index).into());
 }

 Ok(subshare)
}

/// Build a dealer's whole round-2 message set: one sealed package per roster
/// participant, the dealer included.
///
/// Sealing to oneself keeps the wire shape uniform and lets a node apply its
/// own sub-share by the same code path it applies everyone else's.
pub fn seal_round2<P: CurvePoint>(
 dealer: &crate::dkg::Dealer<P>,
 dealer_x25519_secret: &[u8; 32],
 roster: &SealedRoster,
 round: u8,
) -> Result<Vec<SealedSubShare>, Error> {
 let commitment = dealer.commitment();
 let mut out = Vec::with_capacity(roster.participants().len());
 for (index, _) in roster.participants() {
 let subshare = dealer.generate_subshare(*index).expect("index is 1-indexed by construction");
 out.push(seal_subshare::<P>(
 dealer_x25519_secret,
 roster,
 round,
 &subshare,
 commitment,
 )?);
 }
 Ok(out)
}

#[cfg(all(test, feature = "ristretto255"))]
mod tests {
 use super::*;
 use crate::curve::CurveScalar;
 use crate::dkg::Dealer;
 use curve25519_dalek::ristretto::RistrettoPoint;
 use rand::rngs::OsRng;

 type Point = RistrettoPoint;

 const SEED_1: [u8; 32] = [7u8; 32];
 const SEED_2: [u8; 32] = [9u8; 32];
 const SEED_3: [u8; 32] = [11u8; 32];
 const SESSION: [u8; 32] = [0x33u8; 32];
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
 fn the_x25519_key_is_not_the_identity_seed() {
 assert_ne!(x25519_secret_from_seed(&SEED_1), SEED_1);
 }

 #[test]
 fn the_roster_is_order_independent_and_unambiguous() {
 let a = (1u32, [1u8; 32]);
 let b = (2u32, [2u8; 32]);
 assert_eq!(
 SealedRoster::new(&[a, b], SESSION).unwrap().transcript(),
 SealedRoster::new(&[b, a], SESSION).unwrap().transcript()
 );
 assert_eq!(
 SealedRoster::new(&[a, a], SESSION),
 Err(Error::DuplicateIndex(1))
 );
 assert_eq!(
 SealedRoster::new(&[(0u32, [0u8; 32])], SESSION),
 Err(Error::InvalidIndex)
 );
 assert_eq!(SealedRoster::new(&[], SESSION), Err(Error::EmptyContributions));
 }

 /// The property the module exists for: the secret scalar is not on
 /// the wire, and the round trip still works.
 #[test]
 fn a_sealed_subshare_round_trips_and_hides_the_scalar() {
 let mut rng = OsRng;
 let r = roster(SESSION);
 let dealer: Dealer<Point> = Dealer::new(1, 2, &mut rng).expect("index is 1-indexed by construction");
 let subshare = dealer.generate_subshare(2).expect("index is 1-indexed by construction");
 let plaintext = subshare.encode_plaintext();

 let sealed = seal_subshare::<Point>(
 &x25519_secret_from_seed(&SEED_1),
 &r,
 ROUND,
 &subshare,
 dealer.commitment(),
 )
 .unwrap();

 assert!(
 !sealed
 .ciphertext
 .windows(32)
 .any(|w| w == &plaintext[8..40]),
 "the sub-share scalar must not appear on the wire"
 );

 let opened = open_subshare::<Point>(
 &x25519_secret_from_seed(&SEED_2),
 2,
 &r,
 ROUND,
 &sealed,
 dealer.commitment(),
 )
 .unwrap();
 assert_eq!(opened.value(), subshare.value());
 assert_eq!(opened.dealer_index, 1);
 assert_eq!(opened.player_index, 2);
 }

 /// a recipient that is sent a sub-share which fails the
 /// Feldman check keeps the plaintext as evidence, and every other node
 /// re-checks it against its own agreed set and reaches the same verdict.
 #[test]
 fn a_cheating_dealer_leaves_evidence_anyone_can_recheck() {
 use crate::dkg::{
 commitment_digest, Complaint, ComplaintEvidence, ComplaintTally, ComplaintVerdict,
 DkgState,
 };
 use crate::reshare::SubShare;
 use curve25519_dalek::scalar::Scalar;

 let mut rng = OsRng;
 let r = roster(SESSION);
 let (t, n, epoch) = (2u32, 3u32, 8u64);

 let dealers: Vec<Dealer<Point>> = (1..=n)
 .map(|i| Dealer::new(i, t, &mut rng).unwrap())
 .collect();
 let mut st = DkgState::<Point>::new(epoch, t, n);
 for d in &dealers {
 st.submit_commitment(d.round1_package(epoch, &mut rng))
 .unwrap();
 }
 let agreed = st.agreed_round1().unwrap();

 // Dealer 1 broadcast an honest commitment and then sealed a scalar
 // that is not f_1(2). The digest inside the package is the agreed
 // one, so is satisfied and only the Feldman check catches it.
 let junk = SubShare::<Scalar>::new(1, 2, Scalar::random(&mut rng)).unwrap();
 let sealed = seal_subshare::<Point>(
 &x25519_secret_from_seed(&SEED_1),
 &r,
 ROUND,
 &junk,
 dealers[0].commitment(),
 )
 .unwrap();

 // The old path tells recipient 2 nothing it can repeat to anyone.
 assert_eq!(
 open_subshare_agreed::<Point>(
 &x25519_secret_from_seed(&SEED_2),
 2,
 &r,
 ROUND,
 &sealed,
 &agreed,
 )
 .unwrap_err(),
 Error::InvalidSubShare(1)
 );

 let err = open_subshare_agreed_with_evidence::<Point>(
 &x25519_secret_from_seed(&SEED_2),
 2,
 &r,
 ROUND,
 &sealed,
 &agreed,
 )
 .unwrap_err();
 let OpenFailure::BadSubShare { evidence } = err else {
 panic!("a Feldman failure is the accusable case");
 };
 assert_eq!(evidence.dealer_index, 1);
 assert_eq!(evidence.recipient_index, 2);
 assert_eq!(evidence.session_id, SESSION);
 assert_eq!(evidence.round, ROUND);
 assert_eq!(evidence.subshare, junk.value().to_bytes());
 assert_eq!(
 evidence.agreed_digest,
 commitment_digest(agreed.commitment(1).unwrap())
 );
 assert_eq!(
 evidence.sealed_digest,
 sealed_ciphertext_digest(&sealed.ciphertext)
 );
 assert!(
 alloc::format!("{:?}", evidence).contains("[REDACTED]"),
 "the scalar is redacted from Debug"
 );

 // Recipient 2 signs it; a third party with only the roster and its own
 // agreed set reaches the verdict.
 let accuser_secret = Scalar::random(&mut rng);
 let accuser_pk: Point =
 <Point as CurvePoint>::generator().mul_scalar(&accuser_secret);
 let complaint = Complaint::<Point>::sign(
 epoch,
 SESSION,
 ROUND,
 2,
 ComplaintEvidence::BadSubShare { evidence },
 &accuser_secret,
 &mut rng,
 )
 .unwrap();
 assert_eq!(
 complaint
 .verify(epoch, &SESSION, &accuser_pk, Some(&agreed))
 .unwrap(),
 ComplaintVerdict::Upheld
 );

 // ...and still does not disqualify dealer 1 on its own.
 let mut tally = ComplaintTally::new(t);
 tally.record(2, 1, ComplaintVerdict::Upheld).unwrap();
 assert!(!tally.reached(1));
 tally.record(3, 1, ComplaintVerdict::Upheld).unwrap();
 assert!(tally.reached(1), "t distinct accusers, and only then");
 }

 /// `open_subshare` takes the commitment from the caller, whose
 /// obvious source is whatever arrived alongside the sub-share — exactly
 /// what a malicious dealer controls. Both halves of an equivocation open
 /// and verify cleanly through that path; `open_subshare_agreed`, which
 /// looks the commitment up in the echoed round-1 set, accepts only the one
 /// the group agreed on.
 #[test]
 fn the_agreed_set_decides_which_commitment_a_subshare_is_checked_against() {
 use crate::dkg::DkgState;

 let mut rng = OsRng;
 let r = roster(SESSION);
 let (t, n, epoch) = (2u32, 3u32, 4u64);

 // dealer 1 equivocates: polynomial A toward recipient 2, B toward 3
 let evil_a: Dealer<Point> = Dealer::new(1, t, &mut rng).unwrap();
 let evil_b: Dealer<Point> = Dealer::new(1, t, &mut rng).unwrap();
 let honest: Vec<Dealer<Point>> = (2..=n)
 .map(|i| Dealer::new(i, t, &mut rng).unwrap())
 .collect();

 let sub_a = evil_a.generate_subshare(2).unwrap();
 let sealed_a = seal_subshare::<Point>(
 &x25519_secret_from_seed(&SEED_1),
 &r,
 ROUND,
 &sub_a,
 evil_a.commitment(),
 )
 .unwrap();

 // the pairing holds for the equivocated half: it opens, its digest
 // matches, and its Feldman check passes. Nothing here is wrong.
 open_subshare::<Point>(
 &x25519_secret_from_seed(&SEED_2),
 2,
 &r,
 ROUND,
 &sealed_a,
 evil_a.commitment(),
 )
 .expect("each pair is internally consistent — that is the finding");

 // recipient 2's agreed round-1 set contains dealer 1's OTHER
 // commitment, because that is what was broadcast and echoed
 let mut st = DkgState::<Point>::new(epoch, t, n);
 st.submit_commitment(evil_b.round1_package(epoch, &mut rng))
 .unwrap();
 for d in &honest {
 st.submit_commitment(d.round1_package(epoch, &mut rng))
 .unwrap();
 }
 let agreed = st.agreed_round1().unwrap();

 assert_eq!(
 open_subshare_agreed::<Point>(
 &x25519_secret_from_seed(&SEED_2),
 2,
 &r,
 ROUND,
 &sealed_a,
 &agreed,
 )
 .unwrap_err(),
 Error::InvalidSubShare(1),
 "a sub-share against a commitment outside the agreed set is refused"
 );

 // a dealer with no commitment in the agreed set at all is named as such
 let stranger: Dealer<Point> = Dealer::new(3, t, &mut rng).unwrap();
 let sub_s = stranger.generate_subshare(2).unwrap();
 let sealed_s = seal_subshare::<Point>(
 &x25519_secret_from_seed(&SEED_3),
 &r,
 ROUND,
 &sub_s,
 stranger.commitment(),
 )
 .unwrap();
 let mut thin = DkgState::<Point>::new(epoch, t, 1);
 thin.submit_commitment(evil_b.round1_package(epoch, &mut rng))
 .unwrap();
 assert_eq!(
 open_subshare_agreed::<Point>(
 &x25519_secret_from_seed(&SEED_2),
 2,
 &r,
 ROUND,
 &sealed_s,
 &thin.agreed_round1().unwrap(),
 )
 .unwrap_err(),
 Error::UnexpectedDealer(3)
 );
 }

 /// Recipient binding: it is the responder's static key, so no other
 /// participant opens it — which is what makes narsild's broadcast bug
 /// survivable rather than fatal.
 #[test]
 fn the_wrong_recipient_cannot_open_it() {
 let mut rng = OsRng;
 let r = roster(SESSION);
 let dealer: Dealer<Point> = Dealer::new(1, 2, &mut rng).expect("index is 1-indexed by construction");
 let sealed = seal_subshare::<Point>(
 &x25519_secret_from_seed(&SEED_1),
 &r,
 ROUND,
 &dealer.generate_subshare(2).expect("index is 1-indexed by construction"),
 dealer.commitment(),
 )
 .unwrap();

 // participant 3 receives the broadcast and tries its own key
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
 Error::SealedOpenFailed(1)
 );
 // ... and relabelling the envelope does not help
 let mut relabelled = sealed.clone();
 relabelled.recipient_index = 3;
 assert_eq!(
 open_subshare::<Point>(
 &x25519_secret_from_seed(&SEED_3),
 3,
 &r,
 ROUND,
 &relabelled,
 dealer.commitment(),
 )
 .unwrap_err(),
 Error::SealedOpenFailed(1)
 );
 }

 /// Sender binding: the `ss` mix puts the sender's static key in the
 /// key schedule, so a package cannot be reattributed — a MITM cannot
 /// re-sign someone else's sub-share as its own, and cannot manufacture one
 /// under a dealer index it does not hold the key for.
 #[test]
 fn a_package_cannot_be_reattributed_to_another_sender() {
 let mut rng = OsRng;
 let r = roster(SESSION);
 let dealer1: Dealer<Point> = Dealer::new(1, 2, &mut rng).expect("index is 1-indexed by construction");
 let dealer3: Dealer<Point> = Dealer::new(3, 2, &mut rng).expect("index is 1-indexed by construction");

 let sealed = seal_subshare::<Point>(
 &x25519_secret_from_seed(&SEED_1),
 &r,
 ROUND,
 &dealer1.generate_subshare(2).expect("index is 1-indexed by construction"),
 dealer1.commitment(),
 )
 .unwrap();

 // Mallory claims dealer 3 sent it.
 let mut claimed = sealed.clone();
 claimed.dealer_index = 3;
 assert_eq!(
 open_subshare::<Point>(
 &x25519_secret_from_seed(&SEED_2),
 2,
 &r,
 ROUND,
 &claimed,
 dealer3.commitment(),
 )
 .unwrap_err(),
 Error::SealedOpenFailed(3)
 );

 // And a dealer that does not hold participant 3's static secret
 // cannot produce a package that opens as dealer 3 either.
 let forged = seal_subshare::<Point>(
 &x25519_secret_from_seed(&[42u8; 32]),
 &r,
 ROUND,
 &dealer3.generate_subshare(2).expect("index is 1-indexed by construction"),
 dealer3.commitment(),
 )
 .unwrap();
 assert_eq!(
 open_subshare::<Point>(
 &x25519_secret_from_seed(&SEED_2),
 2,
 &r,
 ROUND,
 &forged,
 dealer3.commitment(),
 )
 .unwrap_err(),
 Error::SealedOpenFailed(3)
 );
 }

 /// the swapped pair: verifying a sub-share against a commitment the
 /// attacker also chose proves nothing, so the sealed plaintext carries a
 /// digest of the dealer's commitment and the two are checked together.
 #[test]
 fn a_commitment_and_subshare_from_different_dealings_do_not_pair() {
 let mut rng = OsRng;
 let r = roster(SESSION);
 let dealer: Dealer<Point> = Dealer::new(1, 2, &mut rng).expect("index is 1-indexed by construction");
 // the same dealer index, a different polynomial
 let other: Dealer<Point> = Dealer::new(1, 2, &mut rng).expect("index is 1-indexed by construction");

 let sealed = seal_subshare::<Point>(
 &x25519_secret_from_seed(&SEED_1),
 &r,
 ROUND,
 &dealer.generate_subshare(2).expect("index is 1-indexed by construction"),
 dealer.commitment(),
 )
 .unwrap();

 assert_eq!(
 open_subshare::<Point>(
 &x25519_secret_from_seed(&SEED_2),
 2,
 &r,
 ROUND,
 &sealed,
 other.commitment(),
 )
 .unwrap_err(),
 Error::InvalidSubShare(1),
 "a sub-share must not verify against a commitment it did not travel with"
 );

 // sealing a mismatched pair is refused at the source too
 assert_eq!(
 seal_subshare::<Point>(
 &x25519_secret_from_seed(&SEED_1),
 &r,
 ROUND,
 &dealer.generate_subshare(2).expect("index is 1-indexed by construction"),
 Dealer::<Point>::new(2, 2, &mut rng).unwrap().commitment(),
 )
 .unwrap_err(),
 Error::InvalidIndex
 );
 }

 /// Ceremony binding, via the prologue: a package from another session, or
 /// another round, or a ceremony with a different participant set, does not
 /// open.
 #[test]
 fn a_package_from_another_ceremony_does_not_open() {
 let mut rng = OsRng;
 let r = roster(SESSION);
 let dealer: Dealer<Point> = Dealer::new(1, 2, &mut rng).expect("index is 1-indexed by construction");
 let sealed = seal_subshare::<Point>(
 &x25519_secret_from_seed(&SEED_1),
 &r,
 ROUND,
 &dealer.generate_subshare(2).expect("index is 1-indexed by construction"),
 dealer.commitment(),
 )
 .unwrap();

 let sk2 = x25519_secret_from_seed(&SEED_2);

 // another session id
 let other_session = roster([0x44u8; 32]);
 assert_eq!(
 open_subshare::<Point>(&sk2, 2, &other_session, ROUND, &sealed, dealer.commitment())
 .unwrap_err(),
 Error::SealedOpenFailed(1)
 );

 // another round of the same ceremony
 assert_eq!(
 open_subshare::<Point>(&sk2, 2, &r, ROUND + 1, &sealed, dealer.commitment())
 .unwrap_err(),
 Error::SealedOpenFailed(1)
 );

 // a ceremony with a different participant set
 let smaller = SealedRoster::new(
 &[
 (1, x25519_public_from_seed(&SEED_1)),
 (2, x25519_public_from_seed(&SEED_2)),
 ],
 SESSION,
 )
 .unwrap();
 assert_eq!(
 open_subshare::<Point>(&sk2, 2, &smaller, ROUND, &sealed, dealer.commitment())
 .unwrap_err(),
 Error::SealedOpenFailed(1)
 );
 }

 #[test]
 fn tampering_is_detected() {
 let mut rng = OsRng;
 let r = roster(SESSION);
 let dealer: Dealer<Point> = Dealer::new(1, 2, &mut rng).expect("index is 1-indexed by construction");
 let mut sealed = seal_subshare::<Point>(
 &x25519_secret_from_seed(&SEED_1),
 &r,
 ROUND,
 &dealer.generate_subshare(2).expect("index is 1-indexed by construction"),
 dealer.commitment(),
 )
 .unwrap();
 let last = sealed.ciphertext.len() - 1;
 sealed.ciphertext[last] ^= 1;
 assert_eq!(
 open_subshare::<Point>(
 &x25519_secret_from_seed(&SEED_2),
 2,
 &r,
 ROUND,
 &sealed,
 dealer.commitment(),
 )
 .unwrap_err(),
 Error::SealedOpenFailed(1)
 );
 }

 /// Noise_K mixes a fresh ephemeral, so two seals of the same sub-share
 /// differ — otherwise the ceremony leaks which dealers sent equal packages.
 #[test]
 fn each_package_is_fresh() {
 let mut rng = OsRng;
 let r = roster(SESSION);
 let dealer: Dealer<Point> = Dealer::new(1, 2, &mut rng).expect("index is 1-indexed by construction");
 let sub = dealer.generate_subshare(2).expect("index is 1-indexed by construction");
 let sk = x25519_secret_from_seed(&SEED_1);
 let one = seal_subshare::<Point>(&sk, &r, ROUND, &sub, dealer.commitment()).unwrap();
 let two = seal_subshare::<Point>(&sk, &r, ROUND, &sub, dealer.commitment()).unwrap();
 assert_ne!(one.ciphertext, two.ciphertext);
 }

 /// The whole round 2, sealed: every dealer seals to every participant and
 /// each participant aggregates only what opens under its own key.
 #[test]
 fn a_sealed_round2_completes_the_dkg() {
 let mut rng = OsRng;
 let n = 3u32;
 let t = 2u32;
 let seeds = [SEED_1, SEED_2, SEED_3];
 let r = roster(SESSION);

 let dealers: Vec<Dealer<Point>> = (1..=n).map(|i| Dealer::new(i, t, &mut rng).expect("index is 1-indexed by construction")).collect();
 let wire: Vec<Vec<SealedSubShare>> = dealers
 .iter()
 .enumerate()
 .map(|(i, d)| {
 seal_round2::<Point>(d, &x25519_secret_from_seed(&seeds[i]), &r, ROUND).unwrap()
 })
 .collect();

 let mut shares = Vec::new();
 for j in 1..=n {
 let sk = x25519_secret_from_seed(&seeds[(j - 1) as usize]);
 let mut agg: crate::dkg::Aggregator<Point> =
 crate::dkg::Aggregator::all_dealers(j, n).unwrap();
 for (i, packages) in wire.iter().enumerate() {
 // Every package is on the wire; only one opens.
 let mut opened = 0;
 for pkg in packages {
 if pkg.recipient_index != j {
 continue;
 }
 let sub = open_subshare::<Point>(
 &sk,
 j,
 &r,
 ROUND,
 pkg,
 dealers[i].commitment(),
 )
 .unwrap();
 agg.add_subshare(sub, dealers[i].commitment()).unwrap();
 opened += 1;
 }
 assert_eq!(opened, 1);
 }
 shares.push(agg.finalize().unwrap());
 }

 // the shares interpolate to the group key the commitments predict
 let group_key = {
 let mut k = <Point as CurvePoint>::identity();
 for d in &dealers {
 k = k.add(d.commitment().share_commitment());
 }
 k
 };
 let lag = crate::compute_lagrange_coefficients::<
 <Point as CurvePoint>::Scalar,
 >(&[1, 2, 3])
 .unwrap();
 let mut secret = <<Point as CurvePoint>::Scalar as CurveScalar>::zero();
 for (i, s) in shares.iter().enumerate() {
 secret = secret.add(&lag[i].mul(s));
 }
 assert_eq!(<Point as CurvePoint>::generator().mul_scalar(&secret), group_key);
 }
}
