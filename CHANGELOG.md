# changelog

## [Unreleased]

### the signing core is ZF frost-core

`src/frost.rs` is gone — 1,166 lines of FROST implementation replaced by
`frost-core`, which implements RFC 9591 and has been audited. `frost-core` is
no longer optional; it is the signing core.

**Every signature this crate produces changes.** The old implementation was
structurally correct FROST under context strings of our own
(`"frost-challenge-v1"`, `"frost-binding-v2"`) rather than the registered
ones, so it was a ciphersuite nobody else implemented. Signatures are now
ordinary RFC 9591 FROST and any conforming verifier accepts them. Keys are
unaffected.

- `nested`'s v2 signing path takes a `frost_core::SigningPackage` and a
  `VerifyingKey`: `inner_sign_v2`, `inner_sign_v2_spending`,
  `inner_sign_v2_with_context`, `verify_nested_commitment` and
  `NestedSigningRequest` are now generic over `C: Ciphersuite`.
- `InnerSigningParamsV2::from_outer` and `from_coordinator_checked` are
  removed; `zf::inner_params_from_zf` replaces the first and the second was
  already deprecated.
- `frost::{Nonces, SigningCommitments, SigningPackage, SignatureShare,
  Signature, commit, sign, aggregate, verify_signature}` are gone. Use
  `frost_core::{round1, round2, aggregate}` and its types.
- `zf-decaf377` and `zf` are gone as features. `zf-ristretto255` and
  `zf-secp256k1` remain, pulling ZF's ciphersuite crate for that backend;
  `zf::Decaf377Sha512` now needs only `decaf377`.
- removed with the code they exercised: `tests/audit_frost_core.rs`, the
  `from_coordinator_checked` tests, and the two `narsil_*` examples, whose
  escrow application moved out in 0.6.0. `tests/audit_nested_v2.rs` and
  `tests/zf_nested_equivalence.rs` cover the nested flow against `frost-core`
  and CI runs both.

`src/` drops from 10,551 lines to 9,103.

### nested FROST can sit inside a real RFC 9591 group

`zf::inner_params_from_zf` recomputes an inner holder's outer context — the
binding factor, the challenge and the Lagrange coefficient — from a
`frost_core::SigningPackage` instead of from this crate's own FROST. Same
local derivation as `InnerSigningParamsV2::from_outer`, so a coordinator still
asserts none of it, over `frost-core`'s `internals`.

Bounded on `Element<C>: CurvePoint` and `Scalar<C>: CurveScalar` rather than a
marker trait, which holds for ristretto255 and secp256k1 because the element
and scalar types are the same on both sides.

`tests/zf_differential.rs` checks the thing nested rests on, against the
audited implementation rather than against ourselves: assemble
`z = d + rho*e + lambda*c*sigma` by hand from the bridged context, and it
equals the share `frost_core::round2::sign` produces for that participant,
byte for byte. That is the "a nested position is indistinguishable from a flat
signer" claim, now with an external oracle.

Also: `InnerSigningParamsV2::from_parts`, and `zf` is no longer gated behind
`zf-decaf377` — the decaf377 ciphersuite is, the bridge is not.

## [0.6.0] - 2026-09-23

### pruned

Dead and duplicated code removed.

- **nested FROST v1** (`legacy-v1`, ~487 lines in `nested.rs`). Known-insecure,
  off by default, retained only so an existing deployment could compile while
  it migrated. The feature is gone.
- **the plaintext sub-share serializers** (`unsafe_plaintext`, ~46 lines in
  `reshare.rs`). `SubShare::{to_bytes, from_bytes}` put the secret Shamir
  scalar on the wire; `sealed::seal_subshare` serializes internally, so there
  was never a sound reason to enable them. The feature is gone.
- **`src/redpallas.rs`** (415 lines). After the escrow layer moved out, what
  remained was a RedPallas ciphersuite wrapping this crate's own FROST — which
  is not RFC 9591. ZF's `reddsa` provides the audited equivalent and
  `tests/reshare_zf_frost.rs` already uses it.
- clippy is clean at `--all-features --all-targets`.

`src/` drops from 11,502 lines to 10,548.

### renamed: `osst` -> `frostito`

The crate no longer contains the protocol it was named after, so the package
takes the repository's name. Package `frostito`, `use frostito::...`.

Identifiers follow: `OsstError` -> `Error`, `OsstPoint` -> `CurvePoint`,
`OsstScalar` -> `CurveScalar`, `OsstCurve` -> `Curve`.

**The wire domain tags change too**, from `b"osst/..."` to `b"frostito/..."` —
`DKG_POK_DOMAIN`, `COMPLAINT_SIG_DOMAIN`, `COMMITMENT_DIGEST_DOMAIN`,
`ECHO_DIGEST_DOMAIN`, the four `sealed` constants, `SIGNING_CONTEXT_DOMAIN`,
`LIVENESS_SIG_DOMAIN` and `CONTRIBUTION_SIG_MSG_DOMAIN`. Every proof-of-
knowledge, complaint signature, commitment digest, echo digest, sealed
transcript, signing context and liveness signature therefore changes. This is
deliberate — a rename that left the old tags on the wire would be worse — but
it means a ceremony cannot span the two versions.

`osst` 0.1.1 remains the only version ever published to crates.io and should
be yanked; `frostito` starts here.

`verify` rejects two contributions that carry the same Schnorr commitment.

The OSST challenge `c_i = H(u_i || payload)` does not bind the contributor's
index, so one nonce used across two indices over one payload gives
`s_i - s_j = c(x_i - x_j)` and publishes the difference of the two shares.
Unreachable by accident when a holder has one share; reachable when one process
holds several, which is what a weighted deployment looks like once a weight-`w`
validator is virtualized into `w` indices.

Rejecting does not undo the leak — the contributions are already published — it
refuses the aggregate and names the two indices. Binding the index into the
challenge is the actual fix and is a signature break on every backend; it is
not done here.

### removed: OSST

The OSST identification protocol is gone — `Contribution`, `verify`,
`verify_incremental`, `compute_weights`, `hash_to_challenge`,
`SecretShare::contribute`, `OsstProof`, `OsstBuilder`, the per-backend
`*Contribution` aliases, and `src/types.rs`.

Why, in the order it became clear:

- **Nothing in the crate used it.** Only its own API wrappers and test code.
  `osst::liveness` — the attestation niche it was supposed to serve — does not
  touch it, and does attestation *with* attribution, which OSST cannot.
- **The privacy claim was false.** `Contribution` carries a public `index`, and
  verification needs those indices for the Lagrange weights, so the verifier
  learns exactly which subset contributed. "Share-free" means the verifier does
  not need the individual `y_i`; it never meant the signer set was hidden.
- **FROST dominates it for signing.** 64 bytes against `t x 64`, a standard
  verifier instead of one only this crate implements, identifiable abort
  (RFC 9591 section 5.3), and the same `Y`-only verification.
- **Plain Schnorr dominates it for consensus.** A closed validator set already
  holds every `y_i`, which is precisely what OSST exists to avoid needing, so
  it paid the no-attribution cost for a benefit that did not apply.
- **It was upstream of the ciphersuite divergence.** OSST is why
  `OsstCurve`/`OsstPoint` had to exist, which is what made writing a separate
  FROST look cheap, which is how the non-standard context strings got there.

`SecretShare`, `compute_lagrange_coefficients` and the curve traits stay — the
DKG, reshare, nested and frost paths all use them.

The DKG tests that used an OSST proof as their success condition now assert the
property directly: any `t` dealt shares interpolate to the secret behind the
group key.

`src/lib.rs` drops from 1,092 lines to 179; the crate from 13,592 to 11,500.

### rooting in ZF frost-core

Steps toward replacing this crate's own signing math with ZF's audited
`frost-core`, so what remains is only what is genuinely ours.

- **`osst::zf`** (features `zf-decaf377` + `decaf377`) — `Decaf377Sha512`, a
  `frost_core::Ciphersuite` for decaf377, with its `Field` and `Group` impls.
  ZF ships ciphersuites for the other three backends
  (`frost-ristretto255`, `frost-secp256k1`, `reddsa` for Pallas); decaf377 is
  not an RFC 9591 registered suite, so this one is ours. It follows the
  FROST(ristretto255, SHA-512) structure with its own context string, so a
  signature under it cannot be reinterpreted under another suite.
- `Decaf377Element`, a newtype over `decaf377::Element` supplying the `Eq`
  that `frost_core::Group::Element` requires and decaf377 does not derive.
- new optional features `zf`, `zf-ristretto255`, `zf-secp256k1`,
  `zf-decaf377`, on `frost-core` 3.0 with `internals`.
- `tests/zf_decaf377.rs` — trusted-dealer keygen, commit, sign, aggregate and
  verify end to end inside `frost-core`; the full three-round DKG; and the two
  seams this crate's hardening plugs into, since `round1::Package` and
  `round2::Package` both serialize: an echo digest over the round-1 set, and
  round-2 packages as bytes for `osst::sealed` to carry.

- **`osst::frost` is not RFC 9591.** `tests/zf_differential.rs` drives this
  crate and `frost-core` from one set of ristretto255 key material and one set
  of nonces. The protocol structure matches — the challenge is `H(R || Y ||
  msg)` exactly as §4.6 specifies — but the context strings are ours
  (`"frost-challenge-v1"`, `"frost-binding-v2"`) rather than the registered
  `"FROST-RISTRETTO255-SHA512-v1"` with `"chal"`/`"rho"`. So it is correct
  FROST under a non-standard ciphersuite, and nothing outside this crate
  verifies its signatures.

  What that means for rooting the signing path in `frost-core`: it is a
  **signature-breaking migration on every backend**, not a refactor. The test
  pins both halves — key material is interchangeable (a share dealt here signs
  and verifies under `frost-core`), signatures are not, and neither verifier
  accepts the other's output.

- `frost::Nonces::from_scalars`, gated on `test`/`zf`, so both implementations
  can be driven from the same nonces. Not for deployments: [`commit`] samples.

### moved out

- the zk.poker escrow and jury-dispute layer leaves `osst::redpallas`
  (1,592 -> 415 lines): `JuryNetwork`, `setup_escrow`, `jury_sign_share`,
  `jury_sign_with_osst_consensus`, `nested_redpallas_sign`,
  `derive_address_bytes`, the dispute state machine (`DisputeOpen`,
  `JuryAccepted`, `PlayerDispute`, `JuryDispute`, `DisputeResolved`) and their
  nine tests. Application logic, not threshold cryptography, and nothing in
  this crate used it. Staged in `migration/zkpoker_escrow.rs` for zk.poker;
  the RedPallas ciphersuite itself stays.

### breaking

- `osst::redpallas::zcash` no longer exports the escrow layer (see above).
- new `OsstError::DuplicateCommitment(u32, u32)`. `OsstError` is not
  `#[non_exhaustive]`, so an exhaustive match on it no longer compiles.

### added

- `tests/audit_shared_nonce.rs` — the leak as arithmetic, the rejection, and a
  positive control with independent nonces.

## [0.5.1] - 2026-09-21

Closes the last item on the 2026-09-21 maintainer review's block list (ii):
the **M-6 residual**, round-2 complaint transferability.

0.5.0 gave a complaint a signature, a `(epoch, session_id, round)` binding and
a verdict, but a `BadSubShare` complaint was still something a caller could not
actually *raise*: `sealed::open_subshare_agreed` discards the decrypted scalar
the moment the Feldman check fails, so a cheated recipient could abort and log
and nothing else. `narsild` did exactly that, and the result was the
split-group outcome M-6 names — one node stops, the rest finalize.

Nominally a patch release, and **not** source-compatible: the only downstream
is `narsild`, updated in lockstep (`penumbrafi/penumbra` PR #31).

### added

- `sealed::open_subshare_agreed_with_evidence` — `open_subshare_agreed`, but a
  Feldman failure returns `Err(OpenFailure::BadSubShare { evidence })` instead
  of discarding the plaintext. Everything that is *not* accusable — a package
  that does not open, an envelope that disagrees with its contents, a dealer
  outside the agreed set — is `OpenFailure::Local`, because an accusation built
  from unauthenticated bytes is one anyone could manufacture against anyone.
  `open_subshare_agreed` is now this function with the evidence dropped.
- `dkg::BadSubShareEvidence` — the sub-share scalar, the digest of the dealer's
  commitment **in the agreed round-1 set**, dealer and recipient indices,
  session id, round, and the sealed ciphertext digest. Zeroizes on drop and
  redacts the scalar from `Debug`.
- `dkg::ComplaintTally` — counts **distinct** accusers with `Upheld` verdicts
  per accused dealer and gates disqualification on `t` of them. Refuses
  self-accusation and zero indices; a re-broadcast complaint seen twice counts
  once.
- `sealed::OpenFailure`, `sealed::sealed_ciphertext_digest`,
  `sealed::SEALED_DIGEST_DOMAIN`.
- `dkg::commitment_digest` and `dkg::COMMITMENT_DIGEST_DOMAIN`, moved from
  `sealed` (which re-exports them) so a complaint verifier compiled without the
  `sealed` feature can recompute the digest.

### breaking

| what changed | why |
|---|---|
| `ComplaintEvidence::BadSubShare` carries one `BadSubShareEvidence` instead of `{ commitment, revealed, sealed_digest }` | the accuser no longer supplies the commitment its own evidence is checked against |
| `Complaint::verify` takes `agreed: Option<&AgreedRound1<P>>` | the Feldman check runs against the **verifier's** agreed commitment |
| `Complaint::adjudicate` takes the same argument and returns `Result` | there must be no zero-argument path that adjudicates a `BadSubShare` |

### the honest version of what this buys

`Upheld` on a `BadSubShare` complaint means **"this scalar is not a valid
sub-share for that commitment"**. It does not mean "the dealer sent it".
Noise_K authenticates the sender to the recipient and nothing further, so a
malicious recipient can fabricate a plaintext its own key would have produced —
and that fabricated scalar fails the Feldman check exactly as a genuinely bad
one does. `Upheld` and `Unfounded` therefore cannot distinguish an honest
recipient from a lying one; `Unfounded` only ever appears when an accuser
complains about a sub-share that is in fact valid.

So the gate is quorum, not adjudication, and `ComplaintTally` is it: `t`
distinct accusers against the same dealer, so no tolerated coalition can frame
an honest one. `tests` carry the demonstration — a fabricated complaint against
a wholly honest dealer is `Upheld`, and a lone `Upheld` leaves
`disqualifiable()` empty.

Two residuals, both documented rather than fixed:

- **Exclusion.** A dealer that cheats at most `t-1` recipients is never
  disqualified. Those recipients hold no usable share from it and must decline
  to finalize; that is exclusion, not a split key, and it is detectable but not
  attributable. Closing it needs the GJKR dealer-defence round — the accused
  publishes `f_i(j)` for each complainant and everyone checks — which needs a
  reliable broadcast and a timeout, so it belongs to the protocol layer.
- **Revealing the scalar.** Publishing one evaluation of one dealer's
  polynomial is a real disclosure. It is acceptable because an `Upheld` verdict
  is itself the proof that the published value is *not* a point on the agreed
  polynomial: it discloses nothing about the agreed commitments, the group key,
  or the recipient's real share. The `Unfounded` case does publish a genuine
  point — and there the accuser has spent one of its own, named itself, and is
  still `t-1` short of anything.

## [0.5.0] - 2026-09-21

Follow-on security release addressing `REVIEW-2026-09-21-maintainer.md`, the
maintainer pass over 0.4.0. **Breaking**, and **signature-incompatible with
0.4.x on every backend** — see M-24 and M-12.

The 0.4.0 release closed everything the prior audit raised against this crate,
and this pass re-verified each closure against the code. Three findings were
new (M-5, M-12, M-25), and one of them — dealer equivocation behind the D-2 fix
— needed a protocol round rather than a patch. The rest of this release is the
list the review said it would block 0.5.0 on, plus the two it wanted but did
not block on.

The risk the review found has largely moved out of this crate and into
`narsild`, where a cryptographic core with good properties is exposed through
an HTTP surface with none. Nothing here fixes that; see the review's §(ii).

### breaking

| what changed | why |
|---|---|
| `SigningPackage::binding_factor(index, group_pubkey)` and `group_commitment(group_pubkey)` take the group key | M-24 |
| every signature this crate produces changes | M-24, M-12 |
| `NestedSigningRequest` loses `group_pubkey`, gains `inner_precommits` and `inner_threshold` | M-4, M-20, M-14 |
| `inner_sign_v2` / `inner_sign_v2_with_context` take `local_group_pubkey` | M-4 |
| `aggregate_inner_commitment_pair` and `verify_nested_commitment` take the precommitments | M-20 |
| `reshare::SubShare::{to_bytes, from_bytes}` need the new `unsafe_plaintext` feature and are deprecated there | M-25 |
| `InnerSigningParamsV2::from_coordinator_checked` is `#[deprecated]` | M-21 |
| `liveness::DealerContribution::signing_message` is length-prefixed, tag `osst/contribution-sig/v2` | M-12 |
| new `OsstError` variants: `UnknownQuorumMember`, `EchoMismatch`, `PrecommitMismatch`, `SessionSpent`, `InvalidComplaint` | M-14, M-5, M-20, M-13, M-6 |

### fixed — the wire and the API

- **M-24 (Info → fixed)** — the binding factor omitted the group public key,
  where RFC 9591 §4.4 puts it first in the binding-factor input. One commitment
  set and one message therefore gave the same ρ under every group key, so a
  signing transcript was not pinned to the key it was collected for — the
  freedom M-4 hands a coordinator that also gets to assert `Y`. Now
  `ρ_i = H("frost-binding-v2" ‖ Y ‖ len(m) ‖ m ‖ len(B) ‖ B ‖ i)`, RFC ordering
  with length prefixes instead of the RFC's intermediate hashes. Carried as
  A-2/Info since the prior audit; taken now because 0.5.0 already breaks the
  wire and carrying it further means carrying it a long time.

  `Y` is a parameter, deliberately not a field of `SigningPackage`: a package is
  coordinator-shaped data, and a group key read out of it would be the
  coordinator's assertion, which is M-4. The RedPallas package gets the same
  treatment — its hashes are osst's own construction and never were
  byte-compatible with ZF `frost-core`/`reddsa`, so `tests/reshare_zf_frost.rs`,
  which signs with ZF's own `SigningPackage`, is unaffected.

- **M-12 (Low)** — `DealerContribution::signing_message` concatenated a domain
  tag, the dealer commitment, the liveness proof and the caller's context with
  no length prefixes. `DealerCommitment::to_bytes` is variable-length with the
  threshold supplied out of band, so the commitment/liveness boundary was
  undetermined and the encoding was not injective. Every field is now
  length-prefixed and the tag is `osst/contribution-sig/v2` — the last
  `SCREAMING-CASE-V1` string in the crate. The regression test builds an
  explicit collision against the old rule and asserts the new encoding
  separates it.

- **M-25 (Low)** — D-1 residual. `reshare::SubShare::{to_bytes, from_bytes}`
  were plain `pub fn`s with no deprecation and no warning, one call away from
  the sealed API. Round 2 puts `n−1` evaluations of every dealer's polynomial on
  the wire, so `t` of those 40-byte strings reconstruct the group key; narsild
  reached for them and served the result over an unauthenticated HTTP GET. The
  encoding is now `pub(crate)`, and the public names are behind the new
  off-by-default **`unsafe_plaintext`** feature and `#[deprecated]` there. The
  only sound use is feeding `sealed::seal_subshare`, which does it internally
  without exposing the bytes. `SubShare` is the crate's only plaintext
  secret-share serializer.

- **M-4 (High, osst half) / M-21 (Low)** — `NestedSigningRequest` carried
  `group_pubkey`, so the outer group key arrived with the coordinator's request
  and went into the binding factor and the challenge. `from_coordinator_checked`
  did not save this: it recomputes ρ, c and λ *using the supplied `Y`*, so a
  substituted `Y'` yields a self-consistent package that passes every check and
  an honest holder signs the approved message under an attacker-chosen
  challenge. Not a forgery, but free choice of `c` over a fixed `m`.

  The field is gone; `Y` is a parameter of `inner_sign_v2`, taken from the
  holder's own key package. The type documentation no longer stops at "every
  field is public data" — public is not the same as locally anchored — and names
  `nested_index` and `active_indices` as caller-anchored.
  `from_coordinator_checked` is `#[deprecated]`: it validates self-consistency,
  not provenance, and a caller who stops reading at the name is protected
  against nothing.

### fixed — the protocol

- **M-5 (High)** — the D-2 fix binds a sub-share to the commitment *as
  delivered to this recipient*. That stops a man-in-the-middle; it does not stop
  the **dealer**. A malicious dealer sends `(C_A, f_A(a))` to Alice and
  `(C_B, f_B(b))` to Bob, each pair internally consistent, each passing its
  Feldman and digest checks, and the two derive different group keys with no way
  to tell. Nothing point-to-point can detect this.

  osst cannot supply the reliable broadcast — that is the caller's job, and a
  caller without one must not run this protocol — but it now ships the echo
  round so every participant computes the comparison identically:

  - `EchoDigest` / `round1_echo_digest`: a canonical digest over the whole
    round-1 commitment set, sorted by dealer index, each entry length-prefixed,
    with epoch, threshold and `n` inside the hash so a digest from another
    ceremony cannot match. Commitments only, not the proofs of knowledge —
    the group key, every verification share and every Feldman check are
    functions of the commitments alone, and a dealer whose PoK fails never
    enters the set.
  - `DkgState::agreed_round1() -> AgreedRound1`, which refuses a partial set.
  - `AgreedRound1::confirm` / `confirm_all` → `OsstError::EchoMismatch`.
  - `Aggregator::from_agreed`, so the dealer set — the one value every player
    must agree on — comes from the confirmed set.
  - `sealed::open_subshare_agreed`, which looks a dealer's commitment up in the
    agreed set instead of accepting whatever arrived beside the sub-share. That
    loose argument is exactly what an equivocating dealer controls.

  `an_equivocating_dealer_is_caught_by_the_echo_round` builds the attack end to
  end: both packages verify, both are accepted in isolation, the group keys
  really do differ, and the echo comparison refuses round 2.

- **M-20 (Low)** — the commit–reveal round was caller convention:
  `inner_precommit`/`verify_inner_precommit` existed and nothing called them.
  `aggregate_inner_commitment_pair` now takes the precommitments and verifies
  every reveal against one, returning `PrecommitMismatch(holder)`; extra
  precommitments for holders that did not reveal are fine. This threads through
  `verify_nested_commitment` and `NestedSigningRequest`, so `inner_sign_v2`
  enforces it for every holder.

- **M-14 (Medium)** — `active_indices` is coordinator-supplied and
  `inner_sign_v2` checked only that this holder had a position in it. It now
  rejects, before touching the nonces: index 0, a repeated index, an index with
  no round-1 commitment (`UnknownQuorumMember`), and a set smaller than `t_in`.
  `t_in` cannot be derived from the arguments — a `SecretShare` carries an index
  and a scalar — so `NestedSigningRequest` gains `inner_threshold`, documented
  as caller-anchored. N-3 fixed this on the aggregation side and left the
  signing side open.

- **M-6 (High, osst half)** — complaints were not a value at all, so a caller's
  only policies were "believe everyone" — one packet aborts the ceremony — and
  "believe no-one", which makes K-1 undetectable again.

  `Complaint<P>` is signed by the accuser's roster identity key and bound to
  `(epoch, session_id, round)`. `verify(epoch, session_id, accuser_pk)` checks
  the ceremony binding, the accused/evidence agreement and the signature, then
  returns a `ComplaintVerdict`: `Upheld`, or `Unfounded` when the complaint is
  authentic but wrong — a named participant making a false accusation is a
  different problem from a forgery, and collapsing them would lose the
  accountability the mechanism exists for.

  `ComplaintEvidence` has two kinds of deliberately unequal strength, and says
  so. `ForgedProofOfKnowledge` is fully transferable: the round-1 package is
  public, any third party re-runs `Round1Package::verify`. `BadSubShare`
  (commitment, revealed plaintext sub-share, digest of the sealed package) lets
  anyone confirm the scalar does not lie on the commitment, but **not** that the
  dealer sent it — Noise_K gives the recipient authentication, not
  transferability, so a recipient can fabricate a plaintext its own key would
  have produced. That gap is documented, the ciphertext digest is carried so a
  future key-reveal extension can close it, and callers are told to require `t`
  independent complaints for that kind.

  Identity key: a Schnorr key on the ceremony's own curve. The accuser's
  verification share does not exist yet — the complaint is raised during the DKG
  that produces it — so a long-term identity key is needed either way, and a
  scalar on `P` reuses the backend already compiled in, works in `no_std` with
  no new dependency, and verifies with an equation the crate already implements
  three times. XEdDSA over the roster's X25519 static key was rejected: clamping
  and sign-bit handling are easy to get subtly wrong. **The roster must bind an
  identity public key per participant**; osst does not own the roster, so
  verification is against a caller-supplied key.

  `DkgState::disqualify` no longer says "every participant must apply the same
  complaints" as though the library handled it. It now states that osst provides
  no agreement mechanism and that a caller without reliable broadcast must not
  use it.

- **M-13 (Medium)** — the session-id contract, stated precisely. `session_id`
  is a **mixing guard, not a replay guard**: it stops two concurrent rounds
  being spliced together and enters neither the binding factor nor the
  challenge, so two sessions over the same message and commitment list produce
  the same ρ and the same `c`. What prevents nonce reuse is in-process only —
  the nonces are consumed by value and checked against the published commitment.
  Across a restart that is nothing: a VM snapshot-restore replays them under a
  fresh challenge, and two responses under one nonce give up the share.

  New `SpentSessions` trait (`spend` → `OsstError::SessionSpent`), documented as
  needing to be durable, `fsync`'d and **write-ahead** — an implementation that
  buffers provides nothing, because the crash window is the whole point.
  `inner_sign_v2_spending` records before it computes, so a crash burns the
  session rather than leaving it replayable, and it spends the id in the
  holder's own nonces rather than the request's. `MemorySpentSessions` is for
  tests and says so.

### fixed — smaller

- **M-22 (Low)** — `secp256k1::compress()` returned an all-zero buffer for any
  encoding that was not 33 bytes, which `decompress` maps to the identity: a
  silently wrong hash input in the function whose lossiness was C-1. The length
  check is now an exhaustive `match` with both real cases named and an
  `unreachable!` for anything else, with the infallibility argument written out.
  The panic is over k256's own encoder, never over wire input, so P-1 does not
  apply. Tests pin both branches and assert the premise directly.

### tests

- **M-23 (Low)** — `tests/audit_rejections.rs` adds the rejection paths the
  review named as untested, against the public API:
  `ChallengeMismatch` from `from_coordinator_checked` (each scalar perturbed
  alone); `InvalidProofOfKnowledge` from a forged `Round1Package`, including an
  honest package replayed into another epoch; `DkgAborted` on
  over-disqualification and the state afterwards; and the four sealed paths —
  wrong prologue, wrong sender, wrong recipient, digest mismatch — plus
  ciphertext tampering.

  Two of the seven were already covered and are cross-referenced rather than
  duplicated: the duplicate branch of N-3 (`incomplete_quorum_is_rejected`
  asserts `vec![1, 3]`, so both branches were covered) and `SessionMismatch` in
  `aggregate_inner_commitment_pair` as distinct from `inner_sign_v2`.

- New regression tests for each finding above: the M-12 collision, the M-24 key
  dependence, the M-4 substituted-key trap, the M-14 malformed quorum, the M-5
  equivocating dealer (in both `dkg` and `sealed`), the M-20 unmatched reveal,
  the M-6 complaint verdicts, and the M-13 restore.

### still open, and not this crate's to close

- The review's `narsild` list (§ii) — unauthenticated endpoints, the secret
  shares on `/dkg/status`, irreversible key destruction, epoch rollback, the
  absent durable nonce store. osst now provides the pieces (`SpentSessions`,
  `AgreedRound1`, `Complaint`); wiring them up is PR #31's job.
- `legacy-v1` removal: still present, still off by default, still insecure. A
  removal plan belongs in 0.6.0.

## [0.4.0] - 2026-09-20

Security release addressing SECURITY-REVIEW-2026-09.md. **Breaking**, and on
secp256k1 **wire- and signature-incompatible with 0.3.x** — see C-1.

Every PoC in `tests/audit_*.rs` that targets this crate is now an un-ignored
regression test asserting the attack fails. The three that remain `#[ignore]`d
are about `ghettobox-vault-pvm`'s threshold ElGamal (E-1..E-3), which is not
this crate.

### fixed — nested FROST v2

- **N-1 (High)** — `inner_sign_v2` bound the signer to no message. It took
  three scalars and an index list, so an inner holder had no input from which
  to tell what it was authorising, and a malicious coordinator could derive the
  outer context honestly over a message of its own choosing, collect inner
  shares, and assemble a valid signature over a payload the inner group never
  saw. In the intended deployments — a bridge position, a jury — gating *which*
  payload gets signed is the entire security property.

  `inner_sign_v2` now takes the approved message and a `NestedSigningRequest`
  (outer package, group key, nested index, session id, inner commitment set,
  quorum), recomputes the binding factor and challenge locally, and returns
  `MessageMismatch` when the package's message is not the approved one.
  `inner_sign_v2_with_context` takes a `SigningContext` instead of raw bytes;
  `frost::sign_with_context` does the same for the flat path (S-1).

  `InnerSigningParamsV2`'s fields are private and `from_outer` is the only
  derivation, so a coordinator cannot supply a challenge at all; where a wire
  format distributes one anyway, `from_coordinator_checked` recomputes and
  returns `ChallengeMismatch`.

- **N-2 (Medium)** — nothing tied the outer package's nested commitment to the
  inner round. Round 1 now carries a `session_id` through `inner_commit`,
  `InnerNonces` and `InnerCommitments`, and `inner_sign_v2` checks that the
  nonces belong to this session, that the published set contains this holder's
  own round-1 commitment, and that the package's entry for the nested position
  is exactly (ΣD_k, ΣE_k) over that set. `verify_nested_commitment` exposes the
  last check. `aggregate_inner_commitment_pair` returns a `Result` and rejects
  empty lists, duplicate holders and mixed sessions.

- **N-3 (Low)** — `aggregate_inner_shares_verified` requires the multiset of
  `holder_index` to equal `active_indices`; a missing or duplicated holder is
  named instead of silently producing a wrong scalar.

- **R-1 (Medium)** — nested v1 is gone from the default build. The RedPallas
  path (`zcash::nested_redpallas_sign`) shipped the v1 construction unmarked in
  the ciphersuite closest to mainnet value; it, `aggregate_inner_commitments`,
  `inner_sign`, `InnerSigningParams`, `aggregate_inner_shares` and the inner
  binding factors are now behind the off-by-default `legacy-v1` feature,
  documented as insecure and retained only so an existing deployment compiles
  while it migrates. The RedPallas FVK seed derivation is marked demo-only.

### fixed — curve backends

- **C-1 (High, secp256k1)** — `compress()` returned the bare x-coordinate and
  `decompress()` always rebuilt the even-y point, so the encoding was neither a
  round trip (half of all serialized commitments came back negated) nor
  injective (`P` and `-P` hashed identically, breaking the very coupling the
  binding factor exists to create).

  `compress` now returns SEC1 compressed, 33 bytes, parity byte included;
  `decompress` takes a slice and rejects anything that is not a canonical
  encoding of exactly `COMPRESSED_SIZE` bytes, the 32-byte x-only form
  included. The identity encodes as 33 zero bytes.

  **Compatibility, secp256k1 only.** The compressed encoding feeds
  `encode_commitments`, the binding factor, the challenge, the OSST
  contribution challenge and the inner precommitment, so **every one of those
  values changes**: a 0.3.x signer and a 0.4.0 signer cannot co-sign, and
  0.3.x-serialized commitments, contributions, signatures and dealer
  commitments do not parse. There is no migration path other than re-running
  the affected round; existing *keys* are unaffected. The other three backends
  are byte-identical to 0.3.0.

  Mechanically: `OsstPoint` gains an associated type `Compressed`
  (`[u8; 32]`, or `[u8; 33]` on secp256k1), `compress_vec`/`decompress_slice`
  are gone, and every fixed-width serializer that embedded a point
  (`Contribution`, `frost::SigningCommitments`, `frost::Signature`,
  `liveness::ContributionSignature`, `reshare::DealerCommitment`,
  `reshare::SharePolynomial`) produces and consumes `Vec<u8>`/`&[u8]` sized by
  `COMPRESSED_SIZE`.

- **Z-1 (Low)** — `OsstScalar::zeroize` no longer has a default. The old
  default was a non-volatile `*self = Self::zero()` that three of the four
  backends inherited — including the Zcash and Penumbra ones — and that the
  compiler was entitled to elide in every `Drop` impl calling it. Pallas,
  secp256k1 and decaf377 now use a volatile write plus a compiler fence.

### fixed — DKG and resharing

- **K-1 (Medium)** — dealers publish a Schnorr proof of knowledge of their
  constant term (Komlo–Goldberg SAC 2020 §5.1) in a new `dkg::Round1Package`,
  verified by `DkgState::submit_commitment` before anything is recorded. Both
  failure modes name the dealer — `InvalidProofOfKnowledge(i)` and
  `InvalidSubShare(i)` — and `DkgState::disqualify(i)` drops that dealer from
  the group key and every verification share, returning `DkgAborted` when too
  few remain. `derive_group_key` documents the two caveats that remain: it does
  not witness round 2, and Pedersen DKG without commit–reveal carries the
  GJKR99 last-publisher bias.

- **D-1 (Critical) / D-2 (High)** — new `osst::sealed`, behind a `sealed`
  feature gated on `std`. Round-2 sub-shares were plaintext scalars with no
  sealed alternative in the crate, and `narsild` accordingly put them on the
  wire as JSON over HTTP and broadcast each to every peer, so any single
  participant could reconstruct the group key. Sealing uses
  `Noise_K_25519_ChaChaPoly_BLAKE2s` via `snow` — the pattern ZF's
  `frost-client` and zcli's `frost-spend` both use — binding recipient (the
  responder's static key), sender (the `ss` mix, which is what closes D-2),
  ceremony (roster, session id and round as the Noise prologue) and the
  dealer's Feldman commitment (digest inside the sealed plaintext, so a
  sub-share and a commitment cannot be sourced separately). API:
  `SealedRoster`, `seal_subshare`/`open_subshare` — the Feldman check runs
  inside `open_subshare` and its failure names the dealer — `seal_round2`, and
  `x25519_{secret,public}_from_seed` deriving the static key from the
  participant's existing identity seed.

- **B-1 (Low)** — `batch_verify_subshares` pairs sub-shares with commitments by
  `dealer_index` rather than by position.

### fixed — hashing and API hygiene

- **L-1 (Medium)** — the liveness signature challenge is
  `H("osst/liveness-sig/v1" ‖ R ‖ Y ‖ message)`. Without the key it was
  malleable: `(R, s)` valid under `Y` became `(R, s + e·delta)` valid under
  `Y + delta·G`. Liveness signatures made by 0.3.x do not verify under 0.4.0.
- **H-1 (Low)** — the OSST contribution challenge carries
  `"osst/contribution/v1"`. It used to be byte-identical to the liveness
  challenge, so a liveness signature over a 64-byte message *was* an OSST
  contribution over that payload. The OSST challenge therefore changes on every
  backend.
- **F-1 (Low)** — `frost::sign` rejects a package whose commitment under the
  signer's own index is not the one its nonces produced
  (`UnexpectedCommitment`), as ZF `frost-core` does.
- **P-1 (Low)** — `assert!` on wire-parsed indices and thresholds became
  `Result`. `SecretShare::new`, `frost::commit`, `redpallas::commit`,
  `dkg::Dealer::{new, generate_subshare, generate_subshares}`,
  `reshare::Dealer::{new, generate_subshare}`, `reshare::SubShare::new`,
  `DealerCommitment::{from_polynomial, evaluate_at}` and
  `SharePolynomial::evaluate_at` all return `OsstError`. A zero index from a
  peer used to abort a validator.
- `liveness::ContributionVerifier::verify_batch` takes `&[(u32, P)]` and looks
  keys up by dealer index; `ContributionError::IndexMismatch` is finally
  constructed.

### documentation

- `SECURITY-nested-frost.md` §4.1 no longer claims v2's security "reduces to
  FROST's existing proof" — the equivalence test establishes honest-transcript
  equality, not a reduction. §4.2 no longer presents commit–reveal as the
  replacement for the removed inner binding factor. §5 replaces the "far below
  the ROS threshold" comparison with the actual sub-exponential cost at ℓ = 4.

### not addressed

- **W-1..W-4** are against zcli's weighted `frost-spend`, not this crate. W-1
  is fixed here in the form N-1 takes; the weighted wrapper must adopt the new
  `inner_sign_v2` shape. W-4 has no analogue in osst: its only "weights" are
  the OSST verification scalars, not integer stake.
- **E-1..E-3** are against `ghettobox-vault-pvm`'s threshold ElGamal, which
  needs a Chaum–Pedersen DLEQ per partial and an AEAD. Their PoCs stay
  `#[ignore]`d here as the record.
- **N-4** — `interleaved_dkg` is still a single-process simulation. Renaming it
  and splitting it into dealer-side and holder-side halves is a design change,
  not a fix, and is left open.
- **A-2** — the binding factor still omits the group public key, where RFC 9591
  includes it. The challenge does include `Y`, so cross-group confusion at the
  signature level is prevented; changing it is a wire break for every backend
  with no security gain that has been demonstrated, so it is left open.
- **A-3** — a durable spent-round store keyed by `(epoch, session_id,
  holder_index)`. The session id now exists to key one with, but the store
  itself is the caller's, and where it belongs is a deployment decision.
- `threshold > n` is still unchecked: a `Dealer` does not know `n`.

## [0.3.0] - 2026-09-20

sweep release: pull generic threshold-signing utilities that had drifted
into the downstream repos (zcli `crates/frost-spend`, zk.poker
`poker-server`/`poker-sdk`, zeratul, penumbrafi/penumbra `narsild`) back
into the canonical crate.

### added

- **`context::SigningContext`** — `{ epoch, manifest_hash, message }` with a
  canonical, domain-separated, length-prefixed encoding that every signer
  recomputes independently. That encoding, not the bare message, is what FROST
  signs over.

  This is what makes `reshare` an actual rotation. A key-preserving reshare
  leaves the group public key unchanged, so a pre-rotation quorum can still
  produce signatures that verify under it; binding the epoch into the signed
  bytes means an epoch-n signature is not a valid epoch-n+1 authorization.

  **Scope — it only works where the verifier is osst-aware** (custody
  authorization, escrow release, narsil spend approval, internal attestations).
  It does **not** apply to protocol-defined signatures — Orchard `SpendAuthSig`
  over a sighash, Penumbra spend auth, Bitcoin sighash — where the message is
  fixed by consensus and there is nowhere to put the epoch. Retiring shares in
  that setting needs an on-chain rotation to a *new* group key. See the module
  docs.
- **`random_scalar`** — free-function sugar over `OsstScalar::random`, for
  external callers. `narsild` (penumbrafi/penumbra#31) had duplicated the
  pallas wide-reduction bridge byte-for-byte because the trait method was easy
  to miss; the docs now carry the reason a caller must not reach for the curve
  crate's own `Field::random` (ff 0.14 moved it onto rand_core 0.10).
- **`nested::InnerSigningParamsV2::from_outer`** — derive a nested position's
  outer context (binding factor, challenge, Lagrange coefficient) from the
  outer `SigningPackage` and group public key. Five downstream call sites
  hand-rolled this; two of them also reimplemented `binding_factor` verbatim,
  which would silently break on any domain-tag change. Composition of existing
  public methods, no new crypto.

### notes for downstream

Nothing in this release is breaking; `0.2.0` callers compile unchanged.

Known duplication left in place deliberately, each tracked for its own review:

- **weighted nested FROST v2** (zcli `frost-spend/src/nested.rs`) — a
  stake-weighted generalization where one holder owns many share indices
  (`Σ_j λ_j·share_j` in place of `μ_k·σ_k`) plus commit-reveal precommitments.
  Genuinely generic and a real extension of `nested`, but it is a novel
  construction carrying its own security argument and currently has no caller
  anywhere. Deferred to a PR that can be reviewed on its own terms.
- **threshold ElGamal partial decryption** (zeratul
  `ghettobox-vault-pvm/src/pss/recovery.rs`) — group algebra over `osst::verify`
  and `compute_lagrange_coefficients`, the natural companion to `Contribution`.
  Deferred for the same reason: new crypto surface deserves its own review.
- **`serde`/SCALE codecs** for `SecretShare`, `Contribution`, `DealerCommitment`
  and `SubShare` — three consumers re-derive these, and the `serde`, `codec` and
  `scale-info` optional deps in `Cargo.toml` are currently dead (no `cfg` in
  `src/` references them). Needs a deliberate encode-as-bytes design, since
  backend scalar types do not implement `Encode`/`Serialize` themselves.
- **round-2 confidentiality for `dkg`** (zcli `frost-spend/src/sealed.rs`) —
  osst's DKG genuinely lacks it. Wants an optional feature or companion crate;
  `snow` + `x25519-dalek` + `hkdf` do not belong in no_std core.

## [0.2.0] - 2026-09-20

consolidation release: the three divergent copies of this crate (the
`rotkonetworks/frostito` repo, `zcli:crates/osst`, and
`zk.poker:crates/frostito`) are merged back into one canonical tree at
https://github.com/penumbrafi/frostito. the cargo package keeps the name
`osst`.

### added

- **Orchard spend-auth curve backend.** `curve::pallas::OrchardSpendAuthCurve`
  and `SpendAuthPoint` put Pallas in the Orchard `SpendAuthSig` group, whose
  generator is the hash-to-curve basepoint rather than the Pallas generator.
  This is the group ZF `reddsa` / `frost-core` FROST(Pallas, BLAKE2b-512)
  operates in, so shares, commitments and verifying shares produced here load
  straight into `frost-core` key packages. `PallasCurve` (plain generator) is
  unchanged and is *not* zcash-compatible on its own.
- **ZF FROST reshare cross-test** (`tests/reshare_zf_frost.rs`): ZF
  FROST(Pallas) DKG -> `osst::reshare` key-preserving reshare -> ZF FROST
  signing, end to end, verified against `reddsa`.
- **key-preserving reshare with an explicit dealer set.** `reshare::Aggregator`
  takes the agreed dealer set up front, rejects sub-shares from outside it, and
  emits the epoch's `SharePolynomial` (verifying shares for every player), so
  every player lands on the same public key package.
  `ReshareState::dealer_set()` gives coordinators the deterministic choice.
- `src/test_rng.rs`: `OsRng10`, a test-only bridge from rand 0.8's `OsRng` to
  rand_core 0.10's `TryRng`/`TryCryptoRng`, for reaching ff 0.14's
  `Field::random`.
- GitHub Actions CI: all-features test plus a per-backend build/test matrix.

### changed

- **pallas backend moved to Zakura Common 1.0 (pasta-1.0).** `pasta_curves` is
  now `zakura-pasta-curves =1.0.0` (ff + group 0.14) under a package rename, so
  `use pasta_curves` paths are untouched. `OsstScalar::random` for pallas now
  samples via `fill_bytes` + wide reduction instead of ff's `Field::random`,
  which ff 0.14 moved onto rand_core 0.10 — the public API stays generic over
  rand_core 0.6.
- `repository` now points at `penumbrafi/frostito`.

### breaking

- `dkg::Aggregator::new(player_index)` is now
  `dkg::Aggregator::new(player_index, &dealer_set) -> Result<_, OsstError>`.
  The dealer set is fixed at construction and must be identical on every node:
  a player that sums one dealer more or fewer than its peers derives a
  different group key and an incompatible share. `Aggregator::all_dealers(j, n)`
  is the classic everyone-deals DKG. `finalize()` and `derive_group_key()` no
  longer take a dealer count and now error until the set is complete;
  `derive_group_key()` returns `Result`. New helpers: `dealer_set()`,
  `is_complete()`, `missing_dealers()`. New error variants `UnexpectedDealer`,
  `DuplicateIndex`, `EmptyContributions`.
- the pallas backend now resolves `zakura-pasta-curves 1.0` rather than
  `pasta_curves 0.5`. A dependent that shares a pasta instance with this crate
  must move to Zakura Common 1.0 in the same step. Dependents pinned at rev
  `14e38da` are unaffected until they move.

### security

- the nested FROST v1 outer-nonce binding gap is fixed in v2 — shipped in
  `14e38da` (in 0.1.1's tree, after the 0.1.1 tag) and carried here
  unchanged. `nested::inner_sign_v2` presents the nested commitments as the
  outer `(D, E)` so the outer binding factor commits to them. See
  `SECURITY-nested-frost.md` and `docs/nested-frost-v1-vs-v2.svg`; v1 remains
  for migration only and must not be used for new deployments.

### notes

- `--no-default-features --features pallas` does not build: the `redpallas`
  helpers use `rand_core::OsRng`, which needs `getrandom`/`std`. Pre-existing
  since the initial release; use `--features std,pallas`. The other three
  backends build no_std.

## [0.1.1] - 2025-01-29

### fixed

- correct eprint link for paper (https://eprint.iacr.org/2025/722)

## [0.1.0] - 2025-01-29

initial release.

### added

- OSST identification protocol (schnorr threshold proofs)
- proactive resharing (dealer/aggregator model)
- liveness proofs for custodian participation
- curve backends: ristretto255, pallas, secp256k1, decaf377
- no_std support
- serialization for all types
