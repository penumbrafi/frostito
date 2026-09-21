# frostito

nested FROST threshold signatures with OSST (one-step schnorr threshold)
identification, DKG, and proactive resharing.

implementation of the OSST protocol from ["One-Step Schnorr Threshold Identification"](https://eprint.iacr.org/2025/722) by Foteinos Mergoupis-Anagnou (GRNET).

## canonical repo

the canonical source for this crate lives at
**https://github.com/penumbrafi/frostito**. the cargo package is named
`osst` (dependents `use osst::...`); the repository is named after the
protocol stack.

the vendored copies in `zcli` (`crates/osst`) and `zk.poker`
(`crates/frostito`) are being removed in favour of a git dependency on this
repo. `github.com/rotkonetworks/frostito` is kept as a mirror of `main` so
existing pins (`rev = "14e38da"`) keep resolving; new work goes to
penumbrafi.

## security

this crate has not had a third-party audit. two internal adversarial reviews
have been completed:

- [`SECURITY-REVIEW-2026-09.md`](SECURITY-REVIEW-2026-09.md) (2026-09-20) —
  scope, findings and PoCs; everything it raised against this crate is fixed in
  **0.4.0**, each PoC kept as a regression test in `tests/audit_*.rs`.
- [`REVIEW-2026-09-21-maintainer.md`](REVIEW-2026-09-21-maintainer.md)
  (2026-09-21) — a maintainer pass that re-verified each 0.4.0 closure against
  the code and looked at the callers. It found three new crate findings and a
  larger set in `narsild`. The crate half is fixed in **0.5.0**.

review is not proof: no formal reductions were attempted, and absence of a
finding in either document is not evidence of soundness.

what 0.5.0 changed, and what it means for you:

| finding | severity | effect |
|---------|----------|--------|
| M-24 | info → fixed | the binding factor now includes the group public key, as RFC 9591 §4.4 does. **signature-incompatible with 0.4.x on every backend** |
| M-12 | low | the liveness contribution message is length-prefixed and injective; tag `osst/contribution-sig/v2`. **that signature changes too** |
| M-5 | high | dealer equivocation: `EchoDigest`/`AgreedRound1` ship the echo round over the round-1 set, and `sealed::open_subshare_agreed` resolves commitments from the agreed set |
| M-4/M-21 | high/low | `NestedSigningRequest` no longer carries the group key — `inner_sign_v2` takes it from your own key package; `from_coordinator_checked` is deprecated |
| M-6 | high | `Complaint` is signed, ceremony-bound and justified, with a verdict a third party can reach. 0.5.1 closes the residual: `sealed::open_subshare_agreed_with_evidence` keeps the rejected plaintext so a round-2 complaint can actually be raised, and `ComplaintTally` gates disqualification on `t` distinct accusers |
| M-14 | medium | `active_indices` is validated against the commitment set and the inner threshold |
| M-13 | medium | the session id is documented as a mixing guard, not a replay guard; `SpentSessions` + `inner_sign_v2_spending` are where you put the durable half |
| M-20 | low | the commit–reveal round is enforced, not documented |
| M-25 | low | the plaintext sub-share serializers need the `unsafe_plaintext` feature and are deprecated there |
| M-22 | low | `secp256k1::compress()` has no silent all-zero fallthrough |
| M-23 | low | negative tests for the named rejection paths, in `tests/audit_rejections.rs` |

and what 0.4.0 changed:

| finding | severity | effect |
|---------|----------|--------|
| N-1/N-2 | high | nested v2 inner signers now hold the message and the full commitment set; a coordinator cannot get a share for an unapproved payload |
| C-1 | high (secp only) | secp256k1 point compression is SEC1 with parity. **wire- and signature-incompatible with 0.3.x on that backend** |
| R-1 | medium | nested v1 is behind the off-by-default `legacy-v1` feature, RedPallas path included |
| K-1 | medium | DKG dealers prove knowledge of their constant term; complaints name the dealer and `DkgState::disqualify` acts on them |
| L-1/H-1 | medium/low | liveness signatures bind the public key; OSST and liveness challenges are domain-separated |
| D-1/D-2 | critical/high | `osst::sealed` seals round-2 sub-shares per recipient over Noise_K, binding sender, recipient, ceremony and commitment |
| F-1, Z-1, P-1, B-1 | low | `sign` checks its own commitment; real zeroization on every backend; wire-parsed indices error instead of aborting the process; batch verification pairs by dealer index |

if you ran a DKG with a version before 0.4.0 over a network that did not
itself provide confidentiality and sender authentication for round 2, treat
the resulting key as compromised and regenerate it. that is D-1: it is not
theoretical, and it needs no wire access where sub-shares were broadcast.

nested FROST v1 is insecure (`SECURITY-nested-frost.md`). do not enable
`legacy-v1` for new code. do not enable `unsafe_plaintext` for new code
either — see M-25.

### what this crate cannot do for you

three properties the API now names explicitly, because 0.4.0 documented them
as caller obligations and a caller got each one wrong:

- **reliable broadcast.** the echo round (`AgreedRound1`) makes every
  participant compute the same comparison. it does not deliver the digests. a
  deployment without a broadcast that every honest party agrees on cannot
  detect an equivocating dealer, and must not run the DKG.
- **complaint agreement.** `Complaint` is verifiable and ceremony-bound.
  nothing in this crate re-broadcasts one, adjudicates across nodes, or makes
  `DkgState::disqualify` apply the same set everywhere. that is the caller's,
  and getting it wrong splits the group. a `BadSubShare` verdict says only
  *"this scalar is not a valid sub-share for that commitment"* — noise_K is
  not transferable, so a fabricated scalar is `Upheld` too — which is why
  `ComplaintTally` requires `t` distinct accusers before a dealer is
  disqualified, and why a dealer that cheats at most `t-1` recipients is
  excluded rather than blamed.
- **durable nonce state.** `SpentSessions` is a trait, not an implementation.
  the in-memory one is for tests. a daemon that snapshots and restores without
  a write-ahead, `fsync`'d spent-session log will eventually sign twice under
  one nonce and give up the share.

### OSST verification is not accountable

see below — it is a deliberate privacy/accountability trade, not a defect.

## accountability and privacy tradeoff

**OSST threshold verification is NOT accountable.** if verification fails, you cannot identify which custodian provided a malformed contribution.

this is a double-edged property:

| perspective | implication |
|-------------|-------------|
| **security** | malicious custodian can cause DoS without identification |
| **privacy** | verifier cannot determine which specific custodians participated |

the same "share-free" design that prevents blame attribution also provides **signer privacy** - similar to ring signatures, the verifier only learns that *some* valid t-of-n subset signed, not *which* subset. this can be desirable for:

- **censorship resistance**: can't target specific signers for retaliation
- **plausible deniability**: any qualifying subset could have been the signers
- **reduced metadata leakage**: participation patterns not revealed
- **private rollups**: threshold-signed state roots without revealing sequencer set

this property makes OSST well-suited for **private syndicate** designs inspired by [narsil](https://www.youtube.com/watch?v=VWdHaKGrjq0&t=16m) - where a group collectively holds assets via threshold custody with internal bft consensus for governance. the syndicate maintains its own replicated state machine; only commitments, nullifiers, and proofs are posted to L1.

the privacy property is key for collective custody: when a syndicate signs a state transition, L1 verifiers cannot determine which members participated. internal voting patterns, dissent, and power dynamics remain hidden - the outside world only learns that *some* valid t-of-n subset authorized the action.

use cases:
- **investment syndicates**: pooled capital with private voting on trades
- **multisig treasuries**: DAO funds without revealing signer coalitions
- **joint custody**: shared assets (families, partnerships) with hidden approval patterns

combined with decaf377 support, OSST integrates naturally with penumbra's shielded pool model.

### why?

the core OSST verification aggregates all contributions into a single equation:

```
g^{Σ μ_i·s_i} = Y^{c̄} · Π u_i^{μ_i}
```

this is a feature of the "share-free" property - the verifier only needs the group public key `Y`, not individual public shares `y_i = g^{x_i}`. without individual shares, you cannot verify each schnorr proof independently:

```
g^{s_i} ≟ u_i · y_i^{c_i}   // requires y_i which verifier doesn't have
```

### implications

**privacy benefits:**
- verifier learns nothing about which specific custodians participated
- protects custodian operational patterns from surveillance
- enables private threshold custody without revealing signer set

**security considerations:**
- a malicious custodian can cause verification to fail without being identified
- denial-of-service attacks are possible if custodians collude to submit bad proofs
- for applications requiring accountability, consider storing individual public shares

### partial mitigation via liveness module

the `osst::liveness` module provides accountability for **reshare contributions**:

```rust
// each dealer signs their contribution individually
let contribution = DealerContribution::sign(commitment, liveness, &secret, context, &mut rng);

// verifier checks each signature against custodian's known public key
contribution.verify_signature(&public_key, context)
```

this allows identifying misbehaving dealers during reshare, but does not address the core OSST verification limitation.

### alternatives for full accountability

if you need identifiable aborts:
- **store public shares**: keep `y_i` for each custodian, verify proofs individually before aggregation
- **use FROST**: has built-in identifiable abort mechanisms
- **add DLEQ proofs**: each custodian proves contribution consistency

## features

- **non-interactive**: provers generate proofs independently, no coordination needed
- **threshold**: requires t-of-n provers to verify
- **proactive resharing**: rotate custodian sets without changing the group public key
- **multi-curve**: ristretto255, pallas, secp256k1, decaf377
- **no_std**: works in constrained environments (wasm, polkavm). exception:
  the `redpallas` helpers reach for `rand_core::OsRng`, so `pallas` needs
  `std` for those (`--features std,pallas`); the core protocol is no_std on
  every backend.

optional cargo features, all off by default:

| feature | what it is |
|---|---|
| `sealed` | confidential, authenticated DKG round 2 over Noise_K (`osst::sealed`). needs `std`. **use this** |
| `legacy-v1` | nested FROST v1. **insecure** — see `SECURITY-nested-frost.md`. retained only so an existing deployment compiles while it migrates |
| `unsafe_plaintext` | the plaintext sub-share serializers, `#[deprecated]` when enabled. **secret key material on the wire** — `t` of those 40-byte strings reconstruct the group key (D-1 / M-25). the only sound use is feeding `sealed::seal_subshare`, which does it for you internally, so you should not need this |

## curves

| feature | curve | compatibility |
|---------|-------|---------------|
| `ristretto255` | curve25519 | polkadot, sr25519 |
| `pallas` | pallas (curve generator) | generic pallas |
| `pallas` | pallas in the orchard spend-auth group (`OrchardSpendAuthCurve`) | zcash orchard, ZF `reddsa` / `frost-core` FROST(Pallas) |
| `secp256k1` | secp256k1 | bitcoin, ethereum |
| `decaf377` | decaf377 | penumbra |

## usage

```rust
use osst::{SecretShare, Contribution, verify};

// after DKG, each custodian has a share
let share = SecretShare::new(index, scalar)?;   // errors on index 0

// generate contribution (schnorr proof)
let contribution = share.contribute(&mut rng, &payload);

// verifier collects t contributions and verifies
let valid = verify(&group_pubkey, &contributions, threshold, &payload)?;
```

## resharing

rotate custodian sets while preserving the group public key:

```rust
use osst::reshare::{Dealer, Aggregator};

// old custodians become dealers
let dealer = Dealer::new(index, current_share, new_threshold, &mut rng)?;
let commitment = dealer.commitment();
let subshare = dealer.generate_subshare(player_index)?;

// every new custodian must agree on the dealer set S *before* aggregating
// (e.g. via a signed epoch manifest). players that aggregate over different
// subsets land on different polynomials that pass the group-key check
// individually but never sign together.
let mut aggregator = Aggregator::new(player_index, &dealer_set)?;
aggregator.add_subshare(subshare, commitment)?;   // rejects dealers outside S
let (new_share, polynomial) = aggregator.finalize(&group_pubkey)?;

// `polynomial` is the epoch's public key package, identical on every player:
let verifying_share_j = polynomial.verifying_share(j);   // g^{s'_j}
assert!(polynomial.verify_share(player_index, &new_share));
```

`ReshareState::dealer_set()` gives the deterministic choice (the `t_old`
lowest committed dealer indices) for coordinators to put in the manifest.

## modules

- `osst` - core OSST identification protocol
- `osst::reshare` - proactive secret sharing
- `osst::liveness` - checkpoint proofs for custodian participation
- `osst::curve` - curve backend traits
- `osst::dkg` - distributed key generation over an agreed dealer set
- `osst::nested` - nested FROST (see `SECURITY-nested-frost.md`)
- `osst::redpallas` - zcash orchard spend-auth signing helpers
- `osst::sealed` - confidential, authenticated DKG round 2 (feature `sealed`)
- `osst::context` - epoch-bound signing contexts

## license

MIT OR Apache-2.0
