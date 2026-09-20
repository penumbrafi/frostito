# changelog

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
