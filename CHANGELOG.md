# changelog

## [0.4.0] - unreleased

Security release addressing SECURITY-REVIEW-2026-09.md. **Breaking**, and on
secp256k1 **wire- and signature-incompatible with 0.3.x** — see C-1.

### fixed

- **C-1 (High, secp256k1)** — `OsstPoint::compress` returned the bare
  x-coordinate and `decompress` always rebuilt the even-y point. It was neither
  a round trip (half of all serialized commitments came back negated) nor
  injective (`P` and `-P` hashed identically, so binding factors and challenges
  could not separate a commitment set from its sign-flipped variants — the
  exact coupling the binding factor exists to create).

  `compress` now returns SEC1 compressed, 33 bytes, parity byte included;
  `decompress` takes a slice and rejects anything that is not a canonical
  encoding of that exact length — the 32-byte x-only form 0.3.0 accepted
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
  `liveness::ContributionSignature`, `reshare::DealerCommitment`) now produces
  and consumes `Vec<u8>`/`&[u8]` sized by `COMPRESSED_SIZE`.
  `liveness::ContributionSignature` is generic over the point, holding `R` as a
  point rather than 32 bytes.

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
