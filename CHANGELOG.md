# changelog

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
