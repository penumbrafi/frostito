# Security review — osst 0.3.0, weighted nested FROST, threshold ElGamal

Date: 2026-09-20
Reviewer: code review and adversarial testing, not cryptanalysis. No formal
reductions were attempted. Absence of a finding below is not evidence of
soundness.

Scope:

| # | Target | Path |
|---|---|---|
| 1 | Nested FROST v2 | `osst::nested` — `/steam/rotko/frostito/src/nested.rs` |
| 2 | Weighted nested FROST v2 (**candidate A**) | `/steam/rotko/zcli/crates/frost-spend/src/nested.rs` |
| 3 | Threshold ElGamal (**candidate B**) | `/steam/rotko/zeratul/crates/ghettobox-vault-pvm/src/pss/recovery.rs` |
| 4 | `SigningContext` | `/steam/rotko/frostito/src/context.rs` |
| 5 | osst 0.3.0 at large | `frost.rs`, `dkg.rs`, `reshare.rs`, `curve.rs`, `liveness.rs`, `redpallas.rs`, `lib.rs` |
| 6 | DKG round-2 confidentiality | `osst::dkg` + `penumbrafi/penumbra` PR #31 `crates/bin/narsild` |

PoCs: `tests/audit_nested_v2.rs`, `tests/audit_frost_core.rs`,
`tests/audit_threshold_elgamal.rs`, `tests/audit_secp_encoding.rs`.
All are `#[ignore]`d with their finding id so CI stays green; run with
`cargo test -- --ignored`. Two conventions are mixed and each test says which
it uses: the nested PoCs assert *the attack succeeds* (they pass when run); the
ElGamal, `frost::sign` and liveness PoCs assert *the property that should hold*
(they fail when run). Existing suite: 63/63 pass, unchanged by this branch.

---

## Findings

| ID | Severity | Component | Finding |
|---|---|---|---|
| D-1 | **Critical** | narsild DKG round 2 | Sub-shares sent as plaintext JSON over HTTP **and broadcast to every peer** — any single participant reconstructs the group secret |
| D-2 | **High** | narsild DKG rounds 1–2 | No sender authentication; MITM substitutes a matched (commitment, sub-share) pair that passes Feldman verification |
| N-1 | **High** | `osst::nested` v2 | `inner_sign_v2` binds the signer to no message; a malicious coordinator obtains a valid signature on an unapproved message |
| W-1 | **High** | zcli `frostito_sign_v2` | Same as N-1, and worse: no `from_outer` equivalent exists at all |
| E-1 | **High** | zeratul ElGamal | Partial decryptions carry no DLEQ; the OSST proof says nothing about `R^{x_i}` |
| E-2 | **High** | zeratul ElGamal | OSST payload does not commit to the ciphertext — providers are a threshold CDH oracle |
| R-1 | **High** | `osst::redpallas` | The Zcash/Orchard nested path still ships the v1 construction, unmarked |
| C-1 | **High** (secp only) | `osst::curve::secp256k1` | `compress()` drops the y parity: not a round trip, and `P`/`−P` collide in every hash |
| N-2 | Medium | `osst::nested` v2 | No API binds the outer package's nested commitment to the inner commitment round |
| W-2 | Medium | zcli weighted | `FrostitoCommitment.weight` is self-asserted and drives the threshold check |
| W-3 | Medium | zcli weighted | No invariant that any single validator's weight is below the threshold |
| E-3 | Medium | zeratul ElGamal | Unauthenticated XOR-stream payload encoding; KDF omits `R` and `Y` |
| L-1 | Medium | `osst::liveness` | Schnorr challenge omits the public key — related-key malleability |
| K-1 | Medium | `osst::dkg` | No proof of knowledge of the constant term (RFC 9591 §5.1); `DkgState` has no complaint round |
| F-1 | Low | `osst::frost` | `sign()` does not check the package's commitment for its own index |
| N-3 | Low | `osst::nested` v2 | `aggregate_inner_shares_verified` does not require quorum coverage or reject duplicates |
| N-4 | Low | `osst::nested` | `interleaved_dkg` is a single-process simulation, not a distributed protocol |
| Z-1 | Low | `osst::curve` | `zeroize()` default is a plain assignment; only ristretto overrides it |
| H-1 | Low | `osst` | OSST and liveness share one undomained SHA-512 challenge |
| P-1 | Low | `osst` | `assert!` on wire-parsed indices/thresholds instead of `Result` |
| B-1 | Low | `osst::reshare` | `batch_verify_subshares` zips sub-shares to commitments positionally |
| W-4 | Low | zcli weighted | `u32` weight sum overflows; weight-0 and duplicate/overlapping bundles unchecked |
| S-1 | Info | `osst::context` | `SigningContext` is correct but purely advisory |
| A-1 | Info | `osst::nested` v2 | The flat-equivalence property holds; commit–reveal is belt-and-braces, not load-bearing |
| A-2 | Info | `osst::frost` | Binding factor omits the group public key (RFC 9591 includes it) |
| A-3 | Info | `osst` | No session identifier; one-time nonce use is enforced only by move semantics |

---

## 1. Nested FROST v2 (`osst::nested`)

### 1.1 The construction, restated from the code

An inner group of `n_in` holders collectively occupies **one** position `p` in
an outer `t_out`-of-`n_out` FROST group.

**Key setup.** `interleaved_dkg` (`src/nested.rs:105`) shares each of the outer
polynomial's `t_out` coefficients with an independent inner Feldman DKG, so
inner holder `k` ends with `alpha_{k,0..t_out-1}`. `InnerShare::eval_at(p)`
(`src/nested.rs:85`) evaluates `sum_j alpha_{k,j} · p^j`, which by the
homomorphic property is a Shamir share of `f_p(p)`. `combine_shares`
(`src/nested.rs:216`) adds the other outer participants' split evaluations, so
holder `k` ends with `sigma_k`, a `t_in`-of-`n_in` Shamir share of the outer
share `sigma_out`. The outer share never exists as one scalar.

**Signing (v2).**

1. Round 0: each holder publishes `H(k ‖ D_k ‖ E_k)` (`inner_precommit`,
   `src/nested.rs:1185`), then reveals `(D_k, E_k)` (`inner_commit`,
   `src/nested.rs:255`).
2. `aggregate_inner_commitment_pair` (`src/nested.rs:1226`) returns
   `D_nested = Σ D_k`, `E_nested = Σ E_k`. This **pair** is presented to the
   outer protocol as position `p`'s ordinary `SigningCommitments`.
3. The outer protocol computes `rho = H("frost-binding-v1", p, m, B)` over the
   full outer commitment list `B` and `c = H("frost-challenge-v1", R, Y, m)`
   exactly as for any other signer (`src/frost.rs:360`, `src/frost.rs:380`).
4. Each holder computes `z_k = d_k + rho·e_k + (lambda_out · c · mu_k)·sigma_k`
   (`inner_sign_v2`, `src/nested.rs:1298`), where `mu_k` is the inner Lagrange
   coefficient over the inner quorum.
5. `aggregate_inner_shares_verified` (`src/nested.rs:1356`) checks each share
   against `z_k·G == (D_k + rho·E_k) + (lambda_out·c·mu_k)·P_k` and sums.

Summing over the quorum with `d = Σ d_k`, `e = Σ e_k`,
`Σ mu_k·sigma_k = sigma_out` gives
`z_nested = d + rho·e + lambda_out·c·sigma_out`, i.e. exactly a flat FROST
signer's share.

There is **no** inner binding factor in v2. The v1 `frostito-inner-bind`
factor (`src/nested.rs:283`) and `aggregate_inner_commitments`
(`src/nested.rs:328`) remain exported and documented as insecure.

### 1.2 (a) ROS / Drijvers concurrent-session attacks — no finding

v2 is sound on this point, and for a specific reason worth stating so a future
change does not silently break it.

Every honest holder's effective nonce contribution is `d_k + rho·e_k` with the
**outer** `rho = H(p, m, B)` over the full outer commitment list. `D_nested` and
`E_nested` are injective in each `D_k`, `E_k` (a plain group sum over a
prime-order group), so `B` — and hence `rho` and `c` — moves whenever any
honest inner commitment moves. An adversary therefore cannot hold an honest
effective nonce fixed while sweeping the challenge, which is precisely the
coupling v1 severed by handing the outer protocol
`binding = identity` (killing `rho` for that position) and a pre-bound hiding
point.

This is a *hybrid*: per-position `rho` at the outer layer, a single shared `rho`
across all inner holders. That is fine — the inner holders are additive shares
of one outer signer, not independent signers, so a per-holder `rho` would break
the very linearity that makes the position equal a flat signer. The obligation
the hybrid carries is that the inner group must be treated as one trust unit:
`t_in` corrupt holders are a corrupt outer signer, with no further guarantee.

`tests/audit_nested_v2.rs::v2_response_equals_the_flat_frost_response`
(not ignored) re-asserts the flat-equivalence identity from outside the crate.
Note that the equivalence test — both this one and the in-crate
`nested_v2_equals_flat_frost` — establishes *honest-case algebra*, not a
reduction. It shows the transcripts coincide when everyone follows the protocol;
it does not show that an adversary against the nested scheme yields an adversary
against FROST. The latter is plausible and is the right thing to ask a
cryptographer, but it is not what the test proves, and the SECURITY-nested-frost
§4.1 wording ("security therefore reduces to FROST's existing proof") overstates
what has been demonstrated.

Comparison with ZF `frost-core` / RFC 9591: osst's
`rho_i = H("frost-binding-v1" ‖ i ‖ len(m) ‖ m ‖ encode(B))` matches the RFC's
shape (`H1(identifier, msg_hash, commitment_list_hash)`) except that the RFC's
binding-factor input also carries the encoded group public key — see **A-2**.

### 1.3 (d) N-1 (**High**) — the inner signer is bound to no message

`src/nested.rs:1298`

```rust
pub fn inner_sign_v2<P: OsstPoint>(
    nonces: InnerNonces<P::Scalar>,
    share: &SecretShare<P::Scalar>,
    params: &InnerSigningParamsV2<P::Scalar>,
    active_indices: &[u32],
) -> Result<InnerSignatureShare<P::Scalar>, OsstError>
```

The holder hashes **nothing**. It receives three scalars and an index list and
multiplies. There is no message parameter, no `SigningPackage`, no group public
key — nothing from which a holder could determine what it is authorising. v1's
`inner_sign` at least took `outer_message` (`src/nested.rs:374`); v2 removed the
last trace of message binding at the signer.

The claim that the parameters are "recomputable from public data" is met only by
`InnerSigningParamsV2::from_outer` (`src/nested.rs:1268`), which is optional and
which moves the trust from "three scalars the coordinator asserts" to "one
package the coordinator asserts". `from_outer` genuinely recomputes `rho`, `c`
and `lambda_out` from the package and the group key; it does not and cannot
check that the package's message is the one the group approved, nor that the
package's commitment for the nested position is the inner round's own (that is
**N-2**).

Attack: a malicious coordinator that also holds an outer position builds an
honest package over a message of its choosing, derives params honestly with
`from_outer`, and collects inner shares. Every inner share verifies against
those params, so `aggregate_inner_shares_verified` reports success. The result
is a valid signature over a message the inner group never saw.

PoC: `tests/audit_nested_v2.rs::coordinator_swaps_the_message_under_the_inner_group`.
The jury believes it authorises `"release 10 ZEC to alice"`; the assembled
signature verifies over `"release 10000 ZEC to mallory"` and not over the
approved message.

In the intended deployments this is the whole security property: the bridge's
position B and `poker-server::jury` exist to gate *which* payload gets signed.

**Fix.** Make the message the signer's input, not the coordinator's:

```rust
pub fn inner_sign_v2<P: OsstPoint>(
    nonces: InnerNonces<P::Scalar>,
    share: &SecretShare<P::Scalar>,
    package: &SigningPackage<P>,       // carries the message
    group_pubkey: &P,
    nested_index: u32,
    inner_commitments: &[InnerCommitments<P>],  // for N-2
    active_indices: &[u32],
) -> Result<InnerSignatureShare<P::Scalar>, OsstError>
```

deriving the params internally via `from_outer` and returning
`OsstError::UnexpectedCommitment` when the package's nested entry is not
`aggregate_inner_commitment_pair(inner_commitments)`. Keep the scalar-taking
form only as a `pub(crate)` primitive. Callers then physically cannot sign
without holding the message, and an application-level policy check on
`package.message()` becomes possible. Combine with `SigningContext` (§4) so the
message is the epoch-bound encoding rather than a raw payload.

### 1.4 N-2 (Medium) — the nested commitment is never tied to the inner round

`src/nested.rs:1268`. `from_outer` looks up `nested_index` in the package and
derives from whatever commitment it finds there. It never compares that entry
to `Σ D_k`, `Σ E_k`, and no helper exists that would let a holder do so.
`verify_inner_share` (`src/nested.rs:1332`) cannot help: it checks shares
against the *same* supplied params, so a substituted context verifies
consistently.

Impact is bounded — `rho` moves with the substitution, so the aggregate is
simply wrong and the signature fails — but it is a silent, unattributable
failure, and it lets a coordinator run holders through rounds whose commitment
set they never agreed to, which is the ground state for the more interesting
attacks. PoC:
`tests/audit_nested_v2.rs::substituted_nested_commitment_is_undetectable_by_the_holder`.

**Fix.** Add

```rust
pub fn verify_nested_commitment<P: OsstPoint>(
    package: &SigningPackage<P>,
    nested_index: u32,
    inner_commitments: &[InnerCommitments<P>],
) -> bool
```

and call it from the message-taking `inner_sign_v2` above.

### 1.5 (b) A-3 (Info) — session identifiers and nonce reuse

There is no session id anywhere in the crate. One-time nonce use is enforced
only by `InnerNonces`/`Nonces` being consumed by value and zeroized on drop
(`src/nested.rs:239`, `src/frost.rs:104`). That is a correct in-process
guarantee and the crate is honest that it does not survive a process boundary
(`src/nested.rs:1291`).

For nested v2 this matters more than for flat FROST, because the nested
position's nonce is `Σ` of `t_in` holders' nonces: a single holder that restores
persisted state and signs twice under two different `(rho, c)` pairs yields
`z¹ − z² = (rho¹ − rho²)e_k + (w¹ − w²)sigma_k`, two equations in three unknowns
after one more replay. Recommend a durable spent-round store keyed by
`(epoch, session_id, holder_index)`, checked before `inner_sign_v2` returns, and
an explicit `session_id` field in the package that enters the binding factor.

### 1.6 (c) Domain separation between v1, v2 and plain FROST

Correct, and the absence of a distinct v2 tag is by design. v2's binding factor
*is* plain FROST's `"frost-binding-v1"` (`src/frost.rs:362`) — that identity is
what makes the position equal a flat signer. v1's inner factor is
`"frostito-inner-bind"` (`src/nested.rs:285`) and the precommit is
`"frostito-inner-precommit-v2"` (`src/nested.rs:1187`). No collisions.

The residual risk is version confusion, not hash collision: v1's
`aggregate_inner_commitments` and `inner_sign` are still exported with only a
doc-comment warning. Mark them `#[deprecated(note = "...")]`, or put them behind
a `nested-v1` feature that is off by default, so a caller cannot reach the
insecure construction without saying so in `Cargo.toml`.

### 1.7 (e) Wagner / generalized birthday on the aggregate nonce — no finding

`D_nested = Σ D_k` is a `k`-sum, so a holder revealing last can steer it; that is
what the commit–reveal round addresses. But see **A-1**: with the outer `rho`
applied to `E_nested`, steering the aggregate buys the adversary nothing it does
not already have. The concrete restoration of the v1 gap — setting
`E_nested = identity` by choosing `E_adv = −Σ_honest E_k` — fails because the
adversary would then have to answer with `z_adv` for a commitment whose discrete
log it does not know. The commit–reveal round is sound and cheap and should
stay; it is defence in depth, not the load-bearing mitigation
SECURITY-nested-frost §4.2 describes.

`aggregate_inner_commitment_pair` (`src/nested.rs:1226`) nonetheless does not
enforce it, does not reject duplicate `holder_index`, and does not reject an
empty list. Take the precommitments as an argument and verify them there rather
than documenting "callers MUST".

### 1.8 (f) K-1 (Medium) — rogue key and bias in the DKG

`dkg::Dealer::new` (`src/dkg.rs:55`) publishes a Feldman commitment and no proof
of knowledge of `a_0`. RFC 9591 §5.1 requires a Schnorr PoK over the constant
term in round 1.

Full key takeover is blocked here: `Aggregator::add_subshare`
(`src/dkg.rs:203`) verifies every sub-share against its commitment, and
producing verifying sub-shares requires knowing the polynomial, so a dealer that
picks `C_{n,0}` as a target point cannot then deal. But two gaps remain:

- **Bias (GJKR99).** Commitments are accepted in any order with no commit–reveal
  (`DkgState::submit_commitment`, `src/dkg.rs:322`). The last dealer to publish
  sees every other `C_{i,0}` before choosing its own, and there is no complaint
  or disqualification round, so an abort-and-retry strategy lets it bias the
  distribution of `Y`. For Schnorr signatures this is the known-and-tolerated
  Pedersen-DKG weakness, but it should be stated in the module docs rather than
  left implicit.
- **`DkgState::derive_group_key`** (`src/dkg.rs:358`) sums commitments with no
  sub-share verification at all. If a deployment fixes the group key from
  on-chain commitments *before* round 2 completes, a dealer that never delivers
  valid sub-shares still moves `Y`.

**Fix.** Add the RFC 9591 PoK to `DealerCommitment` and verify it in
`submit_commitment`; add a complaint/disqualification path to `DkgState`.

### 1.9 N-3, N-4 (Low)

- `aggregate_inner_shares_verified` (`src/nested.rs:1356`) iterates the shares it
  was handed and never checks that every index in `active_indices` produced one,
  nor that no `holder_index` appears twice. A short or duplicated quorum
  aggregates to a wrong scalar and is reported as `Ok`. PoC:
  `tests/audit_nested_v2.rs::incomplete_quorum_aggregates_as_success`.
  Fix: require the multiset of `sig.holder_index` to equal `active_indices`.
- `interleaved_dkg` (`src/nested.rs:105`) constructs **every** inner dealer in
  one process and calls `generate_subshare` on all of them locally. It is a
  simulation of the interleaved DKG, not an implementation of it: there is no
  message type, no round structure, no dealer-side/holder-side split. Rename it
  (`simulate_interleaved_dkg`) or split it into the per-dealer and per-holder
  halves a real deployment needs. As written, any production caller of this
  function has all shares in one address space.

### 1.10 (g) Share-free OSST verification and accountability in the nested case

`osst::verify` (`src/lib.rs:355`) checks one aggregate equation
`g^{Σ mu_i s_i} = Y^{c̄} · Π u_i^{mu_i}`, so a failure names no one. That is
inherent to the share-free design and is the correct trade for on-chain
verification cost.

For the nested case it means the OSST authorization gate and the FROST signing
path have **different** accountability properties: `verify_inner_share`
(`src/nested.rs:1332`) does identify a faulty FROST share, but the OSST
authorization that is supposed to gate it does not identify a faulty
contribution. A jury node that submits a bad OSST contribution causes the whole
authorization to fail with no attribution and no eviction path, so the
availability of the nested position is `t_in`-of-`n_in` for signing but
effectively all-honest for authorization. Where attribution matters, verify
contributions individually (`g^{s_i} == u_i · Y_i^{c_i}` against the per-holder
verification share from `DkgState::derive_verification_share`) before folding
them into the aggregate check.

---

## 2. Weighted nested FROST v2 (candidate A — zcli `frost-spend`)

### 2.1 How weights are realised: virtual signers, locally aggregated

Not scaled Lagrange coefficients. Each validator holds **one Shamir identifier
per weight unit**:

```rust
// src/nested.rs:72
pub fn effective_share(&self, all_active_indices: &[u32]) -> Result<Scalar, osst::OsstError> {
    let all_lambda = compute_lagrange_coefficients::<Scalar>(all_active_indices)?;
    let mut effective = Scalar::ZERO;
    for share in &self.shares {
        let pos = all_active_indices.iter().position(|&i| i == share.index)
            .ok_or(osst::OsstError::InvalidIndex)?;
        effective += all_lambda[pos] * share.scalar();
    }
    Ok(effective)
}
```

The Lagrange coefficients are the *ordinary* ones for the full active share set;
the validator merely sums its own `lambda_j · s_j` terms locally. `Σ_validators
effective_k = Σ_{j ∈ active} lambda_j · s_j = sigma_out` by ordinary Lagrange
interpolation.

**This is therefore a valid Shamir sharing, unmodified.** The scheme is flat
FROST over `n` identifiers with a message-count optimisation: 25 messages per
round instead of 200. `frostito_sign_v2` (`src/nested.rs:931`) is
`inner_sign_v2` with `mu_k · sigma_k` replaced by `effective_k`, which is the
same quantity summed over the validator's shares. The aggregation is linear in
exactly the same way, so the FROST unforgeability argument carries over on the
same terms as §1.2: the nested position is a flat signer whose nonce and key are
additively shared, and the weighted variant changes only how those additive
parts are grouped. No new assumption is introduced.

**Threshold semantics.** The threshold is on the number of *active share
indices*, not on the number of validators. A validator holding `weight >= t`
reconstructs the secret alone — by construction, not by accident: you handed it
`t` points on a degree-`t−1` polynomial. This is a governance property, not a
bug, but see W-3.

### 2.2 W-1 (High) — no message binding, and no `from_outer`

`FrostitoSigningParamsV2` (`src/nested.rs:917`) is
`{outer_binding, outer_challenge, outer_lambda, active_share_indices}` and
`frostito_sign_v2` (`src/nested.rs:931`) takes nothing else. This is N-1 with
the mitigation removed: osst at least offers `from_outer`; the zcli type has **no
constructor that derives from a package at all**, so every caller hand-builds
the three scalars.

The crate's own equivalence test makes the point better than any PoC could —
`src/nested.rs:421`:

```rust
let params = FrostitoSigningParamsV2 {
    outer_binding: rand_scalar(&mut rng),
    outer_challenge: rand_scalar(&mut rng),
    outer_lambda: rand_scalar(&mut rng),
    active_share_indices: active.clone(),
};
```

Three uniformly random scalars, no outer package anywhere in the test, and the
validators sign. That is a faithful picture of what a validator can check: nothing.

**Fix.** Add `FrostitoSigningParamsV2::from_outer(&SigningPackage<Point>,
&Point, nested_index)` mirroring osst's, then make `frostito_sign_v2` take the
package and derive internally, as in §1.3. Additionally have the equivalence
test build a real outer package so it exercises the derivation path.

### 2.3 W-2 (Medium) — self-asserted weights drive the threshold check

`FrostitoCommitment.weight` (`src/nested.rs:109`) is a `u32` the validator puts
in its own commitment message, and

```rust
// src/nested.rs:197
pub fn frostito_threshold_met(commitments: &[FrostitoCommitment], threshold: u32) -> bool {
    let total: u32 = commitments.iter().map(|c| c.weight).sum();
    total >= threshold
}
```

is the only place stake is counted. Nothing checks the claim against the roster
or the DKG commitments. The signing arithmetic ignores `weight` entirely — it
uses `active_share_indices` — so an inflated weight does not forge anything; it
causes the coordinator to believe a sub-threshold set is sufficient, proceed, and
produce an invalid signature. Availability and accounting, not forgery.

The weight *is* bound into the round-0 precommitment (`frostito_precommit`,
`src/nested.rs:869`, hashes `c.weight.to_le_bytes()`), so a validator cannot
change its claim between precommit and reveal. That is good and worth keeping;
it just binds the claim to itself, not to reality.

**Fix.** Derive weight from the signed epoch roster at the coordinator, not from
the message; make `frostito_threshold_met` take the roster and
`active_share_indices` and assert
`active_share_indices` is exactly the disjoint union of the participating
validators' rostered share indices, with `len() >= threshold`.

### 2.4 W-3 (Medium) — nothing enforces `max_weight < threshold`

`ValidatorShares::new` (`src/nested.rs:54`) accepts any bundle. A stake
allocation that gives one validator `t` or more identifiers gives it the group
key outright, silently. Given the `rotko 42% / 49.75%` concentration recorded for
penumbra-1, a weighted allocation generated from live stake could reach this
without anyone deciding to.

**Fix.** A checked constructor for the allocation —
`WeightedRoster::new(allocations, threshold)` returning `Err` when any single
weight `>= threshold`, and ideally when any *plausible colluding subset* reaches
it — plus the invariant written into the module docs. This belongs in the
upstreamed crate, not in the caller.

### 2.5 W-4 (Low) — arithmetic and set hygiene

- `frostito_threshold_met` sums `u32` weights with `sum()`: panics on overflow in
  debug, wraps in release. With adversarial weight claims a wrap gives a false
  negative (DoS). Use `u64`/`checked_add`.
- Weight-0 bundles are accepted; `effective_share` returns `ZERO` and the
  validator contributes only nonce. Harmless but should be rejected.
- `frostito_aggregate_commitment_pair` (`src/nested.rs:902`) does not reject a
  duplicate `validator_index`; `frostito_aggregate_responses_verified`
  (`src/nested.rs:973`) resolves commitments by `find`, so a duplicated response
  is verified against the same commitment twice and added twice.
- Nothing checks that two validators' bundles hold disjoint share indices; an
  overlap double-counts the shared `lambda_j · s_j`.
- `effective` in `frostito_sign_v2` is a linear combination of secrets and is
  never zeroized (`FrostitoNonce::drop` zeroizes the nonces, but see **Z-1** for
  what that is worth on pallas).
- Constant-time: no secret-dependent comparisons; `frostito_verify_precommit`
  accumulates with `|=` over public values. `rand_scalar` samples 64 bytes from
  `rand_core::OsRng` and reduces — correct uniform sampling. No finding.

### 2.6 Verdict on candidate A

**Upstream with fixes; no redesign.** The weighting is mathematically sound and
is the right construction: it is flat FROST with a grouping optimisation, not a
new scheme, and it inherits FROST's proof on the same terms the unweighted
nested position does. The defects are all at the API boundary — W-1 is the
blocker, W-2/W-3 are policy invariants the crate should own — and each has a
mechanical fix. Land W-1 and W-3 before any value-bearing deployment.

---

## 3. Threshold ElGamal (candidate B — `ghettobox-vault-pvm`)

### 3.1 The scheme

Hashed ElGamal on ristretto255 (`src/pss/recovery.rs`):

- Key: an existing OSST/Shamir sharing of `x` with `Y = xG`. No dedicated key
  generation; the encryption key is the signing group's key.
- `encrypt` (`:41`): `R = rG`, `shared = Y^r`, `mask = HKDF-SHA256(shared)`,
  `C = m XOR mask`.
- `partial_decrypt` (`:75`): `partial_i = R^{x_i}`, plus an OSST contribution
  `share.contribute(rng, payload)`.
- `combine_partials` (`:99`): verify the OSST contributions with
  `osst::verify`, then Lagrange-interpolate the **partials**:
  `shared = Σ lambda_i · partial_i`.
- `decrypt` (`:64`): XOR back.

Lagrange coefficients come from `osst::compute_lagrange_coefficients` and are
correct; duplicate indices are rejected there and in `osst::verify`. The
KEM-plus-Shamir skeleton is the standard construction and is fine.

Note the code accesses `share.scalar` as a field; in osst 0.3.0 that field is
private behind `scalar()` (`src/lib.rs:147`), so this crate is built against an
older vendored osst. Any upstreaming has to re-establish which version the
review applies to.

### 3.2 E-1 (High) — partial decryptions carry no correctness proof

`partial_decrypt` (`:75`) produces two values that are never related to each
other:

```rust
let partial = ciphertext.ephemeral * share.scalar;          // R^{x_i}
let contribution = share.contribute(&mut rng, payload);      // PoK of x_i w.r.t. G
```

The OSST contribution proves knowledge of `x_i` on base `G`. It proves
**nothing** about `partial`. `combine_partials` verifies the contributions and
then interpolates the partials, which were never checked at all.

A single provider therefore substitutes any point for its partial, passes
verification, and corrupts the recovered shared secret — undetectably, and
unattributably, since OSST verification is share-free (§1.10). Because the
corruption is a *known* offset (`partial'_i = partial_i + delta·G` shifts the
result by `lambda_i·delta·G`), a provider that can observe whether decryption
succeeded also recovers the true shared secret from the corrupted one.

PoC: `tests/audit_threshold_elgamal.rs::corrupted_partial_decryption_is_accepted`.

**Fix.** A Chaum–Pedersen DLEQ per partial, proving
`log_G(P_i) == log_R(partial_i)` where `P_i = x_i·G` is the public verification
share (available from `dkg::DkgState::derive_verification_share`):

```
commit:   (A, B) = (k·G, k·R)
challenge: e = H(dom ‖ G ‖ R ‖ P_i ‖ partial_i ‖ A ‖ B ‖ ctx)
response: z = k + e·x_i
verify:   z·G == A + e·P_i   and   z·R == B + e·partial_i
```

This is also what makes the scheme *accountable*: a failing DLEQ names the
provider.

### 3.3 E-2 (High) — the proof does not commit to the ciphertext

`partial_decrypt(share, ciphertext, payload)` uses `ciphertext.ephemeral` to
compute the partial and `payload` — an unrelated caller-supplied byte string —
for the proof. Nothing ties them. A provider will compute `R^{x_i}` for **any**
`R` it is handed.

Consequently a party authorised to decrypt one ciphertext substitutes another
ciphertext's `R` and obtains that one's shared secret instead. The provider set
is a threshold CDH oracle on the group key: give it `R`, get `x·R`, decrypt
anything ever encrypted to `Y`. Since `Y` here is the *signing* group's key, the
blast radius is every ciphertext ever produced for that group.

PoC: `tests/audit_threshold_elgamal.rs::partials_authorised_for_one_ciphertext_open_another`.

**Fix.** The authorized payload must commit to the ciphertext. Minimally,
`payload := SigningContext::new(epoch, manifest, H(R ‖ C) ‖ request_id).encode()`,
constructed *inside* `partial_decrypt` from the ciphertext it was given, not
accepted from the caller — and the same bytes must appear in the DLEQ challenge
context of E-1 so the two proofs cannot be separated.

### 3.4 E-3 (Medium) — unauthenticated payload encoding

`C = m XOR HKDF(shared)` with no tag (`:41`, `:64`, `derive_mask` at `:152`):

- Bit-flipping in `C` flips the same bits of the plaintext. No integrity at all.
- `derive_mask` feeds HKDF only `shared.compress()`, with no salt and info
  `b"vault-pss-mask"`. `R` and `Y` are absent from the KDF, so nothing binds a
  mask to the ciphertext it belongs to.
- `|C| == |m|` leaks the exact plaintext length.
- With E-2 this is a textbook CCA break; on its own it means the vault cannot
  distinguish a tampered blob from a genuine one.

PoC: `tests/audit_threshold_elgamal.rs::ciphertext_is_malleable`.

**Fix.** KEM-DEM: `key = HKDF(shared, salt = R ‖ Y, info = "vault-pss-v2")`, then
ChaCha20-Poly1305 with `aad = R ‖ context`. No hash-to-group or lifted ElGamal is
needed — the message is a byte string, not a group element, so hashed ElGamal is
the right shape; it just needs an AEAD instead of a raw XOR.

### 3.5 Lower-severity notes

- `combine_partials` (`:99`) never checks `partials[i].index ==
  partials[i].contribution.index`. They are set together today, but the type
  permits a mismatch, which would pair one provider's Lagrange coefficient with
  another's partial.
- `threshold` is caller-supplied at `:99` and `:140` with no check against the
  group's actual threshold.
- Zeroization: none. `partial`, `shared_secret`, and the decrypted `Vec<u8>` are
  all plain values. The recovered `shared_secret` is as sensitive as the
  plaintext.
- Constant time: `ciphertext.ephemeral * share.scalar` is dalek and constant
  time. `RistrettoPoint::default()` is used as the identity accumulator at `:129`
  — correct today, but `identity()` says what is meant.

### 3.6 Verdict on candidate B

**Do not upstream as-is; the proof layer must be replaced, and the payload
encoding with it.** The skeleton — Shamir over ristretto, KEM to the group key,
Lagrange combination of partials — is standard and worth keeping. But "threshold
ElGamal with proofs" is precisely what this is not: the proofs it carries are
about the wrong base point, which is worse than carrying none, because
`combine_partials` reads as verified when it is not. E-1 and E-2 together mean
any single provider corrupts every decryption and any authorised requester
decrypts everything.

That is roughly a rewrite of `recovery.rs`, but a small and well-understood one:
Chaum–Pedersen is thirty lines, and the DEM change is a dependency swap. The
design target to write down first is what a partial decryption is *authorised
by* — that is the question E-2 exposes and no amount of proof machinery answers
it.

---

## 4. `SigningContext` (`osst::context`) — S-1 (Info)

**The encoding is correct.** `encode_into` (`src/context.rs:117`) emits
`len(domain) ‖ domain ‖ epoch ‖ manifest ‖ len(message) ‖ message`, all
fixed-width or length-prefixed, with a domain tag
`"osst/signing-context/v1"`. Every variable-length field is length-prefixed, so
the encoding is injective and no `(epoch, manifest_hash, message)` triple can be
made to collide with another — the in-crate test
`encoding_is_injective_across_field_boundaries` constructs exactly the
boundary-absorption attack and shows it fails. `digest()` is documented as a
handle, not a signing input. Nothing to fix here.

**It is not threaded into anything.** `SigningContext` appears nowhere in
`frost.rs`, `nested.rs` or `reshare.rs`; the only non-test use is the doctest.
It is a helper a caller constructs and passes as the message, and a caller that
forgets it gets a signature over the raw payload with no epoch binding and no
error. Given N-1 and W-1 — where the caller of `inner_sign_v2` does not even
supply a message — the chance of it being forgotten in the nested path is high.

**Fix.** Provide the only-way-in form:

```rust
pub fn sign_with_context<P: OsstPoint>(
    ctx: &SigningContext<'_>,
    nonces: Nonces<P::Scalar>,
    share: &SecretShare<P::Scalar>,
    package: &SigningPackage<P>,   // must have been built over ctx.encode()
    group_pubkey: &P,
) -> Result<SignatureShare<P::Scalar>, OsstError>
```

returning `Err` when `package.message() != ctx.encode()`. The same wrapper is
what the fixed `inner_sign_v2` of §1.3 should take.

**The verifier-side rule, stated explicitly.** Epoch binding is a property of the
*verifier*, not of the signature. `SigningContext` cannot retire old shares by
itself; a key-preserving reshare leaves an epoch-`n−1` quorum able to produce
valid signatures under the unchanged group key. What closes the gap is:

> A verifier MUST reconstruct the context bytes itself, using the epoch and
> manifest hash it obtains from an authoritative source it trusts independently
> of the signature (chain state, signed manifest), and verify the signature
> against **those** bytes only. It must never accept an epoch or manifest carried
> alongside the signature, and must reject any signature that verifies only
> against a different epoch.

The module documents the negative case correctly and importantly: for
protocol-defined signatures (Orchard `SpendAuthSig`, Penumbra spend auth,
Bitcoin sighash) the verifier hashes the transaction, there is nowhere to put
the epoch, and retiring shares requires an on-chain rotation to a **new** group
key. That caveat should be repeated at each call site that produces such a
signature, because it is the case where the mechanism silently does not apply.

---

## 5. Other findings in osst 0.3.0

### 5.1 R-1 (High) — the RedPallas nested path is still v1

`src/redpallas.rs:624`, `nested_redpallas_sign`. At `:670`:

```rust
let jury_commits = SigningCommitments {
    index: jury_index,
    hiding: r_nested,          // pre-bound with redpallas_inner_binding_factor
    binding: Point::identity(),
};
```

This is exactly the construction SECURITY-nested-frost.md §2.1 documents as
vulnerable: a pre-bound single point with an identity binding commitment, so the
outer binding factor multiplies the identity and vanishes. It uses its own
BLAKE2b inner binding factor (`redpallas_inner_binding_factor`, `:596`) with the
same structure as v1's.

It carries **no** deprecation notice, no `⚠️ INSECURE` banner — unlike
`nested::aggregate_inner_commitments`, which does — and it is the
Zcash/Orchard-compatible path, i.e. the one closest to mainnet value. The v2
migration stopped at the generic module.

**Fix.** Either port `nested_redpallas_sign` to the v2 pair-presentation shape
(the RedPallas `SigningPackage` already exposes `binding_factor`, `:141`), or
mark it insecure in the same terms as v1 and gate it behind the same feature.
Do not ship 0.3.x with an unmarked v1 in the Zcash path.

Also in that module, `:444`: the FVK seed is derived as
`BLAKE2b("frostito_fvk_sd_", s1 ‖ s2 ‖ Y)` over *both* players' secret shares,
which requires both secrets in one address space to compute and makes the
spending key recoverable from any two shares. It also means a key-preserving
reshare changes the FVK. If this is demo-only, say so in the doc comment; if it
is not, it is a separate finding.

### 5.2 C-1 (High, secp256k1 backend) — lossy point compression

`src/curve.rs:537`:

```rust
// for secp256k1, compress returns first 32 bytes (x-coord)
fn compress(&self) -> [u8; 32] {
    ...
    result.copy_from_slice(&bytes[1..33]);   // drops the 0x02/0x03 parity byte
}
fn decompress(bytes: &[u8; 32]) -> Option<Self> {
    compressed[0] = 0x02;                     // always even y
    ...
}
```

Two distinct consequences, both confirmed empirically
(`tests/audit_secp_encoding.rs`, run with `--features secp256k1 -- --ignored`;
both tests fail today):

1. **Not a round trip.** `decompress(compress(P))` is `P` or `−P` with
   probability ½. Every fixed-width serializer in the crate goes through
   `compress`: `Contribution::to_bytes` (`src/lib.rs:203`),
   `Signature::to_bytes` (`src/frost.rs:311`),
   `SigningCommitments::to_bytes` (`src/frost.rs:131`),
   `DealerCommitment::to_bytes` (`src/reshare.rs:124`). On secp, half of all
   serialized commitments come back negated, so Feldman verification and
   signature verification fail nondeterministically — and where they *don't*
   fail, they succeeded against `−C`.
2. **Hash collision.** `compress` is the encoding fed to `encode_commitments`
   (`src/frost.rs:344`) and `compute_challenge` (`src/frost.rs:380`). `P` and
   `−P` hash identically, so commitment sets that differ only by point negations
   yield the same binding factor and the same challenge. That is a direct break
   of the injectivity the binding factor depends on — the property §1.2 relies
   on — for this backend.

`COMPRESSED_SIZE` is correctly `33` and `compress_vec`/`decompress_slice` are
correct; it is the 32-byte path that is broken. `DealerCommitment::byte_size`
(`src/reshare.rs:119`) and `from_bytes` (`:134`) also hardcode 32 bytes per
point, so secp commitments do not serialize correctly by that route either.

**Fix.** Make the fixed-width path generic over `COMPRESSED_SIZE` (or gate the
`[u8; 32]` serializers behind a `COMPRESSED_SIZE == 32` bound) and remove
`compress`/`decompress` from the trait in favour of `compress_vec` /
`decompress_slice`. Until then, mark the `secp256k1` feature as non-functional.

### 5.3 L-1 (Medium) — liveness signature challenge omits the public key

`src/liveness.rs:306`:

```rust
fn challenge_hash(r: &[u8; 32], message: &[u8; 64]) -> P::Scalar {
    let mut hasher = Sha512::new();
    hasher.update(r);
    hasher.update(message);
    ...
}
```

No domain tag and, more importantly, no key prefix. Verification
(`:287`) is `g^s == R + e·Y` with `e` independent of `Y`, so a valid `(R, s)`
under `Y` becomes a valid `(R, s + e·delta)` under `Y + delta·G` for any `delta`
of the adversary's choosing, over the same message. Equivalently, an adversary
picks `R` and `s` freely and back-solves `Y = e^{-1}(g^s − R)`, exhibiting a
valid contribution for a key it does not control.

Whether this is exploitable depends on the registry: it is harmless if dealer
public keys are established with a proof of possession, and it is a full
impersonation of an unregistered identity if they are not. Nothing in osst
establishes them either way.

PoC: `tests/audit_frost_core.rs::liveness_signature_is_malleable_in_the_public_key`.

**Fix.** `e = H("osst-liveness-sig-v1" ‖ R ‖ compress(Y) ‖ message)`, as RFC 8032
and BIP340 both do.

Also `ContributionVerifier::verify_batch` (`src/liveness.rs:392`) zips
contributions to public keys **positionally**, so a caller that passes lists in
different orders verifies each contribution against the wrong key. The
`ContributionError::IndexMismatch` variant exists and is never constructed. Key
the public keys by `dealer_index`.

### 5.4 H-1 (Low) — OSST and liveness share one undomained challenge

`osst::hash_to_challenge(u, payload) = SHA512(compress(u) ‖ payload)`
(`src/lib.rs:103`) and `liveness::challenge_hash(r, m) = SHA512(r ‖ m)`
(`src/liveness.rs:306`) are byte-identical functions. A liveness signature
`(R, s)` over a 64-byte message therefore *is* an OSST contribution `(u = R, s)`
over that payload, and vice versa. Nothing in the crate prevents the two from
being instantiated on the same key material, and `liveness::DealerContribution`
is signed by a dealer that also holds an OSST share.

`tests/audit_frost_core.rs::osst_and_liveness_challenges_are_the_same_hash` (not
ignored) asserts the collision; it should start failing once a domain tag is
added, at which point delete it.

**Fix.** Domain-separate both: `"osst/contribution/v1"` and
`"osst/liveness-sig/v1"`. Consider also binding the contribution index and the
group public key into the OSST challenge.

### 5.5 Z-1 (Low) — zeroization is a plain assignment on three of four backends

`src/curve.rs:26`:

```rust
fn zeroize(&mut self) {
    *self = Self::zero();
}
```

Only the ristretto backend overrides it (`src/curve.rs:134`, delegating to
`zeroize::Zeroize`). Pallas, secp256k1 and decaf377 use the default, which is a
non-volatile assignment to a value the compiler can see is dead in every `Drop`
impl that calls it (`SecretShare::drop` at `src/lib.rs:140`, `Nonces::drop` at
`src/frost.rs:104`, `InnerNonces::drop` at `src/nested.rs:239`,
`dkg::Dealer::drop` at `src/dkg.rs:46`). It is entitled to elide the store.

The doc comment on the trait says exactly this ("may not actually overwrite the
original bytes"), so it is a known gap rather than an oversight — but pallas is
the Zcash backend and decaf377 is the Penumbra backend, i.e. the two that carry
value. The `zeroize` crate is already a dependency.

**Fix.** Remove the default and require each backend to implement it with
`zeroize::Zeroize` or an explicit volatile write. Separately: intermediate
scalars (`effective` in the weighted path, `lhs_exponent` in `osst::verify`,
Lagrange coefficient vectors) are never wiped; that is a larger job and probably
not worth it, but the *key* material should not be optional.

### 5.6 P-1 (Low) — panics on adversarial input

`assert!` rather than `Result` on caller-supplied indices and thresholds:
`SecretShare::new` (`src/lib.rs:145`), `frost::commit` (`src/frost.rs:405`),
`dkg::Dealer::new` (`src/dkg.rs:60-61`), `Dealer::generate_subshare`
(`src/dkg.rs:93`), `DealerCommitment::from_polynomial` (`src/reshare.rs:56`),
`evaluate_at` (`src/reshare.rs:88`).

narsild parses `dealer_index` and `recipient_index` off the wire as bare `u32`
and hands them to these functions, so a zero index from a peer aborts a
validator. The deserializers are better behaved (`SigningCommitments::from_bytes`
and `DealerCommitment::from_bytes` both reject index 0), but the constructors
reachable from the DKG driver are not. `threshold > n` is not checked anywhere;
it yields a polynomial nobody can reconstruct, which is a silent
misconfiguration rather than a panic.

`tests/audit_frost_core.rs` has three `#[should_panic]` cases documenting the
surface; they pass today.

### 5.7 B-1 (Low) — positional zip in batch verification

`batch_verify_subshares` (`src/reshare.rs:828`) is a correct randomized
linear-combination check — independent random weights per sub-share, so a single
bad share is caught with overwhelming probability, and it rejects on
`subshare.player_index != player_index`. But it zips `subshares` to
`commitments` **positionally** without checking
`subshare.dealer_index == commitment.dealer_index`. Misaligned inputs verify the
wrong pairs. Add the check, or take `&[(SubShare, &DealerCommitment)]`.

### 5.8 A-2 (Info) — binding factor omits the group public key

`compute_binding_factor` (`src/frost.rs:360`) hashes
`tag ‖ index ‖ len(m) ‖ m ‖ encode(B)`. RFC 9591's `compute_binding_factors`
prepends the encoded group public key to the binding-factor input. osst's
challenge does include `Y` (`src/frost.rs:380`), so cross-group confusion at the
signature level is prevented, and the practical impact is low. It is a deviation
from the construction BCKMTZ22 analyses, though, and if the intent is "FROST as
standardized", it should match. `encode_commitments` (`src/frost.rs:344`)
concatenates fixed-width 68-byte records from a `BTreeMap`, so it is canonically
ordered and unambiguous — no finding there, except on secp (C-1).

The RedPallas ciphersuite (`src/redpallas.rs:62`, `:83`) reproduces Zcash's
challenge (`BLAKE2b-512`, personal `"Zcash_RedPallasH"`, `R ‖ vk ‖ m`) correctly,
so its output is a valid Orchard `SpendAuthSig`. Its binding factor uses
personal `"FROST_RedPallas_"`, which is osst's own choice and not ZF
`frost-core`'s ciphersuite; the two cannot interoperate as co-signers in one
group. That is fine as long as it is not assumed otherwise — it is an internal
value and the emitted signature is still standard.

### 5.9 Deserialization and non-canonical points — no finding

All four backends reject non-canonical encodings on the way in:
`CompressedRistretto::decompress` (`src/curve.rs:216`), `Point::from_bytes`
(`:337`), `Scalar::from_repr` / `from_canonical_bytes` (`:182`, `:297`, `:500`,
`:653`), `decaf377::Encoding::vartime_decompress` (`:690`), and
`EncodedPoint::from_bytes` (`:563`). Scalars are always parsed with
`from_canonical_bytes`, never reduced. Round-trips are exact except on secp
(C-1). The identity point is accepted as a commitment everywhere, which is
correct for FROST (a signer may legitimately commit to it with negligible
probability) and is not exploitable given §1.7.

`compute_lagrange_coefficients` (`src/lagrange.rs:31`) is correct: it rejects
index 0, rejects duplicates, and the common-denominator trick with a single
inversion produces the right values — the in-crate tests check partition-of-unity
and explicit small cases, and `d_bar` cannot be zero once duplicates are
rejected.

### 5.10 A-1 (Info) — a correction to SECURITY-nested-frost.md

Two statements in the existing note should be revised when it is next touched:

- §4.1 "security therefore reduces to FROST's existing proof" overstates what
  `nested_v2_equals_flat_frost` shows. The test establishes honest-transcript
  equality, not a reduction. The reduction is plausible and is the right
  question for a cryptographer; it has not been done.
- §4.2 presents commit–reveal as the replacement for the removed `rho_inner`.
  It is not load-bearing: once the outer `rho` applies to `E_nested`, adaptive
  inner commitment selection gains an adversary nothing (§1.7). Keep the round —
  it is cheap and it closes the general `k`-sum steering — but do not rely on it
  as the reason v2 is sound.
- §5's concurrency bound of 4 sessions is described as "far below" the ROS
  threshold. For Wagner-style attacks against `ℓ` concurrent sessions the cost
  falls smoothly with `ℓ`; 4 sessions is well outside the polynomial-time ROS
  regime, but the figure quoted should be the actual sub-exponential cost at
  `ℓ = 4` rather than a comparison to the `ℓ > log2(q)` threshold, since that
  comparison implies a cliff that does not exist.

---

## 6. DKG round-2 confidentiality — D-1, D-2

### 6.1 What osst provides and what it leaves to the caller

`dkg::Dealer::generate_subshare` (`src/dkg.rs:88`) returns a plaintext
`SubShare<S>` holding the scalar `f_i(j)`. `reshare::SubShare`'s doc comment
(`src/reshare.rs:165`) says "Should be encrypted before transmission" and the
module docs say "sends sub-share `f_i(j)` to participant `j` (encrypted)"
(`src/dkg.rs:19`) — but nothing in the crate encrypts, and no type prevents a
caller from serializing one onto the wire. `SubShare::to_bytes`
(`src/reshare.rs:193`) hands out the 40-byte plaintext.

That is a defensible boundary for a `no_std` core. It is not defensible to ship
it with no sealed alternative, because the failure is silent and total.

### 6.2 D-1 (Critical) — narsild sends sub-shares in the clear, to everyone

In `penumbrafi/penumbra` PR #31 (branch `pr31-narsild`):

- `crates/bin/narsild/src/dkg.rs:39-46` — `DkgSubshareMsg { coeff_index,
  dealer_index, recipient_index, value_hex }`. The secret scalar is a hex
  string. `dkg.rs:222-244` fills it with
  `hex::encode(subshare.value().to_repr())`.
- `crates/bin/narsild/src/broadcast.rs:11-48` — `PeerSet::broadcast` POSTs a
  JSON body to every peer URL with `reqwest`. Peer URLs come from `--peers`
  (`main.rs:514`) and the README documents them as `http://val2:9200`. No TLS, no
  Noise, no mTLS, no cert pinning.
- `crates/bin/narsild/src/main.rs:288-297` — the code *intends* unicast and
  calls the fan-out broadcaster anyway:

```rust
for msg in &round2_msgs {
    if msg.recipient_index == holder_index { /* apply our own */ }
    else {
        // send to the specific peer
        // find which peer has this index
        app.peers.broadcast("/dkg/round2", msg);   // <- posts to ALL peers
    }
}
```

  `PeerSet` has no index→URL map, so the TODO in the comment was never
  implemented. Receivers drop messages not addressed to them
  (`main.rs:329-332`, `dkg.rs:248`), which is a filter at the application layer
  and no protection at all: every node has already received every sub-share.

**What an observer learns.** A dealer's polynomial has degree `t−1` and is
determined by `t` points. Round 2 puts `n−1` evaluations of every dealer's
polynomial on the wire. For any `n > t` — including 2-of-3 — an on-path observer
interpolates every dealer's polynomial, sums the constant terms, and holds the
group signing key. The Feldman commitments do not help: they are public by
design.

**And it needs no wire access.** Because of the broadcast bug, any *single*
honest-but-curious participant receives every other participant's sub-shares
directly and reconstructs the group key alone. The threshold is 1. That is the
Critical part of this finding; the plaintext transport is merely how an outsider
gets the same thing.

**The interleaved nested DKG makes it strictly worse.** `nested::interleaved_dkg`
(`src/nested.rs:105`) runs one inner DKG per outer polynomial coefficient, so
each dealer emits `outer_t` sub-shares per recipient instead of one. narsild's
`DkgSubshareMsg` carries `coeff_index` precisely because of this. The wire
therefore carries `outer_t` independent polynomials' worth of evaluations, and
recovering all of them yields not just one inner secret but every coefficient of
the *outer* polynomial — i.e. the outer group key, not only the nested
position's share.

### 6.3 D-2 (High) — no sender authentication anywhere in the ceremony

- There is **no roster type and no participant public key of any kind** — no
  Ed25519, no validator consensus key, no X25519, no TLS client cert. Identity
  is a bare `u32` `dealer_index` inside a JSON body (`dkg.rs:39-46`) and a list
  of URL strings (`broadcast.rs:12`). Nothing maps one to the other.
- `receive_round2` (`dkg.rs:247-275`) checks only
  `msg.recipient_index == self.holder_index`, then looks up the commitment by
  the attacker-controlled `sub.dealer_index`.
- The Feldman check at `dkg.rs:256-266` is real, but the commitment it checks
  against arrived over the **same** unauthenticated broadcast
  (`main.rs:227`, `main.rs:268`). A MITM — or any peer — supplies a forged
  commitment in round 1 and a matching forged sub-share in round 2 under any
  `dealer_index`, and verification passes. Verifying a value against a
  commitment the attacker also chose proves nothing.
- Round-1 acceptance is last-write-wins (`dkg.rs:180-183` uses `insert`), so a
  late forged commitment overwrites an honest dealer's.
- `handle_dkg_round1` (`main.rs:253-268`) auto-creates a ceremony from an
  unauthenticated peer message, with `inner_n = peer_count + 1`.
- `dkg.rs:160-167` silently `filter_map`-drops malformed commitment points and
  then checks only the surviving *count* against `inner_t`.

The README is candid about this ("There is no authentication on these endpoints
today. Deployments must keep the port on a private network"), which makes it a
known gap rather than a surprise — but a private network is not a threat model
for validator key material, and the broadcast bug of D-1 means even a fully
trusted network does not save it.

### 6.4 Recommended design

Put confidential delivery in osst, behind a feature, so callers cannot get it
wrong:

```toml
[features]
sealed = ["std", "dep:snow", "dep:x25519-dalek", "dep:hkdf"]
```

gated on `std` so the `no_std` core stays clean, with the plaintext
`SubShare`/`Dealer` API unchanged beneath it.

**Do not hand-roll it.** `/steam/rotko/zcli/crates/frost-spend/src/sealed.rs`
already solves exactly this problem for exactly this reason, and its rationale
(lines 1-43) is the argument above, arrived at independently. It uses
**`Noise_K_25519_ChaChaPoly_BLAKE2s`** — the same pattern ZF's `frost-client`
uses for FROST DKG round 2, so it is the Zcash ecosystem's transport rather than
ours. `Noise_K` is the right pattern here because both parties' static keys are
known in advance, making the handshake a single message with no round trip. It
binds all three things that must be bound:

- **recipient** — the responder's static key; nobody else opens it;
- **sender** — the `ss` mix puts the sender's static key into the key schedule
  itself, not merely into a signature wrapped around the ciphertext (this is what
  closes D-2 properly: a MITM cannot substitute a sub-share, because it cannot
  produce a message that opens under the pair);
- **ceremony** — the participant-set hash as the Noise prologue, so both sides
  must agree on the full roster or the message does not open (this closes the
  swapped-commitment variant of D-2, and the round-1 last-write-wins problem
  along with it).

Concretely, for osst:

1. `SealedDkg` roster type: `Vec<(u32 identifier, [u8; 32] x25519_static)>`,
   established in round 1 alongside the Feldman commitments and bound into the
   ceremony transcript hash. The X25519 key derives from the participant's
   existing identity seed via HKDF with a separation tag
   (`sealed.rs:68`), so no new key to distribute.
2. `Dealer::seal_subshare(recipient, &roster) -> SealedSubShare` and
   `Aggregator::open_subshare(&SealedSubShare, &roster)`, with the ceremony
   transcript as prologue.
3. Round 1 commitments signed by the same identity, and the roster fixed before
   round 2 opens — so the commitment a sub-share is verified against comes from
   an authenticated channel.

For narsild specifically, and independent of the crate work:

- Fix the broadcast bug first — it is a one-line severity reduction from
  "any participant holds the group key" to "any network observer does". `PeerSet`
  needs an `index -> URL` map and a `send_to(index, path, msg)`.
- Adopt a signed roster with static X25519 keys; port the `SignedRequest<T>`
  pattern from
  `/steam/rotko/zeratul/crates/ghettobox-vault-pvm/src/pss/client.rs:21-88`
  (Ed25519 over `payload ‖ timestamp ‖ sender_index`, verified with
  `verify_strict` against a known roster) for the transport layer, and the sealed
  round-2 packages above for confidentiality.
- Any key generated by the current code must be considered compromised and
  regenerated. This is not theoretical: every node that participated already
  holds enough to reconstruct.

Note for the record: there is **no `sealed.rs` in `/steam/rotko/zeratul`** — the
prior art referenced is `zcli`'s, cited above. The closest zeratul analogues are
`crates/zanchor/pallets/escrow-arbitration/src/encryption.rs` (X25519 + ChaCha20-Poly1305
ECIES, ephemeral sender key) and the `SignedRequest` roster in
`ghettobox-vault-pvm/src/pss/client.rs`.

---

## Verdicts

### Candidate A — weighted nested FROST v2 (zcli `frost-spend`)

**Upstream with fixes.** The construction is sound. Weights are virtual signers
with locally aggregated Lagrange coefficients, which is a valid Shamir sharing
and reduces to flat FROST by the same linearity argument as the unweighted
nested position; no new cryptographic assumption is introduced and the FROST
unforgeability argument carries over on the same terms. The defects are all at
the API boundary.

Required before upstreaming: **W-1** (params must be derived from a package the
signer holds, which is the same fix as **N-1**), **W-3** (checked weight
allocation). Required before any value-bearing deployment: **W-2**,
**N-2**. **W-4** is hygiene and should be swept in the same pass.

### Candidate B — threshold ElGamal (`ghettobox-vault-pvm`)

**Do not upstream as-is. The proof and encoding layers must be redesigned;
the skeleton can be kept.**

The KEM-to-group-key plus Lagrange-combination structure is standard and
correct. But the partial decryptions carry proofs about the wrong base point
(**E-1**) and the authorization does not name the ciphertext (**E-2**), so the
two properties a threshold decryption scheme exists to provide — that a partial
is correct, and that it was authorised for *this* ciphertext — are both absent
while the code reads as though they are present. Add Chaum–Pedersen DLEQ, bind
the ciphertext into both the payload and the DLEQ context, and replace the XOR
stream with an AEAD (**E-3**). That is a rewrite of `recovery.rs`, but a small
and well-understood one.

### osst 0.3.0 itself

The v2 nested construction is the right fix for the v1 gap and the flat-signer
equivalence is real. Three things should not ship in this state:

- **R-1** — the RedPallas path still contains v1, unmarked, and it is the path
  nearest to mainnet value.
- **N-1** — the v2 API asks an inner holder to sign three scalars, which is
  weaker message binding than v1 offered. It is the single highest-value fix in
  this report and it also fixes W-1.
- **C-1** — the secp256k1 backend's point encoding is broken; mark the feature
  non-functional or fix it.

**D-1 remains the most urgent item overall.** It is not in osst — the crate's
boundary is defensible — but osst's API shape is what made it easy to get wrong,
and a `sealed` feature built on `zcli`'s Noise_K module is the durable fix for
every consumer.
