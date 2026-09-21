# Maintainer review — osst 0.4.0, narsild PR #31, zcli frost-spend, bridge design

**Date:** 2026-09-21
**Reviewer:** maintainer pass, threshold custody / FROST / shielded-pool perspective
**Scope and revisions reviewed**

| Target | Revision |
|---|---|
| `frostito` (osst 0.4.0) | `bf30136` on `main` |
| `penumbrafi/penumbra` PR #31 `narsild` | `bde6335e0` |
| `rotkonetworks/zcli` `crates/frost-spend` | `3cfb5e53` on `master` (the named `d4243ad` does not exist in the repo) |
| Bridge design | `docs/design/zcash-shielded-bridge.md` @ `bde6335e0`; `docs/design/validator-custody-bridge.md` (untracked, in `/steam/rotko/penumbra`) |

This is a follow-on to `SECURITY-REVIEW-2026-09.md`. Part of the job was to check that the
0.4.0 fixes actually closed each prior finding and did not open new ones. **They largely
did.** I re-verified each prior crate finding against the code rather than against the
CHANGELOG; the table below records what I actually checked. The serious problems in this
review are (a) in `narsild`, which is
where the crate meets a network, (b) in `zcli`, where the 0.4.0 fixes were never adopted,
and (c) two new crate-level findings the prior audit missed.

A note on how to read the severities: osst is a library, and a library finding is rated by
what it lets a caller get wrong. `narsild` is a daemon that listens on a socket, and a
daemon finding is rated by what an attacker with network reach gets. That is why the
highest-severity items below are all in `narsild` even though the cryptographic core is in
better shape than it was in 0.3.0.

### Prior findings, re-verified

| Prior ID | Status | Evidence |
|---|---|---|
| N-1 | **closed** | `inner_sign_v2` rejects on `package.message() != approved_message`, `src/nested.rs:1517-1519` |
| N-2 | **closed** | session id threaded through commit/sign; `verify_nested_commitment`, `src/nested.rs:1349-1367` |
| N-3 | **closed** | quorum-coverage check, `src/nested.rs:1645-1660` — but see M-14, the signing side is still open |
| C-1 | **closed** | SEC1 33-byte compress with parity, `src/curve.rs:583-613`; identity round-trips. Minor residue in M-22 |
| F-1 | **closed** | `sign()` checks the package's commitment for its own index, `src/frost.rs:~420-433` |
| K-1 | **closed** | `ProofOfKnowledge` with epoch in the challenge, `src/dkg.rs:45-103`; verified in `submit_commitment`, `:475` — but see M-6, the complaint half is not closed |
| L-1 | **closed** | `challenge_hash` includes `Y`, `src/liveness.rs:320-345` |
| H-1 | **closed** | `OSST_CONTRIBUTION_DOMAIN` vs `LIVENESS_SIG_DOMAIN`, `src/lib.rs:104` / `src/liveness.rs:70` |
| Z-1 | **closed** | `write_volatile` + `compiler_fence` on pallas, secp256k1, decaf377 — `src/curve.rs:269-270, 487-488, 640-641` |
| P-1 | **closed** | no `assert!`/`unwrap` on wire-parsed input outside `#[cfg(test)]`; the remaining hits in `src/reshare.rs:941-1054` are test code |
| B-1 | **closed** | `batch_verify_subshares` pairs by `find(\|c\| c.dealer_index == subshare.dealer_index)`, not by `zip` — `src/reshare.rs:~1090` |
| R-1 | **closed** | `nested_redpallas_sign` and the v1 helpers are behind `#[cfg(feature = "legacy-v1")]`, `src/redpallas.rs:604-645` |
| D-1 | **closed in the crate** | `sealed` module ships Noise_K sealing. Residual footgun in M-25; reintroduced by the caller in M-1 |
| A-2 | open (Info) | M-24 |
| A-3 | open | sharpened as M-13 |

Three findings are new to this pass: **M-5**, **M-12** and **M-25**.

---

## Findings

| ID | Severity | Component | Finding |
|---|---|---|---|
| **M-1** | **Critical** | narsild `main.rs` | `GET /dkg/status` returns this node's secret Shamir shares in the response body, unauthenticated |
| **M-2** | **Critical** | narsild `main.rs` / `signing.rs` | Unauthenticated signing oracle over attacker-chosen bytes; with the documented `--outer-threshold 1` default this is a complete signature |
| **M-3** | **Critical** | narsild `main.rs` / `keypackage.rs` | Any reachable party can trigger a DKG that truncates the key package in place, with no backup — irreversible loss of the escrow key |
| **M-4** | **High** | narsild `signing.rs` | The outer group public key `Y` is taken from the coordinator's request, not from the node's own key package |
| **M-5** | **High** | osst `dkg.rs` / `sealed.rs` + narsild `broadcast.rs` | The D-2 fix binds sub-share↔commitment but not commitment↔broadcast: a malicious **dealer** equivocates and splits the group. No echo round anywhere |
| **M-6** | **High** | narsild `dkg.rs` | Complaints are unauthenticated, carry no epoch/session, are not re-broadcast, and nobody adjudicates — one packet aborts one node, splitting the ceremony |
| **M-7** | **High** | narsild `dkg.rs` + osst `dkg.rs` | Round-1 slot squatting: first-write-wins silently drops an honest dealer's commitment and frames it in round 2 |
| **M-8** | **High** | zcli `frost-spend` | W-1 not fixed: `frostito_sign_v2` has no message parameter and takes ρ, c, λ as opaque coordinator-supplied scalars. `from_outer` has zero call sites in the whole repo |
| **M-9** | **High** | zcli `frost-spend` | The weighted construction **pre-aggregates**; it is not w flat signers and the flat-FROST reduction asked about does not hold in that form |
| **M-10** | **High** | narsild `keypackage.rs` / `main.rs` | Epoch rollback by deleting one unauthenticated, unMACed JSON file; no high-water mark |
| **M-11** | **High** | Bridge design | Two live design docs give contradictory answers to the epoch problem, and one of them contains three sentences that are simply false |
| **M-12** | Low | osst `liveness.rs` | `signing_message` concatenates two variable-length fields with no length prefixes — the encoding is not injective. Missed by the prior audit |
| **M-13** | Medium | osst `nested.rs` | Session id is a mixing guard, not a replay guard: it enters no hash. Combined with narsild's absent durable nonce store, snapshot-restore is live nonce reuse |
| **M-14** | Medium | osst `nested.rs` | `NestedSigningRequest.active_indices` is unvalidated against the commitment set |
| **M-15** | Medium | narsild `roster.rs` | One value is session id, manifest hash and Noise prologue; a same-roster same-epoch re-run reproduces it byte-identically |
| **M-16** | Medium | Bridge design | The withdrawal check "validators verify tx matches event" is three words where it needs to be a fifteen-item list; no reorg-after-mint rule; Zcash fees unaddressed |
| **M-17** | Medium | narsild `main.rs` | Error `Display` is returned verbatim to any caller — a precise which-check-failed oracle |
| **M-18** | Medium | narsild | Unbounded, never-collected state from unauthenticated input, including live secret nonce material |
| **M-19** | Medium | zcli `frost-spend` | W-2/W-3/W-4 all still open: self-asserted weights drive the threshold sum, unchecked `u32` overflow, no `max_weight < threshold` |
| **M-20** | Low | osst `nested.rs` | `inner_sign_v2` never calls `verify_inner_precommit`; the commit–reveal round is caller convention |
| **M-21** | Low | osst `nested.rs` | `from_coordinator_checked` is a footgun that should be `#[deprecated]` |
| **M-22** | Low | osst `curve.rs` | `secp256k1::compress()` silently returns all-zeros on an unexpected encoding length |
| **M-23** | Low | osst `tests/` | Negative-test coverage is thin: seven distinct rejection paths have no test |
| **M-25** | Low | osst `reshare.rs` | D-1 residual: `SubShare::to_bytes()` is still `pub` and undeprecated — the plaintext footgun the `sealed` module exists to remove is one method call away |
| **M-24** | Info | osst `frost.rs` | A-2 still open — the binding factor omits `Y`, where RFC 9591 includes it |

---

## Evidence and fixes

### M-1 (Critical) — `/dkg/status` hands out the secret shares

`crates/bin/narsild/src/main.rs:506`:

```rust
"aborted": c.abort_reason(),
"result": c.result,
```

`DkgResult` derives a plain `Serialize` with no `skip`, and its fourth field is the secret
material — `crates/bin/narsild/src/dkg.rs:143-144`:

```rust
/// Shamir share of each outer coefficient, hex scalars.
pub coefficient_shares: Vec<String>,
```

`finalize()` stores the result (`dkg.rs:685`) and it persists in the ceremony mutex until
the next `/dkg/init` or a restart, so this is a standing window, not a race. There is no
authentication on any endpoint (`main.rs:711-724`) and the default bind is `0.0.0.0:9200`
(`main.rs:552`).

This is finding D-1 of the prior audit — the one rated Critical, the one 0.4.0's entire
`sealed` module was written to fix — reintroduced through an HTTP GET. Collecting the
status page from any `t` nodes reconstructs every outer coefficient, i.e. the group
signing key. The crate's own README names a hostile peer as the adversary to survive
(`README.md:36-39`) and then relies on "keep the port on a private network"
(`README.md:124-127`), which is not a mitigation against an adversary who is by
construction on that network.

**Fix:** `#[serde(skip)]` on `coefficient_shares`, and return only `coeff_commitments` and
`verification_shares` from the status handler. Then add endpoint authentication (below) —
but the `serde(skip)` is the one-line change that stops the bleeding and should land
regardless of anything else in this review.

### M-2 (Critical) — unauthenticated signing oracle

No endpoint carries any authentication (`main.rs:711-724`); `grep` for
`Authorization`/`Bearer`/any auth layer in `main.rs` returns only the bind address. The
pair `/sign/round1` then `/sign/round2` is the whole coordinator flow, and `start_round2`
signs immediately (`signing.rs:476-489`).

What the node independently derives is the **context wrapper only** —
`crates/bin/narsild/src/signing.rs:313`:

```rust
let ctx = SigningContext::new(self.epoch, self.manifest_hash, &parsed.message);
```

`parsed.message` is `hex::decode(&req.message_hex)` (`signing.rs:350`) — chosen by whoever
sent the request. The epoch and manifest are bound; **the payload is not.** There is no
approval policy, no allowlist, no operator gate, nothing that maps a request to a
Penumbra event. With the documented default `--outer-threshold 1` (`main.rs:575`,
`README.md:264`) the nested position alone completes the outer signature.

`README.md:216` claims "It cannot make a node sign anything the node has not
independently derived." That sentence is true of the epoch/manifest binding and false of
the message, which is the part that matters. It should be narrowed or removed.

**Fix:** three separate things, none optional. (1) mTLS or a pre-shared per-peer token on
every endpoint, derived from the roster identities that already exist. (2) A real approval
predicate: the node fetches the withdrawal event from its own `pd` and reconstructs the
expected message, refusing anything that does not match — this is the bridge design's own
stated model (`zcash-shielded-bridge.md:53-55`, "the event, not any off-chain message, is
the authorization") and the daemon does not implement it. (3) Bind to loopback by default
and make a non-loopback bind an explicit flag.

### M-3 (Critical) — remote, irreversible key destruction

`POST /dkg/init {"epoch": N}` for any `N` greater than the current epoch is accepted
(`main.rs:370-378`; the guard at `main.rs:265-269` only refuses a *backwards* epoch), and
a forged `/dkg/round1` auto-adopts a peer-asserted epoch and starts a ceremony when none
is active (`main.rs:411-426`). The honest nodes then run a perfectly legitimate DKG among
themselves, and `main.rs:337` calls `package.save()` → `write_private` with
`.truncate(true)` (`identity.rs`). No backup, no confirmation, no second operator.
`handle_dkg_init` also unconditionally replaces an in-flight ceremony (`main.rs:381-382`).

Old shares are gone. Anything held under the old group key is unspendable — and for the
Zcash escrow, where there is no script recovery path
(`validator-custody-bridge.md:419-421`), unspendable is permanent.

**Fix:** authentication (M-2), plus write-new-then-rename with a retained
`key_package.epoch-N.json` history and a refusal to overwrite a package for an epoch that
the chain has activated. A DKG should never be startable by an unauthenticated packet.

### M-4 (High) — the group public key comes from the request

`signing.rs:301-308` correctly calls `from_coordinator_checked`, and the node correctly
builds its own `SigningContext` from its own epoch and manifest. But the outer group
public key is `parsed.group_pubkey` — taken from the wire — and is passed as-is into
`NestedSigningRequest.group_pubkey` (`signing.rs:318`) and thence into the challenge
`c = H(R ‖ Y ‖ m)`.

`from_coordinator_checked` does not save this: it recomputes ρ, c and λ *using the
supplied `Y`*, so a coordinator that substitutes `Y'` gets a self-consistent package that
passes every check. The node then produces a share over the approved message under an
attacker-chosen challenge.

This is not a forgery — the resulting signature verifies under nothing — so it is High and
not Critical. But it hands an adversary free choice of `c` over a fixed `m`, which is
precisely the degree of freedom the ROS literature is about, and there is no reason to
concede it. osst invites the mistake: `nested.rs:1378` documents `NestedSigningRequest` as
"Every field is public data", which is true and beside the point — public is not the same
as locally anchored.

**Fix:** narsild must take `Y` from its own `KeyPackage` and reject a request whose
`group_pubkey` differs. In osst, change the `NestedSigningRequest` doc comment to
distinguish *public* from *locally anchored*, and name `group_pubkey`, `active_indices`
and `nested_index` as the three fields the caller must anchor itself.

### M-5 (High) — the D-2 fix stops a MITM, not a malicious dealer

`sealed.rs:222-232` puts a digest of the dealer's Feldman commitment inside the sealed
plaintext, and `open_subshare` checks it (`sealed.rs:366-371`). That binds the sub-share to
the commitment *as delivered to this recipient*. Nothing binds the commitment to a single
value seen by **all** recipients.

So a malicious dealer sends `(C_A, f_A(a))` to Alice and `(C_B, f_B(b))` to Bob, each pair
internally consistent, each passing its Feldman check and its digest check. Alice and Bob
derive different group keys and neither can tell. The prior audit's D-2 was written about
a MITM substituting a matched pair; the fix is correct for that attacker and does not
address the dealer itself, which is the stronger and more relevant adversary given the
crate's stated threat model.

osst cannot fix this alone — it needs a reliable broadcast, which is the caller's job — and
`narsild` does not provide one. `broadcast.rs:294-309, 334-348` is `n−1` independent
fire-and-forget HTTP POSTs: no echo round, no cross-node hash of the round-1 set, no
equivocation detection. `coeff_commitments` and `verification_shares` are asserted
identical on every node (`dkg.rs:145-150`) and that assertion is exercised only by an
in-process honest test (`tests.rs:113-114`), never at runtime.

**Fix:** an echo round. After round 1 closes, every node broadcasts
`H(sorted round-1 package set)` and refuses to enter round 2 until it has `n` matching
digests. This is cheap, it is the standard construction, and it simultaneously closes M-6
and M-7. osst should ship the digest helper so every caller computes it the same way; note
that the prior audit's §6.4 recommended design should be checked for whether it called for
this — if it did, shipping 0.4.0 without it is a closure gap rather than a new finding.

### M-6 (High) — complaints: unauthenticated, unbound, unadjudicated

`receive_complaint` (`dkg.rs:701-715`) checks only that both indices are on the roster.
Nothing ties a complaint to its claimed sender. `Complaint` (`dkg.rs:128-135`) carries no
epoch, no session id and no signature, so a complaint captured from one ceremony replays
into a later one. `handle_dkg_complaint` (`main.rs:482-494`) does **not** re-broadcast, so
a complaint delivered to one node aborts that node while the rest finalize — the split-group
outcome the design notes say the broadcast exists to prevent (`dkg.rs:689-698`).

Who adjudicates: nobody. Any complaint from anyone is believed. `reason: String` is
unbounded attacker-controlled text logged at `error!` (`dkg.rs:705-711`), and
`DefaultBodyLimit` is never set, so axum's 2 MiB default is the only bound.

Underneath this sits an osst-level gap that the K-1 fix created. `DkgState::disqualify`
(`src/dkg.rs:543`) is a purely local mutation whose doc says "Every participant must apply
the same complaints, or they derive different keys" — and osst provides no mechanism to
make that true. A complaint is not publicly verifiable: proving dealer `i` sent a bad
sub-share to holder `j` requires `j` to publish `f_i(j)`, which nothing supports. So an
honest node cannot distinguish a true complaint from a false one, and the only two
available policies are "believe everyone" (one packet DoSes the ceremony, which is what
narsild does) and "believe no-one" (K-1 is undetectable again).

**Fix:** complaints must be signed by the complainant's roster identity, carry
`(epoch, session_id)`, be re-broadcast on receipt, and be *justified* — the complainant
publishes the decrypted sub-share plus the sealed ciphertext so every node re-runs the
Feldman check itself and reaches the same verdict. A sub-share whose secrecy is already
forfeit by the complaint is no additional loss. Without justification, keep the abort but
require `t` independent complaints before acting.

### M-7 (High) — round-1 slot squatting frames an honest dealer

osst's `submit_commitment` is first-write-wins and returns `Ok(false)` on a taken slot
(`src/dkg.rs:494-496`), and narsild's `receive_round1` treats `Ok(_)` as success
(`dkg.rs:443-444`). An unauthenticated attacker who posts a self-generated, PoK-valid
commitment under honest dealer 3's index *first* causes dealer 3's genuine broadcast to be
silently dropped. Dealer 3's round-2 sealed package then fails the commitment-digest check
and every recipient raises a complaint naming dealer 3.

The PoK added for K-1 does not help: the attacker proves knowledge of its own constant
term quite honestly. The index is the only claim of identity and it is unauthenticated.

**Fix:** authenticate round 1 to the roster identity (the X25519 keys are already pinned
per-peer, `identity.rs` + `roster.rs:102-130`; they are currently used *only* for sealing
round 2). In osst, `submit_commitment` returning `Ok(false)` for "slot taken" is too quiet
for a security-relevant event — it should be a distinct error the caller must handle.

### M-8 (High) — zcli never adopted the N-1 fix

`frostito_sign_v2` (`crates/frost-spend/src/nested.rs:931-935`) has no message parameter at
all:

```rust
pub fn frostito_sign_v2(
    nonce: FrostitoNonce,
    validator_shares: &ValidatorShares,
    params: &FrostitoSigningParamsV2,
) -> Result<FrostitoResponse, osst::OsstError>
```

`FrostitoSigningParamsV2` is a *local* type (`nested.rs:917-928`) with no constructor and
no `from_outer`; its three scalars are consumed as opaque caller-supplied values and there
is no `SigningPackage` argument anywhere on the weighted path. The v1 function it replaced
(`nested.rs:203-209`) *did* take `message: &[u8]`. `grep -rn from_outer` across the entire
zcli repo returns **zero hits**. `grep -rn "approved"` across `crates/frost-spend/src/`
returns zero hits.

So the message reaches the signer only through the `outer_challenge` scalar: a validator
signs a challenge it cannot attribute to any payload. This is exactly W-1, and exactly N-1,
unfixed.

Mitigating context, which is why this is High and not Critical: the weighted path has **no
non-test caller**. `#[cfg(test)]` begins at `nested.rs:336` and every call site of
`frostito_*` is below it. The bridge design confirms weighting is deferred
(`zcash-shielded-bridge.md:155, 175-176`). The `bridge_e2e.rs` integration test does derive
the three scalars from a real `SigningPackage` (`:202-208`, `:359-366`) — but as a
hand-rolled struct literal, which is the duplication `from_outer` exists to prevent.

**Fix:** give `FrostitoSigningParamsV2` a `from_outer` and delete the public field access;
add an `approved_message` parameter checked byte-for-byte against the package. This is a
mechanical port of the osst 0.4.0 change and should happen before the crate acquires a
caller, not after.

### M-9 (High) — the weighted construction does not reduce to w flat signers

This was the specific question asked, so here is the specific answer: **it pre-aggregates,
and the "w independent flat FROST signers" reduction does not hold.**

1. One nonce pair per physical validator regardless of weight — `frostito_commit`
   (`nested.rs:134-152`) samples exactly one `hiding` and one `binding`; `weight` is
   carried as metadata only.
2. The `w` shares are collapsed into one scalar before signing —
   `ValidatorShares::effective_share` (`nested.rs:72-84`) computes `Σ_j λ_j·σ_j`, called
   once at `nested.rs:936`.
3. The whole inner set contributes **one** pair to the outer commitment list —
   `frostito_aggregate_commitment_pair` (`nested.rs:902-910`) returns `(ΣD_k, ΣE_k)`.
4. One binding factor shared by every validator — `params.outer_binding` (`:919`) is the
   outer ρ for the nested *position*, applied identically by all (`:938`). There is no
   per-virtual-index `ρ_i = H(i, m, B)`. The per-validator ρ that v1 had (`:170-193`) was
   deliberately removed.
5. No per-virtual λ_i survives into the response: `z_k = d_k + ρ·e_k + (λ_out·c)·eff_k`
   (`:937-941`).

The code's own comment is accurate about what it *does* claim (`nested.rs:855-862`): the
entire nested position ≡ **one** flat signer holding `σ_out` with nonce `(d, e)`. That is a
different and weaker statement than the one in the task, and it is the honest one. Note
that osst's own `inner_sign_v2` *does* carry a per-holder `μ_k` (`src/nested.rs:1565`),
because there each holder has exactly one share and one nonce pair — so osst and zcli are
not the same construction and should not be described as if they were.

Two caveats on the substitute reduction, as code facts. The commit–reveal it relies on is
unenforced: `frostito_aggregate_commitment_pair` verifies no precommitment, and the
requirement lives in a doc comment (`nested.rs:889-892, 899`). And the equivalence test
(`nested.rs:371-445`) fills the three outer scalars with `rand_scalar` (`:421-426`) — it
verifies the algebra of the additive split and cannot catch a coordinator-asserted-scalar
failure, which is the failure that actually exists.

**Fix:** either realise weights as genuine virtual signers, each with its own nonce pair,
its own entry in the outer commitment list and its own ρ_i — at which point the flat
reduction is immediate and the whole construction needs no novel argument — or keep the
pre-aggregated form and get the FROST2-shaped claim reviewed by a cryptographer. The first
option costs `w` points on the wire per validator and buys a proof; take it.

### M-10 (High) — epoch rollback by `rm`

The epoch lives only in `key_package.json` (`keypackage.rs:39`) — plain JSON, mode 0600, no
MAC, not encrypted (`keypackage.rs:118-124`). In-memory `signer.epoch` is loaded from it
(`main.rs:653-676`) and the "must advance" check added by the HEAD commit compares against
that in-memory value only (`main.rs:266-268`). Delete the file → `epoch = 0`
(`main.rs:674`) → every epoch from 1 up is accepted again. `format` (`keypackage.rs:104-110`)
is a version probe, not integrity. `/dkg/activate` re-reads disk with no authentication
(`main.rs:514-528`).

Two adjacent defects. `manifest_hash()` fails **open** —
`keypackage.rs:161-169` returns `[0u8; 32]` when `roster_hash` does not decode to 32 bytes,
so a truncated field means signing proceeds under a null manifest binding instead of
refusing; it should return `Result`. And save failure is non-fatal: `main.rs:337-341` logs
"could not persist key package" and calls `install_share` anyway, so the node runs at epoch
`e+1` in memory over an on-disk epoch `e` and silently reverts on restart.

**Fix:** a separate append-only epoch high-water-mark file, checked independently of the key
package; MAC the key package under a key derived from the identity seed; make a save failure
fatal.

### M-11 (High) — the two design docs contradict each other, and one is wrong

`zcash-shielded-bridge.md` and `validator-custody-bridge.md` are both live, overlap in
scope, and give opposite answers to the epoch problem. `zcash-shielded-bridge.md` treats
the fixed escrow address as the premise and leaves the problem explicitly unresolved
(`:221-227`). `validator-custody-bridge.md` gives up address invariance and rotates the key
when departures reach `n−t+1` (`:389-394`), coupling `unbonding_delay` to the rotation
period so ex-holders stay slashable (`:395-400`) — and never states the sighash constraint
that forces the choice. It also drops the nested-FROST/OSST machinery the other doc depends
on (`:459-461`).

Worse, `zcash-shielded-bridge.md` contains three sentences that contradict its own §6 and
are false as written:

- `:99-102` — "Old shares become useless."
- `:198-200` — dev-plan step 6: verify "that the old shares cannot [spend]."
- and the §6 entry that correctly says the opposite: "A pre-rotation quorum that kept its
  shares can still produce a valid spend authorization. … Deleting old shares is a policy,
  not a mechanism; this needs a real answer." (`:221-227`)

A key-preserving reshare does not retire anything. A departed member who kept its share
holds a valid share of the same secret, forever. The three sentences above must be deleted
or corrected before anyone builds against this document — someone will read `:99-102`,
believe rotation is handled, and skip the deletion discipline that is the only thing
actually protecting the escrow.

**Fix:** pick one design. Delete or correct the three sentences regardless.

### M-12 (Low) — the contribution-signature message is not injective

New; missed by the prior audit. `src/liveness.rs:265-268`:

```rust
hasher.update(b"OSST-CONTRIBUTION-V1");
hasher.update(commitment.to_bytes());
hasher.update(liveness.to_bytes());
hasher.update(context);
```

`DealerCommitment::to_bytes()` is `dealer_index:4 ‖ t compressed points` — **variable length
with no prefix** (`src/reshare.rs:136-143`), and `from_bytes` needs the threshold passed out
of band (`:146`). `LivenessProof::to_bytes()` is also variable (`src/liveness.rs:104-110`:
48-byte anchor, `u32` proof length, proof, 32-byte state root) — self-delimiting once its
start offset is known, but its start offset is exactly what is undetermined. `context` is
caller-supplied and trailing.

So the concatenation is not injective: reading `t+1` coefficients instead of `t` shifts the
commitment/liveness boundary 32 bytes and, if the shifted bytes happen to parse, yields a
second `(commitment, liveness, context)` triple with the same digest.

**Severity is Low, and deliberately so.** This is an encoding defect, not a forgery
primitive. `ContributionSignature::sign` is called by a dealer over *its own* commitment
(`:275-283`), so an attacker cannot induce an honest signer to sign a commitment it did not
construct; and a verifier parses with a threshold it pins out of band, so it only ever
reaches one parse. It is the same class of defect as the prior audit's B-1 — a positional
assumption where an explicit one belongs — and it should be fixed on the next wire break
rather than treated as live exposure.

`SigningContext::encode` (`src/context.rs:110-117`) gets this exactly right, length-prefixing
every variable field and documenting why. The same discipline was not applied here. Note
also that this tag is the last `SCREAMING-CASE-V1` string left in the crate; the 0.4.0 H-1
fix moved everything else to `osst/…/v1`.

**Fix:** length-prefix both `commitment.to_bytes()` and `liveness.to_bytes()`, and bump the
tag to `osst/contribution-sig/v2` since the change is signature-incompatible.

### M-25 (Low) — D-1 residual: `SubShare::to_bytes()` is still public

`src/reshare.rs:206-213` still exposes the 40-byte plaintext sub-share serializer as a plain
`pub fn`, with no `#[deprecated]` and no doc warning. The `sealed` module exists precisely
because handing out that plaintext is a total, silent compromise — round 2 puts `n−1`
evaluations of every dealer's polynomial on the wire and any observer interpolates the group
key — and `narsild` demonstrated that a caller will reach for it.

It cannot simply be removed: `seal_subshare` uses it internally (`src/sealed.rs:295`). But
nothing marks it as the dangerous path, so the type system offers a caller no steer at all
between it and the sealed API.

**Fix:** `#[doc(hidden)]` plus a `#[deprecated(note = "plaintext sub-share; use
sealed::seal_subshare")]`, or make it `pub(crate)` and give the sealed module the only public
serializer.

### M-13 (Medium) — the session id is a mixing guard, not a replay guard

Worth stating precisely because the CHANGELOG's N-2 entry can be read as more than it is.
`session_id` appears in `InnerNonces`, `InnerCommitments` and `inner_precommit`
(`src/nested.rs:1264-1270`), and is checked for equality in three places
(`:1327`, `:1524`, `:1534`). It enters **neither** hash that matters: `compute_binding_factor`
(`src/frost.rs:385-391`) and `compute_challenge` (`:405-410`) never see it.

So two sessions with the same message and the same outer commitment list produce the same
ρ and the same c. What actually prevents nonce reuse is (a) `inner_sign_v2` taking
`nonces` by value (`:1510`) so the pair is consumed and zeroized, and (b) the check at
`:1535-1541` that the published commitment matches these nonces. Within one process that is
sound. Across a process boundary it is nothing, and the doc says so:
"Callers that persist state across restarts MUST additionally record
`(session_id, holder_index)` as spent — the type system cannot see a process boundary"
(`:1499-1501`).

narsild does not do this. Nonces live in an in-memory `BTreeMap` (`signing.rs:219`) with no
durable spent-store, which the README admits (`:135-139`). A VM snapshot-restore, a
container restart from an image, or any rollback of the node's state replays a nonce under
a fresh challenge, and two responses under one nonce leak the share by elementary algebra.
For a daemon whose whole purpose is holding long-lived escrow authority, this is the
failure mode most likely to actually happen in production — snapshots are operational
routine, not an attack.

`validator-custody-bridge.md:341-352` gets this right in prose ("nonce state written before
a partial is released and never snapshot-restored"). No code implements it.

**Fix:** a write-ahead spent-session log, `fsync`'d before any share leaves the process,
consulted on every signing request. This is the single highest-value change in narsild
after authentication.

### M-14 (Medium) — `active_indices` is unvalidated

`NestedSigningRequest.active_indices` (`src/nested.rs:1385`) is coordinator-supplied and
`inner_sign_v2` checks only that `share.index` has a position in it (`:1560-1564`). Nothing
checks that it is a subset of the holders in `inner_commitments`, that it is duplicate-free,
or that its size is at least `t_in`. A mismatched set yields a `μ_k` computed over a quorum
that does not match the `ΣD` the package committed to, and the resulting share simply fails
to aggregate.

N-3 fixed exactly this on the *aggregation* side
(`aggregate_inner_shares_verified`, `:1623-1690`) and left the signing side open.

**Fix:** in `inner_sign_v2`, require `active_indices` to be duplicate-free and a subset of
`inner_commitments`' holder indices.

### M-15 (Medium) — one value, three jobs

`roster.rs:159-170`: `hash() = SHA-256(ROSTER_DOMAIN ‖ n ‖ Σ(index ‖ pubkey ‖ len(url) ‖ url))`
— properly length-prefixed, order-independent, unambiguous, with tests (`:245-249`). Good.

`roster.rs:175-181`: `session_id(epoch) = SHA-256(SESSION_DOMAIN ‖ hash() ‖ epoch)`. That
value is the Noise prologue via `sealed_roster()` (`:185-192`, consumed at `dkg.rs:304`,
`:487-492`, `:578-585`), and `hash()` itself is the `manifest_hash` of every signing context
(`keypackage.rs:41-42`).

So: **a re-run of a failed ceremony on the same roster at the same epoch reproduces a
byte-identical session id and prologue.** Nothing nonce-like enters. This is better than
the roster-hash-alone the task hypothesised — the epoch *is* mixed in — but a failed
ceremony is re-run at the *same* epoch, which is precisely the case the epoch does not
separate.

Replay is caught transitively today: the sealed plaintext's Feldman digest is checked
against *this* run's round-1 commitment (`dkg.rs:563-585`) and round 1 is fresh per
`Dealer::new` (`:286`). But round 1 is unauthenticated (M-7), so an attacker who observed
run A replays dealer X's round-1 *and* round-2 into run B ahead of X's real broadcasts, and
peers finalize on X's stale polynomial. DoS and view-split, not key recovery.

Note also an inconsistency: the epoch is in the DKG PoK challenge (`src/dkg.rs:71-75`) but
reaches the Noise prologue only via `session_id`. Two different bindings for the same
ceremony parameter.

**Fix:** add a per-attempt nonce — `session_id(epoch, attempt)` — advanced on every restart
of a ceremony and agreed as part of `/dkg/init`.

### M-16 (Medium) — the bridge's verification step is underspecified

`zcash-shielded-bridge.md:114-118` is the whole of the withdrawal check: each validator
checks the transaction "matches the withdrawal event emitted on Penumbra — destination,
amount, escrow change". That is three words where an implementation needs a checklist, and
the gap is where the money goes.

Each validator must receive the **full transaction bytes** — the doc never says where they
come from — and verify locally, refusing on any failure:

- per Orchard action, `alpha` and `rcv` disclosed by the builder;
- every output's note plaintext disclosed, `cmx` recomputed from it — this pins recipient,
  value and memo without needing `ovk`;
- each spend's claimed escrow note is in the validator's own `ivk`-decrypted set, with
  `cv_net` recomputed from `(v_in − v_out, rcv)` — pins the spent value without needing `nk`;
- anchor is a locally-known anchor at depth ≥ N;
- `Σv_in − Σv_out` equals the fee, within a ZIP-317 bound;
- no transparent bundle, no Sapling bundle, no actions beyond those enumerated;
- expiry height set and sane;
- the sighash recomputed from those bytes — and that sighash is the *only* thing signed.

Three further gaps in the same document. **Reorgs after a mint are unspecified**
(`:219-220` lists it as open); Zcash has no finality, so the rule must be explicit —
"reorg deeper than N after a mint halts the bridge pending governance" is an acceptable
answer and no answer is not. **Fees are not mentioned at all** (`grep -i fee` → zero hits);
the fee comes out of escrow, so wrapped supply drifts from backing on every withdrawal and
that drift must be accounted on the Penumbra side. **Prover selection is unresolved**
(`:211-212`) for a role holding `nk` + `fvk` — full viewing power over every escrow note,
and a refusal-to-serve chokepoint. `validator-custody-bridge.md` is materially better on
fees (`:377-379`) and reorg batching (`:161`) and materially worse on deposits, having no
memo scheme at all.

One thing the first doc underweights in its own favour: a stale quorum cannot spend on
its own, because an Orchard spend needs a Halo 2 proof whose witness requires `nk` and the
note witness. The prover role is therefore a genuine second factor for share retirement,
not merely a liveness dependency — worth stating, and worth noting that
`validator-custody-bridge.md` gives `nk` to every member (`:94`, `:164`) and thereby gives
that factor up.

### M-17 (Medium) — error text is a which-check-failed oracle

`err()` (`main.rs:66-68`) returns any error's `Display` verbatim to the requester, including
osst's internals via `SigningError::Osst` / `DkgError::Osst`. A caller learns exactly which
check failed: `MessageMismatch` vs `ChallengeMismatch` vs `SessionMismatch` vs
`UnexpectedCommitment`, and `"no nonces for this session"` (`signing.rs:179`). Combined with
M-2 this is a free probe of a node's epoch, manifest and nonce state.

osst deliberately made `SealedOpenFailed` uninformative (`src/error.rs:64-67`) and then
`narsild` prints it with the dealer index attached. The distinction osst *does* need to
keep is `SealedOpenFailed` vs `InvalidSubShare` — that one drives the complaint round and
must stay.

**Fix:** map errors to a small closed set of public codes; log the detail locally.

### M-18 (Medium) — unbounded state from unauthenticated input

`ThresholdAccumulator::sessions` (`accumulator.rs:54, 104`), `LocalSigner::nonces`
(`signing.rs:219`), `requests` and `results` (`signing.rs:409-411`) have no expiry.
`receive_commitment` auto-samples and stores **secret nonces** for any session id a caller
announces (`signing.rs:461-467`), so an unauthenticated party makes the node generate and
retain unbounded live nonce material. No `DefaultBodyLimit`, no rate limit, and
`reqwest::Client::new()` with no `.timeout()` (`broadcast.rs:273`) posting via detached
per-message tasks (`:336-348`).

Also in this band: `requests` is overwritten where its own doc says "as first seen"
(`signing.rs:408-409` vs the `insert` at `:478`), which poisons `try_aggregate` (`:517`) so
a session can never aggregate; `receive_round2` does not require distinct `coeff_index`
values (`dkg.rs:544-549`), so duplicates stall the ceremony; and the accumulator's
first-wins dedup (`accumulator.rs:131-133`) lets an attacker squat signing slots the same
way M-7 squats DKG slots.

**Fix:** session TTL and a cap on concurrent sessions; sample nonces only for a session this
node has accepted; `DefaultBodyLimit`; client timeouts.

### M-19 (Medium) — zcli W-2/W-3/W-4 all still open

`FrostitoCommitment.weight` (`nested.rs:104-111`) is a free `u32` argument to
`frostito_commit` (`:134`), never reconciled against the locally authentic
`ValidatorShares::weight()` = `self.shares.len()` (`:61-63`). The threshold check consumes
the self-asserted field directly (`:197-200`):

```rust
let total: u32 = commitments.iter().map(|c| c.weight).sum();
total >= threshold
```

Plain `sum()` — no `checked_add` anywhere in the file; panics in debug, wraps in release.
No `max_weight < threshold` check. No weight-0 rejection. No dedup: `grep` for
`dedup|HashSet|BTreeSet` in `nested.rs` returns nothing, so two `ValidatorShares` bundles
over overlapping share indices are undetected and a duplicate `validator_index` counts
twice toward the threshold.

The one hardening added since the audit: `frostito_precommit` (`:874`) hashes `weight`, so
a validator cannot change its lie adaptively. The lie itself is unconstrained. Note also
that `frostito_precommit` hashes neither message nor session id, so precommitments replay
across sessions, and `frostito_aggregate_responses_verified` (`:975-1000`) matches
commitments by `find` while summing every response — a validator submitting twice doubles
its contribution.

**Fix:** derive weight from `shares.len()` and drop the wire field; `checked_add`; assert
`max_weight < threshold` at roster construction; require disjoint share-index sets.

### M-20 (Low) — the commit–reveal round is caller convention

`inner_precommit` / `verify_inner_precommit` exist (`src/nested.rs:1264-1294`) and
`inner_sign_v2` never calls either. It verifies only that its *own* commitment is in the set
(`:1533-1543`). The requirement is a doc comment on `aggregate_inner_commitment_pair`
(`:1300`): "Callers MUST have verified every precommitment".

I agree with the prior audit's A-1 that this is belt-and-braces rather than load-bearing —
the outer ρ covers the full outer commitment list including the nested aggregate, so a
holder revealing last cannot hold an honest effective nonce fixed. But "not load-bearing"
and "unenforced" together mean nobody will notice when a caller skips it, and narsild's
accumulator (M-18) is exactly such a caller.

**Fix:** have `aggregate_inner_commitment_pair` take the precommitments and verify them,
rather than documenting that someone else should.

### M-21 (Low) — `from_coordinator_checked` is a footgun

It does what it says (`src/nested.rs:1463-1487`) and is correctly documented as the
legacy-wire-format escape hatch. But it *reads* like the blessed way to accept coordinator
input, and narsild's use (`signing.rs:301-308`) shows the trap: the function recomputes
against the supplied `package` and `group_pubkey`, so it validates self-consistency, not
authenticity (M-4). A caller who reads the name and stops reading is protected against
nothing.

**Fix:** `#[deprecated(note = "prefer from_outer; this validates self-consistency, not the
provenance of package or group_pubkey")]`.

### M-22 (Low) — `compress()` fails silently

`src/curve.rs:583-594`: if `to_encoded_point(true)` returns anything other than 33 bytes,
`out` stays all-zeros — which `decompress` maps back to the identity. Today the only such
case is the identity itself, so the behaviour is correct; but a future k256 change or an
unexpected point turns a bug into a silently wrong hash input rather than a panic, in the
function whose lossiness was the prior audit's C-1.

**Fix:** match on the length explicitly and handle the identity as a named case.

### M-23 (Low) — negative-test coverage

The regression suite is real and the 0.4.0 work behind it is good:
`coordinator_cannot_swap_the_message_under_the_inner_group`,
`substituted_nested_commitment_is_rejected_by_the_holder`,
`nonces_from_another_session_are_rejected`, `sign_rejects_a_foreign_commitment_for_its_own_index`,
`compress_is_injective_in_the_sign`, `negating_a_commitment_moves_the_binding_factor`,
`liveness_signature_does_not_transfer_to_a_related_key`,
`osst_and_liveness_challenges_are_domain_separated`, `incomplete_quorum_is_rejected`,
`non_canonical_encodings_are_rejected`, `wire_parsed_indices_error_rather_than_aborting_the_process`.
Each maps to a finding. That is the right shape.

Missing, one per rejection path that has no test: `ChallengeMismatch` from
`from_coordinator_checked`; the *duplicate* branch of N-3 (only the missing branch is
covered); `InvalidProofOfKnowledge` from a forged `Round1Package`; the four sealed
rejection paths — wrong prologue, wrong sender, wrong recipient, digest mismatch;
`DkgAborted` on over-disqualification; `SessionMismatch` in `aggregate_inner_commitment_pair`
(as distinct from in `inner_sign_v2`).

On constant-time comparisons, since it was asked: nothing secret is compared with `!=`
anywhere in the crate. The comparisons in `inner_sign_v2` and `verify_nested_commitment` are
over public points; `verify_inner_precommit` (`:1282-1294`) already uses an accumulating
XOR over public data; the only secret-dependent comparison in the system is the Poly1305
tag inside `snow`. No finding.

### M-24 (Info) — A-2 remains open

`compute_binding_factor` (`src/frost.rs:385-391`) hashes domain, index, length-prefixed
message and the encoded commitment list — no group public key. RFC 9591 §4.4 includes it.
Unchanged since the prior audit; still Info, still worth closing whenever the wire format
next breaks.

---

## Answers to the questions asked

### A. Nested v2 soundness

**The equations, as the code implements them.** For nested position `p` with inner holders
`k ∈ Q`, message `m`, full outer commitment list `B` (sorted by index,
`index:4 ‖ D ‖ E` per entry, `src/frost.rs:370-373`):

```
inner commitments   D_k = g^{d_k},  E_k = g^{e_k}            nested.rs:1276-1281
nested entry        (D_p, E_p) = (Σ_k D_k, Σ_k E_k)          nested.rs:1309-1333
outer binding       ρ_p = H("frost-binding-v1" ‖ p ‖ len(m) ‖ m ‖ B)   frost.rs:385-391
group commitment    R = Σ_i (D_i + ρ_i·E_i)                  frost.rs:252-262
challenge           c = H("frost-challenge-v1" ‖ R ‖ Y ‖ m)  frost.rs:405-410
inner share         z_k = d_k + ρ_p·e_k + (λ_p · c · μ_k)·σ_k   nested.rs:1562-1564
verification        z_k·G == (D_k + ρ_p·E_k) + (λ_p·c·μ_k)·P_k  nested.rs:1596-1621
aggregation         z_p = Σ_{k∈Q} z_k, all shares verified first  nested.rs:1623-1690
```

Summing: `z_p = Σd_k + ρ_p·Σe_k + λ_p·c·Σ(μ_k σ_k) = d_p + ρ_p·e_p + λ_p·c·s_p` — bit-for-bit a
flat signer's response, which is what `v2_response_equals_the_flat_frost_response` asserts.

**Is every honest signer's effective nonce a function of (message, full outer commitment
list, full inner commitment list, session id)?** Of the first two, yes: the effective nonce
`d_k + ρ_p·e_k` depends on ρ_p, which hashes `m` and all of `B` including the nested entry,
which in turn is the sum over all inner commitments. Of the third, only through that sum —
ρ_p sees `ΣD_k`, not the individual `D_k`. Of the fourth, **no**: the session id enters no
hash (M-13).

That last point is the honest statement of the open cryptographic question. The inner group
shares a single ρ across all holders (`:1554`), which is structurally FROST2 rather than
FROST1 — and FROST2 is proven (Bellare–Crites–Komlo–Maller–Tessaro–Zhu). The delta is that
here ρ hashes the *sum* `(ΣD, ΣE)`, which a `t_in − 1` adversary inside the jury can steer
to a value of its choosing after seeing the honest `D_k`, whereas FROST2's ρ hashes the
list. That is the exact step a reduction would have to discharge. The module doc calls a
reduction "plausible … it has not been done" (`:41-46`), which is right; this review's only
amendment is to name the gap precisely rather than leave it as a general caveat.

**Can a coordinator obtain a share over a message the signer did not approve?** No — that
is N-1, and it is fixed. `inner_sign_v2` rejects on `request.package.message() != approved_message`
(`:1517-1519`). Every input to `inner_sign_v2`, marked:

| Input | Status |
|---|---|
| `approved_message` | **caller-held** — the whole point |
| `package.message()` | trusted, but *checked* against the above |
| `ρ_p`, `c`, `λ_p` | **recomputed locally** from the package (`:1546-1550`) |
| `μ_k` | **recomputed locally** from `active_indices` (`:1552`) |
| `nonces` | **locally generated**, consumed by value |
| own `(D_k, E_k)` in the set | **checked** against the nonces (`:1535-1541`) |
| `(D_p, E_p)` in the package | **checked** = `(ΣD_k, ΣE_k)` (`:1544`) |
| `session_id` | **checked** equal to the nonces' (`:1524`) |
| **`group_pubkey`** | **trusted from coordinator** → M-4 |
| **`active_indices`** | **trusted from coordinator**, unvalidated → M-14 |
| **`inner_commitments`** (others' entries) | **trusted from coordinator**; constrained only by the aggregate check → M-20 |
| **`nested_index`** | **trusted**; pinned by the aggregate check, but a package with the same pair at two indices passes `SigningPackage::new`, whose duplicate check is on index, not on points |

So the answer to the question as posed is no for the message, and yes for the challenge:
a coordinator supplying `Y'` gets a share over the approved message under a challenge of
its choosing (M-4).

**Concurrency / ROS across `k` parallel sessions.** Nothing durable stops it. The session
id is not in ρ or c, so it is not a cryptographic separator; it is an equality gate that
prevents *mixing* two live rounds. What actually prevents reuse is by-value consumption
plus the own-commitment check — sound within one process, worth nothing across a restart.
Who enforces uniqueness: nobody. narsild generates session ids as
`SHA-256(roster ‖ epoch)` for DKG (M-15) and accepts arbitrary caller-supplied ids for
signing (`signing.rs:461-467`). The realistic exploit is not a clever concurrent
adversary; it is a VM snapshot restore.

**Is the inner aggregated nonce hiding?** Yes. The outer protocol sees `(ΣD_k, ΣE_k)` and
`z_p`. Each is a sum over the quorum of values that are uniformly random given one honest
holder, so the outer coordinator learns neither `|Q|` nor which holders participated —
nothing beyond OSST's stated non-accountability. No finding.

### B. Sealed DKG

**Noise_K's actual properties**, from the spec's own table rather than the module doc:
one-way pattern `K` gives **sender authentication 1** and **payload security 2**. In
`sealed.rs`'s "What it binds" section (`:44-62`) none of the three limits below is stated,
and they all matter here.

**Forward secrecy: absent. Say it plainly.** `K` is `e, es, ss`. An attacker holding
recipient `j`'s X25519 static can compute `es` from the wire ephemeral and `ss` from the
sender's public static — both DHs — so **compromise of one recipient's static key decrypts
every sub-share ever sent to that recipient, in every epoch, from recorded traffic.** The
X25519 key is HKDF'd from the identity seed (`sealed.rs:113-119`), so seed compromise
dominates and the marginal loss is small today; that changes the moment a deployment stores
the derived key separately. Recommend putting the epoch into `X25519_DERIVE_INFO` so the
window is one epoch, or moving to `KK`/`XK` and paying for the round trip.

**KCI: yes, and it has a concrete consequence.** The same fact — the recipient's static
computes both DHs — means an attacker who compromises `j` can forge a sealed package to `j`
from *any* dealer. The D-2 digest binding limits the damage: the forgery must carry a
sub-share that passes Feldman against the named dealer's real commitment, which the
attacker cannot produce. So the yield is not a bad share but a **framing primitive** —
deliver garbage "from" an honest dealer, `j` raises a complaint, and with narsild's
believe-everyone policy (M-6) that dealer is out. KCI plus an unadjudicated complaint round
is a worse combination than either alone.

**Replay across sessions.** The prologue is
`PROLOGUE_DOMAIN ‖ transcript ‖ session_id ‖ round` (`sealed.rs:199-206`), all fixed-width,
unambiguous. The task's hypothesis — roster hash alone as session id, static across re-runs
— is not quite what narsild does: it mixes the epoch (`roster.rs:175-181`). But a *failed*
ceremony is re-run at the same epoch, so the prologue does repeat exactly there (M-15).
Impact is framing and view-divergence, not disclosure, because the Feldman digest is
checked against the current run's commitment.

**Reflection / dealer == recipient.** Self-sealing is deliberate (`seal_round2` seals to
every roster member including the dealer, `:389-393`) and safe: Noise_K with
`local_private = s`, `remote_public = pk(s)` is well-defined, and the indices inside the
plaintext are checked against the envelope on open (`:355-364`). A package `A→B` cannot be
reflected as `B→A` — it will not open. The one gap is narsild-side and minor: `receive_round2`
validates `recipient_index == holder_index` but not that `dealer_index != holder_index`
(`dkg.rs:530-535`), so a peer can make a node broadcast a complaint against itself (L-1).

**Does the Feldman digest stop the D-2 swap when the attacker is the dealer?** **No** — and
this is M-5, the most important thing in section B. The digest binds the sub-share to the
commitment *on that wire*, which defeats a MITM sourcing the two separately. A dealer
choosing both is unconstrained: different `(C, share)` pairs to different recipients, each
internally consistent, each passing every check osst performs. Only an echo round fixes it.

**What a compromised X25519 identity yields:** every past sub-share sent to that node
(no forward secrecy, above), the ability to forge packages to that node from anyone (KCI,
above), and — since the same seed derives the node's signing identity — whatever else that
seed protects. Not the group key by itself; one share plus `t−1` others.

### C. Roster and identity

**Is one value doing three jobs?** Yes — session id, `manifest_hash` and Noise prologue all
derive from `Roster::hash()` (M-15). The hash itself is well constructed: length-prefixed,
order-independent, tested (`roster.rs:159-170, 245-249`). The problem is not the hash, it is
the absence of a per-attempt nonce, which makes a re-run of a failed ceremony on the same
roster at the same epoch byte-identical to the original.

**Is the roster signed?** **No — only hashed**, despite `README.md:78` saying "The signed
roster", `README.md:158`, the header comment at `roster.rs:1`, and a commit titled
"… signed roster". It is CLI configuration: `--peer INDEX=URL=PUBKEY` (`main.rs:563-567`),
parsed at `roster.rs:102-130`, with no gossip and no on-chain anchor.

What an operator-level attacker gets: editing **one** node's config only isolates that node
— a different session id means packages do not open, which is the intended failure and is
fine. Editing the deployment config for **all** nodes substitutes the membership wholesale,
and there is no external anchor against which any node could detect it. For a validator
custody bridge the roster should be derived from chain state, not from a flag —
`validator-custody-bridge.md:117-119` says exactly this ("the set is derived from chain
state, not proposed") and narsild does not implement it. Credit where due: duplicate indices
and duplicate public keys are both refused (`roster.rs:86-97`), which closes the
two-members-one-key case cleanly.

**Identity.** X25519 static, KDF'd from a 32-byte seed at `<data-dir>/identity.key`, mode
0600, and the loader *refuses* a loosened mode rather than silently fixing it
(`identity.rs:37-64, 76-101`). Pinned per-peer in the roster, no TOFU anywhere, and startup
verifies the node's own roster entry matches its own identity (`main.rs:624-641`). This part
is well done. Its limit is scope: the identity authenticates round-2 sealing and nothing
else (M-7, M-6, M-2).

**Epoch: persistence and rollback.** In `key_package.json` only, plain JSON, no MAC
(`keypackage.rs:39, 118-124`). The "must advance" guard compares against the in-memory value
loaded from that file (`main.rs:266-268, 653-676`). **Delete the file and the epoch is 0
again** — full rollback, no residue, and `/dkg/activate` re-reads disk unauthenticated
(M-10). There is no separate high-water mark. Note also `main.rs:281`'s `epoch + 1`: after an
attacker sets the epoch near `u64::MAX` via M-3, this panics in debug and wraps in release.

### D. The Orchard epoch problem

**The analysis in the design doc is correct.** Orchard spend authorization signs the ZIP-244
signature digest with `rsk = ask + α`, verified against `rk = ak + [α]·G`, where `α` is a
public per-action randomizer chosen by the transaction builder. The signature digest commits
to the transaction; it has no field for protocol metadata of our choosing. So
`SigningContext`'s epoch binding — which is sound, and correctly scoped in its own module doc
(`src/context.rs:29-42`) — cannot reach a `SpendAuthSig`. A key-preserving reshare leaves
every past quorum able to produce a valid spend authorization. Confirmed.

Taking the five mitigations in turn:

**(1) Group-chosen α per epoch — void.** `rsk = ask + α` is *linear* in `α`, and `α` is
public and per-action. A holder of any share of `ask` signs under any `α` whatsoever; there
is no derivation in which an old share "fails" for a new randomizer. Rerandomization is an
unlinkability mechanism, not an authorization mechanism. Discard this one completely.

**(2) Proactive resharing — does not invalidate anything by itself.** Correct as stated in
the task. A reshare re-randomizes the polynomial while preserving `f(0)`; a departed member
holding an epoch-`e` share still holds a valid share of the same secret. Shares from
different epochs do not interpolate with each other, so the requirement is per-epoch, and
the honest way to write the invariant is:

> for every past epoch `e`, the number of departed-or-compromised holders of epoch-`e`
> shares must remain below `t`.

Cumulative churn violates this eventually and unconditionally. `validator-custody-bridge.md`
gets this right (`:111-116`, `:385-387`) and derives the correct trigger — rotate when
departures reach `n − t + 1` (`:389-394`). `zcash-shielded-bridge.md:99-102` gets it wrong
in one sentence (M-11).

**(3) Governance: move the escrow at rotation — the only cryptographic answer.** Accepting
an address change is the sole mechanism that actually retires shares, because it retires the
*key*. Everything else is policy.

**(4) Many small notes, rotated gradually — the right operational shape.** It converts a
single flag-day sweep into a continuous process, bounds the exposure of any one rotation to
the notes not yet moved, and fits how a bridge already spends. It does not change the
security argument; it makes (3) affordable.

**(5) Large `t` — necessary, not sufficient.** It raises the collusion bar for every past
epoch simultaneously, which is worth real money. It does not bound the number of past
epochs.

**One factor both docs underweight, in the design's favour:** a stale quorum holding old
`ask` shares still cannot spend, because an Orchard spend needs a Halo 2 proof whose witness
requires `nk` and the note witness. `zcash-shielded-bridge.md`'s prover role
(`:104-121`) is therefore load-bearing for *share retirement*, not merely for liveness — a
point the doc does not make and should. It follows that `validator-custody-bridge.md`'s
choice to give `nk` to every member (`:94`, `:164`) discards a second factor it does not
appear to know it had.

**Recommendation.** Combine (3), (4) and (5), and drop (1) entirely.

- Treat the escrow address as **rotating on a schedule**, not fixed. Publish the current
  address on-chain and make deposit-address lookup a protocol operation, so the fixed-address
  requirement dissolves into a UX problem — which is where it belongs, and which
  `validator-custody-bridge.md:423-426`'s grace-period sweep already solves.
- Hold escrow in many small notes and migrate them continuously to the current group key, so
  a rotation is never a flag day.
- Pick `t` large enough that no plausible past-epoch coalition reaches it, and rotate on the
  `n − t + 1` departure trigger.
- Couple `unbonding_delay` to the rotation period so anyone who held a share is still
  slashable when it could be used (`validator-custody-bridge.md:395-400`). This is the best
  idea in either document and belongs in whichever design survives.
- Keep `nk` custody separate from `ask` custody, and rotate the prover.
- Delete the three false sentences (M-11), and stop describing local share deletion as a
  mechanism.

**Verdict on whether this is fatal: no, but it is fatal to the fixed-address premise.**
The cryptography is fine; what fails is the claim that a key-preserving reshare retires
anything. With a fixed address there is **zero** cryptographic retirement, and the escrow's
safety rests entirely on deletion discipline, the per-epoch churn invariant, and `nk`
custody — three operational properties, none verifiable by the chain. That is an acceptable
posture for a bridge that admits it, and an unacceptable one for a bridge that tells its
users old shares become useless. Accept address rotation and the problem is solved by
construction rather than managed forever.

**Does the same problem apply on the Penumbra side?** No — and this is the asymmetry worth
exploiting. Penumbra actions are ours to define, so a burn/mint action can carry the epoch
and the manifest hash as consensus-checked fields, and `pd` can reject an authorization
from a superseded epoch outright. The Penumbra leg should do this explicitly rather than
relying on `SigningContext` as a convention, and the design docs should say so: the Zcash
leg is the only one with the problem, which is a much narrower statement than either
document currently makes.

### E. Bridge design gaps

Covered in M-16 (withdrawal checklist, reorg rule, fees, prover selection, dust) and M-11
(the contradiction between the two documents). The short version: the consensus rule for
"a deposit exists" is specified in shape — a Zcash header chain verified in `pd`, PoW
finality, a confirmation depth (`zcash-shielded-bridge.md:31-35`) — and unspecified in
every number and every edge case that determines whether it is safe. No depth value, no
reorg-after-mint rule, no fee accounting, no prover selection, no dust policy, and a
withdrawal verification step three words long. The design is a good sketch and says so
honestly (`:3-4`). It is not close to implementable.

### F. What the prior audit missed

M-5 (the D-2 fix does not bind the broadcast, so a malicious dealer equivocates) is the
significant miss; M-12 (the contribution-signature message is not injective) and M-25
(`SubShare::to_bytes` still public) are real but minor. M-13's
precise framing — the session id enters no hash and is therefore a mixing guard, not a
replay guard — is a sharpening rather than a miss; the prior audit's A-3 saw the issue and
under-stated it. M-14, M-20, M-21, M-22 and M-23 are smaller items in the same area.

On the specific sub-questions: constant-time comparison — no finding, nothing secret is
compared with `!=` (see M-23). Error-path oracles — no finding in osst, real finding in
narsild (M-17). Serialization ambiguity — `codec.rs` is clean (it is hex helpers over osst's
canonical encoders, with non-canonical encodings rejected rather than coerced,
`codec.rs:19-39, 55-59`, and every wire struct is `#[serde(deny_unknown_fields)]`); the
ambiguity is in osst's `liveness.rs` instead (M-12), where it is an encoding defect rather
than an exploitable one. Hash domain separation — the
prologue/manifest/context/binding-factor tags are all distinct and all the encodings are
either length-prefixed or fixed-width, with the single exception in M-12; no collision
between them. `from_coordinator_checked` — a footgun, M-21.

---

## What I would block merge on

### (i) osst 0.5.0

Blocking:

1. **M-12 + M-25** — length-prefix `liveness::signing_message`, and deprecate
   `SubShare::to_bytes`. Neither is live exposure, but both are signature- or API-breaking,
   so they have to ride a version that already breaks; carrying a non-injective signature
   input past 0.5.0 means carrying it a long time.
2. **M-5** — ship the echo-round digest helper and make `aggregate_inner_commitment_pair`
   verify precommitments (M-20). osst cannot provide the broadcast, but it must stop
   documenting the caller's obligation and start encoding it.
3. **M-14** — validate `active_indices` in `inner_sign_v2`.
4. **M-4 (doc half)** — rewrite the `NestedSigningRequest` comment to name `group_pubkey`,
   `active_indices` and `nested_index` as caller-anchored, and `#[deprecate]`
   `from_coordinator_checked` (M-21).
5. **M-6 (osst half)** — either give `DkgState` a justified-complaint API, or change
   `disqualify`'s doc from "every participant must apply the same complaints" to an explicit
   statement that osst provides no agreement mechanism and a caller without reliable
   broadcast must not use it.
6. **M-23** — negative tests for the seven uncovered rejection paths. The suite's current
   shape is right; complete it.

Not blocking but wanted: M-22, M-24, and a `legacy-v1` removal plan.

### (ii) narsild PR #31 leaving draft

Blocking, and I would not approve this leaving draft with fewer than all of these:

1. **M-1** — `#[serde(skip)]` on `coefficient_shares`. This is one line and it is a Critical
   key disclosure; nothing else should be discussed until it lands.
2. **M-2** — authentication on every endpoint, a real approval predicate sourced from `pd`,
   and a loopback default bind.
3. **M-3** — no unauthenticated DKG initiation; key-package writes go through
   write-new-then-rename with retained history.
4. **M-4** — take `Y` from the local key package.
5. **M-13** — a durable, `fsync`'d spent-session store consulted before any share is
   released. Without it a VM snapshot is a share disclosure, and snapshots are routine.
6. **M-5 / M-7** — an echo round over the round-1 set, and authenticated round-1 broadcasts.
7. **M-6** — signed, ceremony-bound, re-broadcast, justified complaints.
8. **M-10** — an independent epoch high-water mark; `manifest_hash()` returns `Result`;
   save failure is fatal.
9. **README corrections** — `:216` ("cannot make a node sign anything the node has not
   independently derived") and `:78` ("The signed roster") are both false as written. The
   "what is still missing" list understates the consequences: it says outsiders can start
   sessions and post public contributions, when in fact they can read secret shares, destroy
   key material irreversibly, and obtain signatures over arbitrary bytes.

Deferrable to a follow-up: M-17, M-18, and the L-band items.

The engineering underneath is sound — `from_coordinator_checked`, `inner_sign_v2_with_context`,
`aggregate_inner_shares_verified`, one-shot nonce removal, `deny_unknown_fields`, the
identity file-mode discipline, the roster hash construction. The gap is that the crate was
built as a protocol implementation and deployed as a network service, and the network
service half is missing. That is a bounded amount of work, not a redesign.

### (iii) the bridge design proceeding to pd implementation

Blocking:

1. **M-11** — pick one design. Two live documents with opposite answers to the central
   question is not a state anyone should write consensus code against. Delete or correct
   `zcash-shielded-bridge.md:99-102` and `:198-200` today, independently of which document
   wins.
2. **Section D's recommendation adopted or explicitly rejected in writing.** If the fixed
   address stays, the document must state that no cryptographic share retirement exists and
   name the operational controls it is relying on instead. If it goes, the rotation trigger
   and the `unbonding_delay` coupling need to be in the spec.
3. **M-16** — the withdrawal verification checklist written out item by item, with a stated
   source for the transaction bytes; a reorg-after-mint rule with a number in it; Zcash fee
   accounting against wrapped supply; a prover selection mechanism; a dust/bad-memo policy.
4. **A deposit-finality rule with an actual depth**, and an explicit halt-and-governance
   clause for a reorg deeper than that depth after a mint. Zcash has no finality; the design
   must say what happens when PoW disagrees with a mint that already happened.
5. **The Penumbra leg's epoch binding specified as a consensus-checked action field**, not
   as a `SigningContext` convention (section D).

Not blocking for a design document, but required before mainnet: a threshold-proving story,
or an explicit acceptance that the prover is a trusted viewing party with a named selection
rule and a rotation schedule.

---

## Verdict

The 0.4.0 security release did what it set out to do. The nested v2 construction is sound
as far as honest-transcript equivalence goes, N-1 and N-2 are genuinely closed, and the
`sealed` module is a real fix for a real Critical. Two things the prior audit missed are
worth fixing before 0.5.0, and one of them — the dealer-equivocation gap behind the D-2
fix — needs a protocol round, not a patch.

The risk has moved rather than disappeared. It now sits in `narsild`, where a cryptographic
core with good properties is exposed through an HTTP surface with none, and in `zcli`,
which never adopted the fixes. `narsild` is a draft PR and that is the right status for it;
it should stay draft until the list in (ii) is done.

On the epoch question: not fatal, but fatal to the fixed-address premise. Accept that the
escrow address rotates, and the problem stops being permanent.
