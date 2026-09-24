# frostito

threshold Schnorr for collective custody: distributed key generation, nested
FROST, and proactive resharing, on top of ZF
[`frost-core`](https://github.com/ZcashFoundation/frost).

the signing math is `frost-core`'s. what lives here is the part it does not
cover:

- confidential, authenticated DKG round 2, with dealer-equivocation detection
  and checkable complaints
- **nested FROST** — one outer FROST position held by an inner threshold
  group, so a chain or a sub-committee can be a party inside somebody else's
  quorum
- **key-preserving reshare** — rotate the custodian set without changing the
  group public key, so a deposit address survives validator churn

## using it

```toml
[dependencies]
frostito = { version = "0.8.0", features = ["zf-secp256k1-tr", "sealed"] }
```

pin `0.8.0`. it renames the nested signing API, with no deprecation path from
0.7.x.

### features

default build is `std` + `ristretto255`. everything else is off.

| feature | what it is |
|---|---|
| `sealed` | DKG round 2 over Noise_K: sub-shares encrypted and authenticated per recipient. needs `std` |
| `zf-secp256k1-tr` | BIP340/Taproot. this is the one bitcoin verifies |
| `zf-secp256k1` | RFC 9591's registered secp256k1 suite. **not** bitcoin-compatible |
| `zf-ristretto255` | RFC 9591 ristretto255 |
| `ristretto255` `secp256k1` `pallas` `decaf377` | curve backends for the DKG, reshare and nested code |

`no_std` on every backend, `sealed` aside.

### what this signs, and what it does not

| chain | works | via |
|---|---|---|
| bitcoin taproot (P2TR) | yes | `zf-secp256k1-tr`. not yet checked against libsecp256k1 |
| zcash shielded (orchard) | yes | `reddsa` redpallas; reshare into ZF key packages is tested |
| zcash transparent | no | ECDSA. FROST is schnorr-only |
| bitcoin pre-taproot | no | ECDSA, same reason |
| penumbra (UM) | not yet | penumbra already ships `decaf377-frost` (ciphersuite `Decaf377Rdsa`, BLAKE2b personalised, re-randomizable). it is on `frost-core` 0.7 and this crate is on 3.0; that version split is the only thing in the way. `zf::Decaf377Sha512` is **not** it — same curve and basepoint, different hash and context string, so nothing it signs verifies under penumbra |

## curves

everything below `zf` is generic over `P: CurvePoint`; the snippets fix a
concrete point type.

| feature | curve | compatible with |
|---|---|---|
| `ristretto255` | curve25519 | polkadot, sr25519 |
| `secp256k1` | secp256k1 | bitcoin, ethereum |
| `pallas` | pallas, curve generator | generic pallas |
| `pallas` | pallas, orchard spend-auth group (`curve::pallas::SpendAuthPoint`) | zcash orchard, ZF `reddsa` |
| `decaf377` | decaf377 | see the penumbra row above — not penumbra spend-auth |

## distributed key generation

round 1: feldman commitment plus a proof of knowledge of the constant term.
echo round: participants compare digests of the round-1 set, so a dealer
cannot hand two of them different commitments. round 2: one sealed sub-share
per recipient.

```rust
use curve25519_dalek::ristretto::RistrettoPoint as Point;
use frostito::{dkg, sealed};

let (epoch, t, n) = (7u64, 2u32, 3u32);

// round 1 — every participant deals
let dealer: dkg::Dealer<Point> = dkg::Dealer::new(me, t, &mut rng)?;
let my_package = dealer.round1_package(epoch, &mut rng);

let mut state: dkg::DkgState<Point> = dkg::DkgState::new(epoch, t, n);
for package in round1_packages {
    state.submit_commitment(package)?;   // verifies the proof of knowledge
}

// echo round — you broadcast `agreed.digest()`, and every peer must match.
// a mismatch is a dealer equivocating or a broadcast that is not reliable;
// either way the ceremony aborts.
let agreed = state.agreed_round1()?;
agreed.confirm_all(&peer_digests, n as usize)?;

// round 2 — sealed per recipient, bound to sender, recipient and ceremony
let roster = sealed::SealedRoster::new(&x25519_pubkeys, session_id)?;
for (j, packet) in sealed::seal_round2::<Point>(&dealer, &my_x25519_secret, &roster, 2)?
    .into_iter()
    .enumerate()
{
    send_to(j as u32 + 1, packet);
}

// aggregate over exactly the agreed dealer set
let mut agg = dkg::Aggregator::<Point>::from_agreed(me, &agreed)?;
for packet in inbox {
    let sub = sealed::open_subshare_agreed::<Point>(
        &my_x25519_secret, me, &roster, 2, &packet, &agreed,
    )?;
    let commitment = agreed.commitment(sub.dealer_index)?.clone();
    agg.add_subshare(sub, &commitment)?;
}

let my_share = agg.finalize()?;              // s_me
let group_pubkey = agg.derive_group_key()?;  // Y
```

`open_subshare_agreed` discards the plaintext of a sub-share that fails the
feldman check. `open_subshare_agreed_with_evidence` returns it, which is what
`dkg::Complaint` needs to be checkable by a third party. `dkg::ComplaintTally`
gates disqualification on `t` distinct accusers.

## nested FROST

`frostito::nested` splits one outer FROST position among an inner group. the
outer share is never materialized as a scalar by any party, and inner signers
hold the message and the full outer commitment set, so a coordinator cannot
obtain a share for a payload the signer has not seen.

the nested position is presented to the outer protocol as an ordinary signer —
`D = Σ D_k`, `E = Σ E_k` — so it receives a real outer binding factor, and each
holder answers with

```text
z_k = d_k + ρ·e_k + (λ·c·μ_k)·σ_k
```

`zf::inner_params_from_zf` recovers `ρ`, `c` and `λ` from a `frost-core`
`SigningPackage`, which is what makes an inner holder's response bit-for-bit
equal to the share `frost_core::round2::sign` would have produced for that
position. that equivalence is asserted against `frost-core` itself in
`tests/zf_nested_equivalence.rs`, and under taproot in `tests/zf_taproot.rs`.

what that establishes is honest-transcript equality, not a reduction. the
inner group is one trust unit: `t_in` corrupt holders are a corrupt outer
signer, with no further guarantee.

under taproot the parity normalisation is not yet applied by `inner_sign` —
the recipe is verified in the tests, but a caller has to follow it by hand
until it moves into the holder.

## signing

spent-nonce durability is a separate concern from producing a share, and
there was no function that did both. so it is a layer, in `tower`'s shape.

```rust
use frostito::signer::{Holder, SignRequest, Signer, Spend, Stack};

// built once and held: the store lives in the layer
let mut signer = Stack::new(Holder::new(&share, &verifying_key))
    .layer(Spend::new(log))   // durable, before anything else runs
    .into_inner();

// epoch and manifest bound into the bytes, per round
let z = signer.sign(SignRequest::bound(nonces, &ctx, &req))?;
```

outermost runs first: `Spend` wraps `Holder`, so the session is recorded
before any signing work begins.

a layer holds material that outlives the round; what varies per round goes in
the request. so the message is not a layer — it is fixed at construction,
`raw` for bytes somebody else chose (a sighash) and `bound` for bytes this
protocol chose, with no public field for anything downstream to substitute.

## resharing

rotates the custodian set. the group public key is unchanged, which is the
point: a deposit address outlives the validator set holding it.

```rust
use frostito::reshare::{Dealer, Aggregator};

// old custodians become dealers
let dealer = Dealer::new(index, current_share, new_threshold, &mut rng)?;
let commitment = dealer.commitment().clone();
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

because the reshare is key-preserving, rotation alone does not retire old
shares — a stale quorum can still sign. `frostito::context` binds the epoch
and a manifest hash into the signed bytes to close that, and its own docs say
where it does not apply (protocol-defined signatures, where the message is a
sighash somebody else chose).

## what the caller owes

none of this is supplied by the crate, and all of it is load-bearing:

- **reliable broadcast** for round 1 and the echo round. the echo round detects
  equivocation; it does not repair it
- **agreement on the dealer set** before any aggregation, in DKG and reshare
  alike
- **durable spent-session state**. a holder that restores a snapshot and signs
  again with the same nonces gives up its share. `SpentSessions` is the seam;
  `MemorySpentSessions` is in-memory — a restart forgets everything

## modules

- `frostito::dkg` — distributed key generation over an agreed dealer set,
  complaints, disqualification
- `frostito::sealed` — encrypted, authenticated DKG round 2 (feature `sealed`)
- `frostito::nested` — nested FROST
- `frostito::signer` — composable signing: `Holder`, `Bind`, `Spend`, `Stack`
- `frostito::reshare` — proactive secret sharing
- `frostito::context` — epoch-bound signing contexts
- `frostito::zf` — the bridge that drives `nested` from a `frost_core` signing
  package, plus `Decaf377Sha512`
- `frostito::curve` — curve backend traits

[`docs/frostito-design.svg`](docs/frostito-design.svg) is the architecture
diagram. [`SECURITY.md`](SECURITY.md) is the reporting address and the scope.

canonical source: https://github.com/penumbrafi/frostito

## license

MIT OR Apache-2.0
