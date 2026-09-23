# frostito

threshold Schnorr: distributed key generation, FROST signing, nested FROST,
and proactive resharing.

the signing math is being rooted in ZF [`frost-core`](https://github.com/ZcashFoundation/frost);
what stays here is the part it does not cover — confidential authenticated DKG
round 2, dealer-equivocation detection, complaints, committee rotation, and
nested FROST.

## using it

repository and cargo package are both `frostito`.

```toml
[dependencies]
frostito = { git = "https://github.com/penumbrafi/frostito", features = ["sealed"] }
```

there are no release tags. pin a `rev`.

### features

default build is `std` + `ristretto255`. everything else is off by default.

| feature | what it is |
|---|---|
| `sealed` | DKG round 2 over Noise_K: sub-shares encrypted and authenticated per recipient (`osst::sealed`). needs `std` |
| `zf` | ZF `frost-core` 3.0 as the signing core, with `internals`. `zf-ristretto255` / `zf-secp256k1` add ZF's ciphersuite for that backend; `zf-decaf377` enables `osst::zf`, which supplies the decaf377 ciphersuite ZF does not ship |

`no_std` on every backend.

### curves

| feature | curve | compatible with |
|---------|-------|---------------|
| `ristretto255` | curve25519 | polkadot, sr25519 |
| `pallas` | pallas (curve generator) | generic pallas |
| `pallas` | pallas in the orchard spend-auth group (`OrchardSpendAuthCurve`) | zcash orchard, ZF `reddsa` / `frost-core` FROST(Pallas) |
| `secp256k1` | secp256k1 | bitcoin, ethereum |
| `decaf377` | decaf377 | penumbra |

everything is generic over `P: OsstPoint`. the snippets below fix a concrete
point type.

## distributed key generation

round 1: Feldman commitment plus a proof of knowledge of the constant term.
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
for j in 1..=n {
    let packet = sealed::seal_subshare::<Point>(
        &my_x25519_secret, &roster, 2,
        &dealer.generate_subshare(j)?, dealer.commitment(),
    )?;
    send_to(j, packet);
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

let my_share = agg.finalize()?;            // s_me
let group_pubkey = agg.derive_group_key()?;  // Y
```

`open_subshare_agreed` discards the plaintext of a sub-share that fails the
Feldman check. `open_subshare_agreed_with_evidence` returns it, which is what
`dkg::Complaint` needs to be checkable by a third party. `dkg::ComplaintTally`
gates disqualification on `t` distinct accusers.

## nested FROST

`frostito::nested` splits one outer FROST position among an inner group. the
outer share is never materialized as a scalar by any party. inner signers hold
the message and the full commitment set, so a coordinator cannot obtain a
share for a payload the signer has not seen.

worked flow: [`examples/narsil_nested.rs`](examples/narsil_nested.rs)
(interleaved DKG, escrow authorization, outer aggregation).
[`docs/nested-frost-v1-vs-v2.svg`](docs/nested-frost-v1-vs-v2.svg) shows what
the insecure v1 did differently; v1 itself is gone.

## resharing

rotates the custodian set. the group public key is unchanged.

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

## modules

- `osst::dkg` — distributed key generation over an agreed dealer set;
  complaints and disqualification
- `osst::sealed` — encrypted, authenticated DKG round 2 (feature `sealed`)
- `osst::frost` — plain FROST signing
- `osst::nested` — nested FROST
- `osst::reshare` — proactive secret sharing
- `osst::liveness` — checkpoint proofs for holder participation
- `osst::context` — epoch-bound signing contexts
- `osst::zf` — `Decaf377Sha512`, a `frost_core::Ciphersuite` for decaf377 (feature `zf-decaf377`)
- `osst::curve` — curve backend traits

[`docs/frostito-design.svg`](docs/frostito-design.svg) is the architecture diagram.

## canonical repo

canonical source: https://github.com/penumbrafi/frostito.
`github.com/rotkonetworks/frostito` mirrors `main` so existing pins
(`rev = "14e38da"`) keep resolving.

the vendored copies in `zcli` (`crates/osst`) and `zk.poker`
(`crates/frostito`) are being replaced by a git dependency on this repo.

## license

MIT OR Apache-2.0
