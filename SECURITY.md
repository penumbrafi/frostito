# security

this is threshold signing code that has not been audited by anyone outside
the people who wrote it. do not put money behind it yet.

what follows is what we know to be true, stated plainly, so you can decide
for yourself. it is not a threat model and it is not a promise.

## the signatures are not rfc 9591

`frostito::frost` implements frost correctly — the challenge is
`H(R || Y || msg)`, exactly as §4.6 says — but under our own context strings
rather than the registered ones. so it is a ciphersuite nobody else has, and
nothing outside this crate will verify what it produces.

we are moving the signing path onto zcash foundation's `frost-core`, which is
audited and is the standard. when that lands, every signature this crate
produces changes. keys survive; signatures do not.

if you need interoperable frost today, use `frost-core` directly. this crate
is for the parts around it.

## what you have to provide yourself

three things. each has been got wrong in practice, including by us.

**reliable broadcast.** the echo round makes every participant compute the
same digest over the round-1 set and compare it. it does not deliver anything.
if your transport does not give every honest party the same view, you cannot
detect a dealer handing two people different commitments, and you must not run
the dkg over it. a chain underneath you counts. a gossip mesh with no
agreement does not.

**agreement on complaints.** a `Complaint` is signed, ceremony-bound, and
checkable by a third party. nothing here re-broadcasts one, adjudicates across
nodes, or makes everyone disqualify the same dealer. get that wrong and the
group splits: one node aborts, the rest finalize, and the key is now held by
people who disagree about who holds it.

an `Upheld` verdict means *this scalar is not a valid sub-share for that
commitment*. it does not mean the dealer sent it — noise_K authenticates the
sender to the recipient and to nobody else, so a lying recipient can fabricate
a scalar that fails the same check. that is why `ComplaintTally` wants `t`
distinct accusers before it will disqualify anyone, and why a dealer who
cheats `t-1` recipients gets excluded rather than blamed.

**durable spent-nonce state.** `SpentSessions` is a trait. the in-memory one
is for tests. a daemon that snapshots and restores without a write-ahead,
`fsync`'d log will eventually sign twice under one nonce and hand over the
share. `session_id` mixes; it does not prevent replay.

## weighted groups

there is no weight support. the way you get weights is virtualisation: a party
of weight `w` holds `w` shares at `w` identifiers. that works — shamir counts
shares, not machines — but every threshold in your system has to be in weight
units, consistently, and nothing here checks that for you. pass a party count
where a weight threshold belongs and `ComplaintTally` quietly stops protecting
anybody.

one hazard is specific to this: a weight-`w` party produces `w` contributions
in one process. reuse a nonce across them and you publish the difference of
your own shares. sample per call.

## reporting

open an issue, or mail the address in `Cargo.toml`. there is no bounty and no
embargo process. if it is serious, say so in the subject and we will not
publish anything before you want us to.
