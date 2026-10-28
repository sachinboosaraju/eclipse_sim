# P2P Eclipse-Attack Simulator, Countermeasures and a New Defence

Discrete-event simulation of a Kademlia-style (Ethereum discv5) discovery
network, a reproduction of the Marcus–Heilman–Goldberg low-resource eclipse
attack (ePrint 2018/236), an evaluation of the paper's countermeasures that
fit our model, and a new identity-churn peer-scoring defence of our own,
measured for its false-positive rate on honest churn.

## Run

    pip install matplotlib
    python experiments.py

Prints both result tables and saves `success_prob.png` and
`defence_tradeoff.png`.

## Files

- `kademlia.py` — routing table (256 log-distance k-buckets, k=16, endpoint
  verification, LRU-with-liveness eviction) and the defence modes.
- `simulator.py` — discrete-event engine, honest population with churn,
  adversarial sybil flood (attacker holds A /24 subnets, each with many IPs).
- `experiments.py` — the two experiments and the plots.

## Routing table (where the vulnerability lives)

Implemented ourselves, not from a library: a node sits in bucket
`logdist(victim, id)`; insertion requires an endpoint proof (the node must
answer a ping); on a full bucket the least-recently-seen entry is pinged and
kept if it answers, so a bucket of live honest nodes resists takeover. The
attacker gains slots only as honest nodes churn offline — the behaviour the
low-resource attack exploits.

## The paper's seven countermeasures and what we did with each

The paper proposes **seven** countermeasures (Sections III, V and VI). geth
v1.8.0 fully adopted CM1, CM5 and CM6, adopted CM2 only partially (the /24
limit, not the one-key-per-IP mapping), and did not adopt CM3, CM4 or CM7.

| # | Paper's countermeasure | In our simulator |
|---|------------------------|------------------|
| CM1 | Cap incoming TCP connections (rely on outbound) | **Assumed.** Our eclipse metric is the adversary's share of the routing table that feeds *outbound* peer selection, which is exactly what CM1 forces the client to depend on. |
| CM2 | One-to-one ECDSA key ↔ IP, plus geth's partial /24 limit (2/bucket, 10/table) | **Implemented and evaluated** as two separate modes: strict one-key-per-IP (`ip`) and the per-/24 cap (`subnet`). |
| CM3 | Secret (non-public) node-ID → bucket mapping | **Not evaluated.** It defends against *grinding node IDs into targeted buckets*; our attacker floods with random IDs by volume, so this is orthogonal to the mechanism our abstraction captures. |
| CM4 | Secret self-lookup | **Not evaluated**, same reason as CM3 (defends ID/lookup targeting, not volume flooding). |
| CM5 | Run seeding even when the table is non-empty | **Not modelled.** Our steady-state churn model has no reboot / seed-database phase for seeding to help. |
| CM6 | Close the reboot exploitation window (delay bonding from unsolicited pings until self-lookup finishes) | **Not modelled**, same reason — no reboot event in our model. |
| CM7 | Use nonces instead of UDP timestamps (responses must echo a random nonce) | **Not applicable.** It fixes the separate *time/clock-manipulation* attack (Section VI), not the routing-table takeover we simulate. |

So of the paper's seven countermeasures: **one (CM2) is implemented and
evaluated** — via two mechanisms, strict one-key-per-IP and the per-/24 cap;
**one (CM1) is assumed** by our outbound-share metric; and the **remaining five
(CM3–CM7) are not evaluated**, because they act at layers our discovery-table
model abstracts away (ID/lookup secrecy, reboot seeding) or target a different
attack (CM7, the time attack). On top of these we add our own new defence
(identity-churn scoring, Experiment 2), which is not one of the paper's seven.

Defences evaluated with results: **three** — one-key-per-IP (CM2), per-/24 cap
(CM2 / geth), and our identity-churn scoring (new).

## Experiment 1 — attack vs countermeasures

Success = adversary holds ≥75% of the table. The attacker controls A /24
subnets of 16 IPs each; the x-axis is total attacker IPs.

- **No defence:** eclipsed with 16 IPs — the low-resource result.
- **One key per IP (CM2):** holds until ~64 IPs, fails from ~128 — IP limits
  are insufficient because a low-resource attacker rents a whole /24 and gets
  hundreds of IPs cheaply. This is exactly why the paper and geth moved to /24
  limits.
- **Per-/24 cap (geth fix):** holds until ~128 IPs, fails from ~256 (≥16
  distinct subnets).
- **Identity-churn score (ours):** no eclipse across the whole range (up to
  512 IPs).

## Experiment 2 — our new defence and its false-positive rate

**Why a new defence:** the /24 cap is a *static concurrency* rule. It cannot
tell an honest cloud /24 that hosts a handful of stable nodes from a /24 that
a low-resource attacker is cycling hundreds of distinct sybil IDs through — so
to stay secure it must cap hard, and a hard cap rejects honest cloud-hosted
peers (its false-positive cost), while a loose cap lets the attacker win.

**Our defence (identity-churn scoring):** per /24 origin, track the number of
*distinct node IDs* ever advertised. An honest /24 shows few, stable IDs; a
sybil /24 shows a flood. A subnet whose distinct-ID count exceeds a threshold
is treated as a sybil source: its nodes are refused admission and are the
first evicted, while low-churn origins are kept. Enforcement acts only under
capacity pressure, so honest nodes are not rejected while the bucket has room.
This is our own rule, not libp2p's peer-scoring module.

Plotting honest false-positive rate against attack severity (mean adversary
table share, attacker = 16 subnets / 256 IPs) — lower-left is better:

- **Geth /24 cap:** at near-zero false positives the attacker takes ~95% of
  the table; the only way it lowers severity is by tightening the cap, which
  raises false positives.
- **Ours:** holds the attacker to ~18–27% of the table at a false-positive
  rate at or near zero — it dominates the /24 cap across the whole curve.

## What is new in our work vs the paper

- The paper proposes countermeasures but reports **no false-positive
  evaluation under honest churn**; we measure it and show the /24 cap's hidden
  cost on clustered honest (cloud-hosted) peers.
- Our defence keys on **identity churn per network origin** (a sybil-rate
  signal) instead of the paper's **static per-/24 concurrency cap**, and in
  simulation achieves both lower attack severity and lower false positives.

## Limitations

Our defence assumes the attacker reuses a bounded set of /24s and must emit
many IDs per origin — true for the low-resource attack. An adversary with very
many /24s, or one that injects IDs slowly, looks honest to this signal — but
that adversary is no longer low-resource, which is the paper's threat model.
CM3–CM6 target layers (ID/lookup secrecy, reboot seeding) outside our
discovery-table abstraction and would need a connection/reboot model to test.
