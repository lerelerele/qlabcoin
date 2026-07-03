# Attack Qubits

Attack Qubits is an educational blockchain-lab project for measuring practical quantum progress against deliberately small cryptographic challenges.

**Live clock:** <https://lerelerele.github.io/attack-qubits/> — regenerated from the canonical chain on every push.

It is not a cryptocurrency for value transfer. It is a public research clock: each level represents a demonstrated number of useful logical attack qubits applied to a verifiable challenge. Level 1 starts at one logical qubit, then advances step by step toward a Bitcoin-like threshold.

## Core Idea

Attack Qubits separates three quantities that are often confused:

- Physical qubits: atoms, ions, superconducting qubits, photons, or another hardware substrate.
- Logical qubits: error-corrected or otherwise usable qubits in a reliable computation.
- Attack qubits: logical qubits actually used to solve a published cryptographic challenge.

Only attack qubits advance the Attack Qubits clock.

## Clocks

```text
Academic clock: level N = N useful logical attack qubits demonstrated.
Bitcoin clock: distance to an approximate secp256k1/Shor threshold.
```

The initial Bitcoin threshold is modeled as:

```text
logical_qubits_for_ECDLP(n) = 9n + 2 ceil(log2 n) + 10
```

For a 256-bit prime-field elliptic curve, this gives roughly 2330 logical qubits, before accounting for gate depth, error correction overhead, runtime, routing, and architecture-specific constraints.

## First Milestones

```text
Level 1: one useful logical qubit in a verifiable circuit (plus-state distribution).
Level 2: two useful logical qubits with entanglement evidence (Bell-pair distribution).
Level 3: three useful logical qubits in a repeatable quantum subroutine (GHZ-3).
Level 4+: toy order-finding challenges over tiny prime moduli.
Level 19+: tiny ECDLP challenges on deterministic educational curves; Q is a
           hash-derived point with no known discrete log (prime-order curves are
           certified solvable).
Level 2330: approximate Bitcoin-like logical-qubit threshold, realized as a
            256-bit hash-to-point reference marker — not secp256k1, not a claim
            of practical breakability, and not certified solvable.
```

All levels are live: every family has a deterministic target and a classical
verifier, so `challenge`, `verify`, and `submit` work end to end from level 1
to the 2330 reference line. See `docs/CHALLENGE_FORMAT.md`.

## CLI

Pure Go standard library, no dependencies. Install the binary with
`go install github.com/lerelerele/attack-qubits/cmd/attack-qubits@latest`,
or clone and use `go run`:

```bash
go run ./cmd/attack-qubits clock -max 12
go run ./cmd/attack-qubits level 19
go run ./cmd/attack-qubits challenge 5            # deterministic target for any level (1-3 primitive, 4-18 order, 19+ ECDLP)
go run ./cmd/attack-qubits verify 1 -measured '{"0":512,"1":488}'      # levels 1-3: outcome distribution
go run ./cmd/attack-qubits verify 5 -solution 36                       # levels 4-18: multiplicative order
go run ./cmd/attack-qubits verify 19 -solution <d>                     # levels 19+: discrete log d with dG = Q
go run ./cmd/attack-qubits keygen -author labA                         # generate an ed25519 key pair (offline)
go run ./cmd/attack-qubits register -author labA -pubkey <hex>         # publish/rotate a public key on chain
go run ./cmd/attack-qubits submit 5 -solution 36 -circuit sha256:... -author labA -key <hex>   # signed: verify + record
go run ./cmd/attack-qubits transition 5 hardened
go run ./cmd/attack-qubits transition 5 reopened  # opens the next level
go run ./cmd/attack-qubits reproduce 5 -author labA -key <hex> -circuit sha256:... -result reproduced  # signed corroboration
go run ./cmd/attack-qubits state                  # registry derived from the chain
go run ./cmd/attack-qubits history                # dump the chain (blocks + hashes)
go run ./cmd/attack-qubits verify-chain           # check chain integrity + replay
go run ./cmd/attack-qubits mitigation -list       # the A-F hardening ladder
go run ./cmd/attack-qubits mitigation             # active posture derived from the clock
go run ./cmd/attack-qubits mitigation -mode C -request '{"pubkey_exposed":true,"has_live_utxo":true}'
go run ./cmd/attack-qubits distance               # Bitcoin threshold under multiple QEC assumptions
go run ./cmd/attack-qubits dashboard              # text quantum clock derived from the chain
go run ./cmd/attack-qubits dashboard -html        # self-contained public dashboard (attack-qubits-dashboard.html)
go run ./cmd/attack-qubits bitcoin
```

Challenge state lives on an **append-only event chain** (default
`attack-qubits-chain.json`, not committed). Each block chains to the previous one by
`sha256`; the registry is derived by replaying the chain. The lifecycle is
`open → claimed → verified → broken → hardened → reopened`; `submit` records a
verified solution and `transition` records harden/reopen events. `submit` and
`reproduce` events are **signed with ed25519**: an author registers a public key
(`register`) and signs each attributed event, so a forged or unsigned event fails
replay. See `docs/CHAIN_FORMAT.md`.

## Distance Profiles

The Bitcoin threshold can be read against several QEC-overhead assumptions
(`attack-qubits distance`): optimistic 25:1, moderate 100:1, conservative 1000:1
physical-per-logical, plus an empirical profile that refuses any conversion.
Profiles only re-price the threshold in hardware terms — the demonstrated
distance percentage is identical across all of them, because only attack qubits
recorded on the chain advance the clock. See `docs/DISTANCE_MODEL.md`.

## Research Cycle

```text
open challenge
break challenge
publish proof and hardware/circuit report
verify classically
mark level broken
apply mitigation
open the next level
```

## Mitigation Ladder

Attack Qubits should harden itself in visible phases:

```text
Phase A: exposed public key challenges.
Phase B: hash-only addresses, pubkey revealed only on spend.
Phase C: no live UTXO after public-key exposure.
Phase D: migration window after exposure.
Phase E: hybrid ECC + hash-based signatures.
Phase F: post-quantum signatures such as ML-DSA or SLH-DSA.
```

## Contributing

Attack Qubits is a public research clock: contributions are claims recorded on the
canonical append-only chain (`attack-qubits-canonical-chain.json`) via pull request,
validated by CI (`go test` + `verify-chain`, which re-runs every recorded
solution through its classical verifier). There is no token and no financial
reward — what you earn is a public, auditable, timestamped record of a
demonstration. See [`CONTRIBUTING.md`](CONTRIBUTING.md).

## Related Work

[Project Eleven's Q-Day Prize](https://www.projecteleven.com/blog/project-eleven-awards-1-btc-q-day-prize-for-largest-quantum-attack-on-elliptic-curve-cryptography-to-date)
awarded 1 BTC in April 2026 for breaking a 15-bit elliptic-curve key on publicly
accessible quantum hardware — the largest public demonstration of this attack
class to date. Attack Qubits is complementary but structurally different:

- A bounty is a one-off event; this is a **continuous ladder**. Every level from
  1 qubit to the 2330-qubit reference line has a deterministic challenge and a
  classical verifier, so progress is recorded in single-qubit steps instead of
  announced in jumps.
- Results here are **claims on a signed, replayable chain**, not press releases:
  CI re-runs every recorded solution through its verifier from genesis on every
  commit.
- There is no prize and no token. The record itself is the reward.

## Source Assumptions

- Q6100-style hardware is treated as physical-qubit inspiration, not as 6100 logical qubits.
- The Attack Qubits level is based on demonstrated logical attack qubits.
- The Bitcoin threshold is a reference line, not a panic line.

See `docs/` for the full project model.
