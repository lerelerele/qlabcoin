# Challenge Format

Challenges are JSON documents. They are produced by the CLI and have a
deterministic id of the form `qlab-L<NNN>-<hash10>`, where `<hash10>` is the
first 10 hex chars of `sha256("qlabcoin:<level>:<family>")`.

> The `qlabcoin:` domain-separation tag is the project's original name, frozen
> at genesis. It is a protocol constant, not branding: changing it would change
> every derived challenge and invalidate submissions already recorded on the
> canonical chain.

```bash
go run ./cmd/attack-qubits challenge 1
```

```json
{
  "id": "qlab-L001-f845323307",
  "level": 1,
  "required_logical_qubits": 1,
  "family": "quantum-primitive",
  "status": "open",
  "target": {
    "name": "plus-state",
    "circuit": "H q0",
    "type": "quantum-primitive",
    "expected_outcomes": ["0", "1"],
    "min_shots": 100,
    "tolerance": 0.1,
    "max_noise": 0.05,
    "description": "Demonstrate useful logical attack qubits in a repeatable quantum subroutine.",
    "hint": "run \"H q0\" for at least 100 shots and submit the outcome counts; ...",
    "win_condition": "submit measured output, circuit hash, and reproducible verification notes"
  },
  "verification": {
    "classical": true,
    "requires_backend_report": true,
    "requires_circuit_hash": true
  },
  "mitigation_after_break": "publish result; open next level"
}
```

Each family embeds its own deterministic target parameters: `expected_outcomes`
for quantum-primitive levels, `modulus`/`base` for toy-order-finding, and the
curve `p`/`a`/`b`/`gx`/`gy`/`qx`/`qy` (plus `certified_solvable`) for toy-ecdlp.

## Families

```text
quantum-primitive
  Levels 1-3. Deterministic primitive circuits (plus-state, Bell pair, GHZ-3);
  the deliverable is a measured outcome distribution. Verified classically by
  distribution shape: >= 100 shots, expected outcomes within ±10% of 50%, at
  most 5% other outcomes.

toy-order-finding
  Levels 4 up to FirstECDLPLevel-1. Early Shor-like period-finding and
  small discrete-log-shaped challenges over tiny groups. Cheap to verify
  classically (order correct and minimal).

toy-ecdlp
  FirstECDLPLevel (19) and above. A deterministic tiny elliptic curve
  y² = x³ + ax + b over F_p per level, with base point G and a public point Q.
  The win condition is any scalar d with d·G == Q. Q is derived by hashing to a
  point on the curve — no discrete log is used to build it, so none is stored or
  recoverable from source. Small fields (<= 16 bits) use a prime-order curve, so
  the group is cyclic and Q is provably in <G>: the challenge is certified
  solvable (field size follows the reference model with a 3-bit floor).

bitcoin-reference
  Level 2330. The same ECDLP engine at 256 bits, as a reference MARKER: a
  concrete hash-derived point on an arbitrary educational curve — NOT secp256k1.
  Its group order is beyond this build's point-counting horizon, so solvability
  is not certified and no solution is known to exist.
```

The boundary between `toy-order-finding` and `toy-ecdlp` is
`FirstECDLPLevel`, derived from the resource model
(`LogicalQubitsForECDLP(1) = 19`) rather than hard-coded.

**Determinism caveat**: every family derives its parameters from the level via
hashing, so challenges are reproducible without coordination. For
order-finding, the answer is therefore also derivable from source (`SolveOrder`)
— those levels are pedagogical. The primitive distribution checks can likewise
be satisfied by fabricated counts. For ECDLP, only the curve and the point Q are
derived; Q comes from a hash-to-point, so **no discrete log is stored or
recoverable from source** — recovering `d` is a genuine computation. In all
cases what makes a submission credible is the audited protocol around it —
circuit hash, backend report, independent reproductions on the chain — not
secrecy.

## Verification per family

```bash
go run ./cmd/attack-qubits verify 1  -measured '{"0":512,"1":488}'    # distribution
go run ./cmd/attack-qubits verify 5  -solution 36                     # order
go run ./cmd/attack-qubits verify 19 -solution <d>                    # discrete log
```

## Toy order-finding targets

For levels in the `toy-order-finding` band (4 .. `FirstECDLPLevel-1`), the
challenge `target` carries a deterministic group: a base `g` and a prime modulus
`m`, both derived from the level so the same level always yields the same target.

```bash
go run ./cmd/attack-qubits challenge 5
```

```json
{
  "target": {
    "base": 2,
    "modulus": 37,
    "type": "toy-order-finding",
    "hint": "find the multiplicative order of 2 modulo 37 (least k>=1 with 2^k ≡ 1 mod 37)"
  }
}
```

The solution is the multiplicative order: the least `k >= 1` with `g^k ≡ 1 (mod m)`.
For level 5 that order is 36. Classical verification checks that the claim holds
*and* is minimal (no proper divisor of the claim already reaches 1).

## Submission and state

`submit` verifies the solution classically and, on success, appends a signed
`submit` event to the chain, advancing the level `open → claimed → verified →
broken` in one step. The event is signed, so `-author` and `-key` are mandatory
(see `docs/CHAIN_FORMAT.md` — "Signed events & identity"):

```bash
go run ./cmd/attack-qubits submit 5 -solution 36 -circuit sha256:example \
  -author <handle> -key <privkey-hex>
```

State is **not** stored separately: it is derived by replaying the append-only
event chain (default `attack-qubits-chain.json`; see `docs/CHAIN_FORMAT.md`). The
remaining manual steps append their own events via `transition`:

```bash
go run ./cmd/attack-qubits transition 5 hardened
go run ./cmd/attack-qubits transition 5 reopened   # opens level 6
```

See `examples/submission-005.json` for a full winning entry.

## Solver Proof

A submission records the solution plus the reproducibility metadata. For an
ECDLP level the solution is a scalar `d` with `d·G == Q` (recovered by the
solver — it is not derivable from the challenge source):

```json
{
  "challenge_id": "qlab-L019-89834f043f",
  "claimed_logical_attack_qubits": 19,
  "solution": "<d such that d·G == Q>",
  "circuit_hash": "sha256:...",
  "backend": {
    "hardware": "example university lab",
    "physical_qubits": 12,
    "logical_qubits": 1,
    "notes": "demonstration run"
  }
}
```

Attack Qubits must verify the solution classically before advancing the clock, both
at submit time and on every chain replay.
