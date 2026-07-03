# Contributing to Attack Qubits

Attack Qubits is a public research clock. A contribution is a **claim recorded on the
canonical chain**: you demonstrate work against a level's challenge, and the
project records it — auditable, timestamped, and independently reproducible.
There is no token and no financial reward (see the Non-Goals in the spec). What
you earn is a public, verifiable record of the demonstration, with your name on
it.

The canonical chain lives in this repo at
[`attack-qubits-canonical-chain.json`](attack-qubits-canonical-chain.json). It is the
single source of truth; the registry, mitigation posture, and dashboard are all
derived from it. Changes are made by pull request and accepted by merge.

> **"Signed"** in this project means **signed with your ed25519 key** (see
> "Set up your identity" below), NOT a GPG/signed-off git commit. The signature
> is recorded *inside* the chain event and verified by CI. You do not need to
> configure git signing.

## Getting started

You need [Go 1.26+](https://go.dev/dl/) and a GitHub account.

```bash
# 1. Fork the repo on GitHub (use the Fork button), then:
git clone https://github.com/<YOUR-HANDLE>/attack-qubits.git
cd attack-qubits

# 2. Build the CLI to confirm everything works:
go build ./...
go test ./...

# 3. See the current clock and the open challenges:
go run ./cmd/attack-qubits state -chain attack-qubits-canonical-chain.json
go run ./cmd/attack-qubits challenge 2          # the lowest open level
```

## How to break a level (end to end)

Each level has a deterministic target and a classical verifier. The flow is the
same for every level: **get a solution → register your key → submit it signed →
open a PR**.

### Step 1 — Get a solution for your level

How you obtain the solution depends on the level family (run `challenge <N>` to
see the target and hint):

- **Levels 1–3 (quantum-primitive):** run the circuit on a simulator (or real
  hardware) and record the outcome counts. Level 1 is a Hadamard `H q0` that
  produces outcomes `0`/`1` ~50/50 each; level 2 is `H q0; CX q0 q1` producing
  `00`/`11` ~50/50 (a Bell pair); level 3 is `H q0; CX q0 q1; CX q1 q2`
  producing `000`/`111` (GHZ-3). Use ~1000 shots; the check accepts each
  expected outcome within ±10% of 50%.
  - "Shots" = number of times you run (sample) the circuit.
  - Any quantum simulator works (Qiskit Aer, Cirq, QuTiP, …); you submit the
    counts, not the code. Example counts for level 1: `{"0":512,"1":488}`.
- **Levels 4–18 (toy order-finding):** find the multiplicative order of a base
  `g` modulo a small prime `m` (the least `k≥1` with `g^k ≡ 1 mod m`). Both `g`
  and `m` are shown by `challenge <N>`. You can compute this by hand for these
  tiny primes, or with a quantum period-finding demo.
- **Levels 19+ (toy-ECDLP):** find the discrete log `d` such that `d·G = Q` on
  the level's tiny curve. These are real puzzles (no known `d` is stored in the
  source); small-field levels are certified solvable, the rest are reference
  markers.

Check your solution locally before submitting:

```bash
go run ./cmd/attack-qubits verify 1 -measured '{"0":512,"1":488}'      # levels 1-3
go run ./cmd/attack-qubits verify 5 -solution 36                        # levels 4-18
go run ./cmd/attack-qubits verify 19 -solution <d>                      # levels 19+
```

### Step 2 — Set up your identity (once)

Submissions are **signed with ed25519**. Generate a key pair offline and keep
the private key secret:

```bash
go run ./cmd/attack-qubits keygen -author <your-handle>
# prints {author, pubkey, privkey}. Save privkey offline; NEVER commit or share it.
```

### Step 3 — Register your public key on the chain

Append a `register` event to the canonical chain:

```bash
go run ./cmd/attack-qubits register -author <your-handle> \
  -pubkey <pubkey-from-keygen> \
  -chain attack-qubits-canonical-chain.json
```

> **Ordering:** if this is your first claim and you put `register` and `submit`
> in the same PR, the `register` event **must come before** the `submit` event
> in the chain (a submit is verified against the registered key). Easiest: run
> `register` and `submit` as separate commits, register first.

### Step 4 — Record your solution signed

```bash
go run ./cmd/attack-qubits submit 1 \
  -author <your-handle> -key <privkey-from-keygen> \
  -measured '{"0":512,"1":488}' \
  -circuit sha256:<hash-of-your-circuit> \
  -circuit-desc "Single-qubit Hadamard plus-state, ~1000 shots" \
  -repro-notes "shots, simulator/device, run details" \
  -proof "why the classical check passes" \
  -chain attack-qubits-canonical-chain.json
```

(For levels 4-18 use `-solution <order>` instead of `-measured`; for 19+ use
`-solution <d>`.) The `-author` and `-key` flags are **mandatory**.

### Step 5 — Verify and open a PR

```bash
go run ./cmd/attack-qubits verify-chain -chain attack-qubits-canonical-chain.json
git checkout -b break-level-N
git add attack-qubits-canonical-chain.json
git commit -m "Break level N (<family>)"
git push origin break-level-N
```

Then open a pull request against `main` from your fork. **Commit only the change
to `attack-qubits-canonical-chain.json`** — not your private key.

## What happens after your PR is merged

1. **You** have broken level N. It is recorded `broken` and credited to you
   (your handle appears on the public dashboard under "Demonstrations").
2. **A maintainer** then runs the lifecycle step that opens the next level:
   ```bash
   go run ./cmd/attack-qubits transition N hardened -chain attack-qubits-canonical-chain.json
   go run ./cmd/attack-qubits transition N reopened -chain attack-qubits-canonical-chain.json
   ```
   This is the "apply mitigation → open the next level" step. It is **not** your
   job as a contributor — when a level is freshly broken, CI opens a reminder
   issue for the maintainer automatically. Once level N is reopened, level N+1
   becomes the open challenge anyone can attempt.

## What CI enforces

Every pull request runs `.github/workflows/ci.yml`, which:

- builds the project and runs `go vet` and the full test suite;
- runs `verify-chain` on the canonical chain: hash links must be intact, every
  recorded submission must still pass its family's classical verifier
  (measurement distribution, multiplicative order, or `d·G == Q`), **and** every
  signed event (`submit`/`reproduce`) must carry a valid ed25519 signature from
  a registered author.

A PR that adds an unverifiable solution, breaks a hash link, violates a lifecycle
transition, or carries an unsigned/invalidly-signed attributed event fails CI and
will not be merged. Reproducibility metadata (circuit hash, backend report, notes)
is not machine-checkable — it is reviewed by humans and is what makes a claim
credible beyond the bare classical check.

## Independent reproductions

Already broken a level? You can **corroborate** someone else's result (or your
own) with a `reproduce` event, also signed:

```bash
go run ./cmd/attack-qubits reproduce 1 \
  -author <your-handle> -key <privkey-from-keygen> \
  -circuit sha256:<your-reproduction-circuit> \
  -result reproduced \
  -chain attack-qubits-canonical-chain.json
```

Positive reproductions raise the level's reproduction counter on the dashboard.

## Honest-language rule

Attack Qubits measures **demonstrated logical attack qubits**, not physical-qubit
counts or hardware promises. Do not describe a result as breaking Bitcoin, and
do not equate physical qubits with logical qubits. See `docs/THREAT_MODEL.md`.
