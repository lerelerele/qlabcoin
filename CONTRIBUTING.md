# Contributing to Qlabcoin

Qlabcoin is a public research clock. A contribution is a **claim recorded on the
canonical chain**: you demonstrate work against a level's challenge, and the
project records it — auditable, timestamped, and independently reproducible.
There is no token and no financial reward (see the Non-Goals in the spec). What
you earn is a public, verifiable record of the demonstration.

The canonical chain lives in this repo at
[`qlabcoin-canonical-chain.json`](qlabcoin-canonical-chain.json). It is the
single source of truth; the registry, mitigation posture, and dashboard are all
derived from it. Changes are made by pull request and accepted by merge.

## What you can submit

- **A solution** to an open level (`submit`). Levels have deterministic,
  classically verifiable targets:
  - **1–3** quantum-primitive: submit measured outcome counts (`-measured`).
  - **4–18** toy-order-finding: submit the multiplicative order (`-solution`).
  - **19+** toy-ecdlp: submit a scalar `d` with `d·G == Q` (`-solution`).
- **A lifecycle transition** on a broken level (`transition`): `hardened`, then
  `reopened` (which opens the next level).
- **An independent reproduction** of an already-broken level (`reproduce`).

## How to submit a solution

Submissions are **signed** (ed25519). First set up your identity once, then sign
each claim. Always pass `-chain` so you append to the canonical file, not the
gitignored local default.

1. **Set up your identity (once per author).** Generate a key pair offline and
   keep the private key secret:

   ```bash
   go run ./cmd/qlabcoin keygen -author <your-handle>
   # prints {author, pubkey, privkey}. Save privkey offline; never commit it.
   ```

2. **Register your public key** on the canonical chain (a separate PR, or the
   same PR as your first claim):

   ```bash
   go run ./cmd/qlabcoin register -author <your-handle> \
     -pubkey <pubkey-from-keygen> \
     -chain qlabcoin-canonical-chain.json
   ```

3. Read the challenge and confirm your solution locally:

   ```bash
   go run ./cmd/qlabcoin challenge 5
   go run ./cmd/qlabcoin verify 5 -solution 36
   ```

4. **Record it signed.** The `-author` and `-key` flags are mandatory:

   ```bash
   go run ./cmd/qlabcoin submit 5 -solution 36 \
     -author <your-handle> -key <privkey-from-keygen> \
     -circuit sha256:<hash-of-your-circuit> \
     -circuit-desc "3-qubit order-finding circuit" \
     -measured '{"...":"raw measured outputs"}' \
     -backend '{"hardware":"...","physical_qubits":N,"logical_qubits":M}' \
     -repro-notes "shots, calibration, run details" \
     -proof "why the classical check passes" \
     -chain qlabcoin-canonical-chain.json
   ```

5. Verify the whole chain still checks out, then open a PR with **only** the
   change to `qlabcoin-canonical-chain.json`:

   ```bash
   go run ./cmd/qlabcoin verify-chain -chain qlabcoin-canonical-chain.json
   ```

Reproductions (`reproduce`) follow the same pattern: they are signed, so pass
`-author` and `-key` as well.

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

## Honest-language rule

Qlabcoin measures **demonstrated logical attack qubits**, not physical-qubit
counts or hardware promises. Do not describe a result as breaking Bitcoin, and
do not equate physical qubits with logical qubits. See `docs/THREAT_MODEL.md`.

## A note on the challenges

Challenge parameters are derived deterministically from the level, so anyone can
reproduce them from source. For order-finding this means the answer is also
derivable from source — those levels are pedagogical, and their credibility
rests on the audited report and independent reproductions, not on secrecy. The
ECDLP targets (19+) are different: `Q` is a hash-derived point with **no** known
discrete log, so recovering `d` is a genuine computation. Small ECDLP curves are
still classically breakable by brute force; only at larger sizes does the
difficulty become the point the clock is measuring.
