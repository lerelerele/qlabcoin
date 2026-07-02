# Qlabcoin Specification Draft

## 1. Purpose

Qlabcoin is a challenge chain for studying when quantum hardware can perform useful attacks against small cryptographic targets.

The project must not imply that current quantum hardware can break Bitcoin. Its role is to measure progress from one useful logical attack qubit toward larger cryptographic attacks.

## 2. Units

```text
physical_qubit
  A hardware qubit: atom, ion, superconducting circuit, photon, etc.

logical_qubit
  A corrected or sufficiently reliable computational qubit.

attack_qubit
  A logical qubit actually used in a submitted attack circuit.
```

The Qlabcoin level is:

```text
level = demonstrated_attack_qubits
```

## 3. Reference Bitcoin Threshold

For elliptic-curve discrete logarithms over prime fields, Qlabcoin uses this initial resource model:

```text
Q(n) = 9n + 2 ceil(log2 n) + 10
T(n) = 448 n^3 log2(n) + 4090 n^3
```

Where:

- `n` is the curve field size in bits.
- `Q(n)` estimates logical qubits.
- `T(n)` estimates Toffoli gates.

For `n = 256`:

```text
Q(256) = 2330 logical qubits
```

This does not include physical qubit overhead, error correction, routing, runtime, or hardware-specific constraints.

## 4. Level Families

```text
Levels 1-3:
  Quantum primitive challenges (plus-state, Bell pair, GHZ-3). Verified
  classically by measured-outcome distribution shape.

Levels 4-18:
  Toy period-finding / toy discrete-log challenges. Verified classically
  (multiplicative order, correct and minimal).

Levels 19+:
  Tiny ECDLP challenges on deterministic educational curves (3-bit field
  floor). Verified classically: any d with dG = Q.

Level 2330:
  Approximate secp256k1 logical-qubit reference line, realized as a concrete
  256-bit educational-curve challenge (not secp256k1).
```

All four families have classical verifiers; `submit` accepts any level, and
chain replay re-runs the family's verifier on every recorded submission.

## 5. Challenge Lifecycle

```text
open
  Challenge is published.

claimed
  A solver submitted a quantum/circuit report and solution.

verified
  Classical verification accepted the solution.

broken
  The level is marked broken.

hardened
  The protocol mitigation was applied.

reopened
  Next challenge is opened.
```

## 6. Submission Requirements

Each winning submission should include:

- challenge id;
- solution;
- circuit description;
- circuit hash;
- measured outputs;
- number of logical attack qubits used;
- hardware/backend metadata;
- reproducibility notes;
- classical verification proof.

Since Phase 3, all nine fields are modeled by the `Submission` type and accepted
by the `submit` command (`-circuit`, `-circuit-desc`, `-measured`, `-backend`,
`-repro-notes`, `-proof`, plus the solution and claimed qubits). Fields are
optional in the type so older chains still load, but a complete report is the
documented expectation for an academic submission.

Independent reproductions of an already-broken level are recorded separately as
`reproduce` events on the chain (see `docs/CHAIN_FORMAT.md`); positive ones raise
the level's derived `reproductions` counter.

## 7. Distance Profiles

The Bitcoin threshold is additionally reported under multiple QEC-overhead
assumptions (see `docs/DISTANCE_MODEL.md`): optimistic (25 physical per
logical), moderate (100), conservative (1000), and empirical (no conversion).
Profiles translate the threshold into Q6100-processor and physical-qubit terms;
they never advance the clock. The demonstrated distance percentage is defined
solely as `100 * demonstrated_level / 2330` and is identical across profiles.

## 8. Non-Goals

- No real financial value.
- No claim that physical qubits equal logical qubits.
- No claim that breaking a toy level breaks Bitcoin.
- No deployment of intentionally vulnerable cryptography for real assets.
