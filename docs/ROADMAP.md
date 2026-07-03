# Roadmap

## Phase 0: Project Shell

- Define level model.
- Define challenge JSON.
- Create CLI for clock and challenge generation.
- Publish assumptions.

## Phase 1: Toy Challenge Engine (done)

- Deterministic toy order-finding groups for levels 4-18.
- Classical verification (multiplicative order, strict minimality).
- Solver submission via `submit` (verifies and advances to broken).
- Challenge state transitions via `transition`; derived state via `state`.
- Classical verification for the quantum-primitive (1-3) and toy-ecdlp (19+)
  families was completed later (see "All level families" below).

## Phase 2: Local Chain (done)

- Append-only event chain of blocks, each chained by sha256 to its predecessor.
- Challenge registry derived by replaying the chain (single source of truth).
- Broken-level history, hardening events, and reopen events all recorded on chain.
- CLI: history, verify-chain; submit/transition/state now operate on the chain.
- Remaining: consensus/network (the chain is local for now).

## Phase 3: Academic Clock (done)

- Submissions now carry the full report from spec §6: circuit description,
  measured outputs, reproducibility notes, and verification proof (via the
  `submit` flags).
- Independent reproductions of a broken level are recorded as `reproduce` events
  on the chain; positive ones raise a derived `reproductions` counter.
- Remaining: signed author identity / external review (the chain is local and
  authorship is not yet cryptographically authenticated).

## Phase 4: Mitigation Lab (done)

- Mitigation ladder A-F modeled as declarative postures (see docs/MITIGATION.md):
  exposed-pubkey (A), hash-only-address (B), no-live-UTXO-after-exposure (C),
  migration-window (D), hybrid signatures (E), post-quantum signatures (F).
- Spend evaluation (EvaluateSpend) reports whether a hypothetical spend is
  acceptable under each posture and why.
- Active mode is derived from the chain (highest broken level -> rung), not set.
- CLI: mitigation (-list / -mode / -request); state now reports the derived mode.
- Remaining: signed author identity, multi-party spend policies.

## Phase 5: Bitcoin Distance Model (done)

- Reference secp256k1 threshold.
- Multiple hardware/error-correction (QEC) assumption profiles.
- Public dashboard (text + self-contained HTML). See docs/DISTANCE_MODEL.md.

## All Level Families (done)

- Quantum-primitive (1-3): deterministic circuits verified by measured-outcome
  distribution.
- Toy-ecdlp (19+): deterministic curves with a hash-to-point Q (no known
  discrete log); small fields use prime-order curves and are certified solvable.
  Level 2330 is a concrete 256-bit reference marker. See docs/CHALLENGE_FORMAT.md.
- Chain replay re-verifies every recorded submission per family.

## Signed Identity (done — v2)

- Authors register an ed25519 public key on chain (`register`); `submit` and
  `reproduce` events carry an ed25519 signature over a canonical payload.
- Replay verifies signatures against the registered key in strict mode (missing
  signature, unregistered author, or tampered payload all fail the chain).
- Commands: `keygen` (offline key pair), `register` (publish/rotate), and
  `-author`/`-key` flags on `submit`/`reproduce`. See docs/CHAIN_FORMAT.md.
- Attribution, not a PKI: real-world authorship still rests on GitHub PR + CI.

## Publication + External Review (in progress)

- LICENSE, CONTRIBUTING.md (submission-by-PR against the canonical chain), and
  CI (`.github/workflows/ci.yml`) are in place; the canonical chain
  (`attack-qubits-canonical-chain.json`) starts at genesis.
- Remaining: create the public remote and push; host the dashboard; accept
  university challenge submissions and reproducibility reviews as PRs.
