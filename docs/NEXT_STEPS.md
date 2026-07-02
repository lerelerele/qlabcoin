# Next Steps

Phases 1–6 are done: all level families (1 → 2330) have deterministic targets
and classical verifiers, state lives on an append-only verified chain, the
mitigation ladder and the multi-profile Bitcoin distance model are implemented,
and there is a public dashboard. See the `docs/` for the model and `README.md`
for the command surface.

## Publishing (the current focus)

Qlabcoin only does its job as a *public* research clock. The remaining work is
about running it in the open rather than adding engine features.

1. **Publish the repository** as research-only. `LICENSE` (MIT), `CONTRIBUTING.md`
   (submission-by-PR against the canonical chain), and CI (`.github/workflows/ci.yml`)
   are in place; what remains is creating the public remote and pushing.
2. **Host the dashboard.** `qlabcoin dashboard -html` emits a self-contained page;
   publish it (e.g. GitHub Pages) and regenerate it from the canonical chain.
3. **Seed the canonical chain.** `qlabcoin-canonical-chain.json` currently holds
   only the genesis block — the honest starting state. Real demonstrations land
   as PRs.

## Identity (the main open design question)

Chain events are unauthenticated: the `author` of a reproduction is a free-form
string, and anyone with the file can append a block. For a real multi-lab clock:

1. **v1 (pragmatic):** identity comes from GitHub — who opens the PR — with CI as
   the arbiter. Good enough to start.
2. **v2 (robust):** signed events (e.g. ed25519 keys recorded on the chain), so a
   submission or reproduction is cryptographically attributable and cannot be
   forged even by someone editing the file directly.

## Smaller follow-ups

- Raise `maxCertifiedFieldBits` with a faster point-counting algorithm (e.g.
  baby-step/giant-step order finding, or Schoof) so more ECDLP levels can be
  certified solvable instead of shipped as reference markers.
- Add a machine-readable dashboard artifact (JSON) alongside the HTML.
- Bump the module/version out of `0.0.1` once the public chain goes live.

## Public messaging

Use:

```text
Qlabcoin measures demonstrated logical attack qubits.
```

Avoid:

```text
This many physical qubits can break Bitcoin.
```
