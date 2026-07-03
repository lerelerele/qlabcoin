# Next Steps

Phases 1–6 are done and chain events are now signed (ed25519 attribution): all
level families (1 → 2330) have deterministic targets and classical verifiers,
state lives on an append-only verified chain with signed `submit`/`reproduce`
events, the mitigation ladder and the multi-profile Bitcoin distance model are
implemented, and there is a public dashboard. See the `docs/` for the model and
`README.md` for the command surface.

## Publishing (the current focus)

Attack Qubits only does its job as a *public* research clock. The remaining work is
about running it in the open rather than adding engine features.

1. **Publish the repository** as research-only. `LICENSE` (MIT), `CONTRIBUTING.md`
   (submission-by-PR against the canonical chain), and CI (`.github/workflows/ci.yml`)
   are in place; what remains is creating the public remote and pushing.
2. **Host the dashboard.** `attack-qubits dashboard -html` emits a self-contained page;
   publish it (e.g. GitHub Pages) and regenerate it from the canonical chain.
3. **Seed the canonical chain.** `attack-qubits-canonical-chain.json` currently holds
   only the genesis block — the honest starting state. Real demonstrations land
   as PRs.

## Identity (done — v2 implemented)

Chain events are cryptographically attributed. Authors register an ed25519
public key on chain (`register`), and every `submit`/`reproduce` event carries
an ed25519 signature over a canonical payload that the replay verifies against
the registered key. Signatures are mandatory (strict mode); a signed event from
an unregistered author, a missing signature, or a tampered payload all fail
replay. See `docs/CHAIN_FORMAT.md` ("Signed events & identity").

This is attribution, not a PKI: the chain proves an event came from the holder of
a key; "who the author is in the real world" still rests on v1 (GitHub PR author
+ CI). A future hardening could add a key-revocation/compromise flow beyond the
current simple re-register (rotation).

## Smaller follow-ups

- Raise `maxCertifiedFieldBits` with a faster point-counting algorithm (e.g.
  baby-step/giant-step order finding, or Schoof) so more ECDLP levels can be
  certified solvable instead of shipped as reference markers.
- Add a machine-readable dashboard artifact (JSON) alongside the HTML.
- Bump the module/version out of `0.0.1` once the public chain goes live.

## Public messaging

Use:

```text
Attack Qubits measures demonstrated logical attack qubits.
```

Avoid:

```text
This many physical qubits can break Bitcoin.
```
