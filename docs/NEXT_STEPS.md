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

1. **Publish the repository** — done: <https://github.com/lerelerele/attack-qubits>
   (originally published as `qlabcoin`, renamed 2026-07-03; the `qlabcoin:`
   challenge-derivation tags are frozen at genesis as protocol constants).
2. **Host the dashboard** — done: <https://lerelerele.github.io/attack-qubits/>,
   regenerated from the canonical chain by `.github/workflows/publish-dashboard.yml`
   on every push to `main`.
3. **Grow the canonical chain.** `attack-qubits-canonical-chain.json` holds genesis
   plus the maintainer's level-1 bootstrap (register, submit, harden, reopen).
   The frontier is level 2 (Bell-pair evidence). External demonstrations land
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
