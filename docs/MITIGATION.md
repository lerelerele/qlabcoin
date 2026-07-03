# Mitigation Lab

A didactic model of the post-quantum hardening ladder. It is **not** a wallet and
**not** a transaction engine: there is no real money. Each rung represents a
defensive *posture*; `attack-qubits mitigation` reports which posture is currently
implied by the academic clock, and `EvaluateSpend` checks whether a hypothetical
spend would be acceptable under a given posture and why.

## The ladder (A -> F)

| Mode | Name | What it enforces |
|------|------|------------------|
| A | exposed public key | Baseline. Public keys may be exposed and spent from. Most vulnerable. |
| B | hash-only address | Addresses commit to a hash of the key; a raw `p2pkh` (which embeds the pubkey) is refused. |
| C | no live UTXO after exposure | A live UTXO on an exposed public key is refused. |
| D | migration window after exposure | An exposed key is tolerated only for ~30 days; older exposures must have been swept. |
| E | hybrid ECC + hash signatures | An ECC-only signature is refused; a hybrid signature is required. |
| F | post-quantum signatures | A post-quantum scheme (`ml-dsa` / `slh-dsa`) is required. |

The ladder mirrors the README "Mitigation Ladder" (Phases A-F) and reconciles it
with the roadmap: `D` is the migration-window rung.

## Active mode is derived, not set

There is no explicit "set mode" command. The active posture is derived from the
chain: as the highest *demonstrated* (broken) level rises, the recommended
posture hardens. The bands are deliberately coarse and didactic, not a scientific
claim of when one must migrate:

```text
nothing broken             -> A
>= 1 level broken          -> B
>= 5 levels                -> C
>= FirstECDLPLevel (19)    -> D   (first ECDLP-shaped demonstration)
>= 100                     -> E
>= 1000                    -> F   (approaching the Bitcoin reference threshold)
```

Because the mode is derived from the append-only chain, it cannot be edited
without appending legitimate, hash-chained blocks.

## Spend evaluation

A spend request describes the situation around a key/UTXO; the decision says
whether it is acceptable under a mode:

```bash
attack-qubits mitigation -mode C -request '{"pubkey_exposed":true,"has_live_utxo":true}'
# -> allowed: false, reason: "live UTXO on an exposed public key is not allowed"

attack-qubits mitigation -mode F -request '{"signature_scheme":"ml-dsa"}'
# -> allowed: true, reason: "post-quantum signature (ml-dsa) accepted"
```

Spend request fields:

- `pubkey_exposed` (bool)
- `address_type` (`p2pkh` | `p2sh` | `p2wpkh` | `p2tr` ...)
- `has_live_utxo` (bool)
- `signature_scheme` (`ecdsa` | `hybrid` | `ml-dsa` | `slh-dsa`)
- `age_after_exposure` (e.g. `"30d"`, used by the migration window)

## Non-goals

- No real funds, balances, or transaction processing.
- No cryptographic verification of ML-DSA / SLH-DSA: they are *scheme
  identifiers* for the lab, not implemented algorithms.
- The bands are illustrative starting points, meant to be tuned by future
  resource models, not a policy prescription for real deployments.
