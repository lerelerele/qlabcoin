# Bitcoin Distance Model (Phase 5)

Only one clock ever advances in Attack Qubits: the **academic clock**, i.e. the
highest level demonstrated on the chain (demonstrated logical attack qubits).
The distance model does not add a second clock. It translates the fixed Bitcoin
logical-qubit threshold into physical-qubit and processor terms under several
QEC-overhead assumptions, so the same honest number can be read against
different beliefs about hardware.

## The threshold being translated

```text
Q(n) = 9n + 2 ceil(log2 n) + 10          # logical qubits for ECDLP over n bits
Q(256) = 2330                            # secp256k1 reference line
```

## Processor unit

```text
1 Q6100 = 6100 physical qubits
```

The Q6100-style neutral-atom array is used as a *physical* hardware unit only.
It is never treated as 6100 logical qubits.

## Profiles

Each profile is one assumption about the physical-per-logical QEC overhead:

| Profile      | Phys/logical | Logical per Q6100 | Curve bits per Q6100 | Q6100 for Bitcoin | Physical qubits for Bitcoin |
| ------------ | -----------: | ----------------: | -------------------: | ----------------: | --------------------------: |
| optimistic   |           25 |               244 |                   24 |                10 |                      58,250 |
| moderate     |          100 |                61 |                    5 |                39 |                     233,000 |
| conservative |         1000 |                 6 |                    0 |               389 |                   2,330,000 |
| empirical    |            — |                 — |                    — |                 — |                           — |

Derivations (integer arithmetic, matching the code):

```text
logical_per_q6100     = floor(6100 / overhead)      # fractions of a logical qubit are unusable
q6100_for_bitcoin     = ceil(2330 / logical_per_q6100)
physical_for_bitcoin  = 2330 * overhead
curve_bits_per_q6100  = max n with Q(n) <= logical_per_q6100
```

Reading the table didactically:

- Under the **optimistic** 25:1 overhead, one Q6100 would already host a ~24-bit
  reference curve and Bitcoin would sit 10 processors away.
- Under the **conservative** 1000:1 (surface-code-scale) overhead, one Q6100
  yields 6 logical qubits — not even a 1-bit reference curve fits — and the same
  threshold costs 2.33 million physical qubits.
- The **empirical** profile refuses any conversion: only attack qubits actually
  demonstrated on the chain count.

## The invariant

`distance_percent` is **identical across all profiles** by design:

```text
distance_percent = 100 * demonstrated_level / 2330
```

Assumptions may re-price the threshold in hardware terms, but they must never
make the clock look further along than what has been demonstrated and recorded
on the chain. This is the project's honest-language rule applied to the model.

## CLI

```bash
attack-qubits distance                 # profiles vs the chain's highest broken level
attack-qubits distance -level 50       # hypothetical clock position, no chain needed
attack-qubits dashboard                # text quantum clock (chain-derived)
attack-qubits dashboard -html          # write attack-qubits-dashboard.html (self-contained)
attack-qubits dashboard -html -out -   # HTML to stdout
```

The HTML dashboard is a single static page with no scripts and no external
assets, so it can be published as-is (e.g. GitHub Pages). It shows the academic
clock, the derived mitigation posture, the profile table, and the
honest-language note. `examples/dashboard.html` is a committed snapshot built
from `examples/chain.json`.
