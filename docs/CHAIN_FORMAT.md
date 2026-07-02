# Chain Format

State in Qlabcoin lives on an **append-only event chain** persisted as a single
JSON file (default `qlabcoin-chain.json`, not committed). The chain is the single
source of truth; the live challenge registry is *derived* from it by replaying
the events.

## Blocks

```json
{
  "blocks": [
    {
      "index": 0,
      "prev_hash": "0000000000000000000000000000000000000000000000000000000000000000",
      "events": null
    },
    {
      "index": 1,
      "prev_hash": "<sha256 of block 0>",
      "events": [
        {
          "type": "submit",
          "level": 5,
          "submission": { "...": "see Submission below" },
          "timestamp": "2026-07-01T00:00:00Z"
        }
      ]
    }
  ]
}
```

- **Genesis block** (`index 0`): `prev_hash` is 64 hex zeros, no events. It
  anchors the chain and never changes.
- Every later block has `index = previous.index + 1` and
  `prev_hash = sha256(previous_block)`.
- One event per block (1 event = 1 block). This keeps the history auditable.

## Hashing

A block's hash binds it to its predecessor and to its events:

```text
block_hash = sha256( canonical_json({ prev_hash, events }) )
```

`canonical_json` is deterministic Go struct encoding (field order is fixed).
`Nonce` is reserved for future use and currently 0; it is excluded from the hash
so it can be repurposed later without redefining chain identity.

Use `qlabcoin verify-chain` to check that every `prev_hash` matches the recomputed
hash of the previous block, and that all events replay to a valid registry. Any
edit to a recorded event (or to a link) breaks a hash link — except an edit to
the *last* block, which no later `prev_hash` binds. To close that gap, replay
re-runs classical verification on every recorded submission: measured-outcome
distributions for levels 1-3, multiplicative orders for levels 4-18, and
discrete-log scalars (d·G == Q) for levels 19+. A tampered head block with a
bogus solution is refused too.

Every command that treats the chain as the source of truth (`submit`,
`transition`, `reproduce`, `state`, `mitigation`) verifies the hash links right
after loading and refuses a tampered file. `history` deliberately skips this so
a corrupt chain can still be inspected.

## Events

```text
submit     a verified solution was accepted (open -> broken)
harden     mitigation applied (broken -> hardened)
reopen     level reopened, next level opened (hardened -> reopened)
reproduce  independent corroboration of an already-broken level
```

Each event carries a `level` and an RFC3339 UTC `timestamp`. A `submit` event
also carries the full `Submission` (challenge id, solution, circuit hash, backend
metadata, and the `verified_at` timestamp). A `reproduce` event carries a
`Reproduction`:

```json
{
  "type": "reproduce",
  "level": 5,
  "reproduction": {
    "author": "lab-b",
    "backend": { "...": "hardware/stack metadata" },
    "circuit_hash": "sha256:rep",
    "result": "reproduced",
    "notes": "independent run on a different backend",
    "timestamp": "2026-07-01T00:00:00Z"
  },
  "timestamp": "2026-07-01T00:00:00Z"
}
```

`result` is `"reproduced"` (raises the level's derived `reproductions` counter)
or `"failed"` (recorded for audit, does not raise the counter). A `reproduce`
event on a level that is not broken/hardened/reopened is invalid and fails
`verify-chain` and `state`.

## Derived state

The registry is never stored separately. To answer "what is the state of level
N?", Qlabcoin replays the chain from the genesis block and applies each event
with the same transition rules used when recording it:

```text
submit     -> open becomes broken
harden     -> broken becomes hardened
reopen     -> hardened becomes reopened, and level N+1 is opened
reproduce  -> recorded against an already-broken level; positive results
              increment the level's reproductions counter
```

An event that violates a valid transition (e.g. hardening a level that is not
broken, or reproducing one that has never been broken) makes the chain corrupt:
`verify-chain` and `state` will refuse it. So does a `submit` event whose
recorded solution fails classical re-verification for its level's family.

## CLI

```bash
qlabcoin history      # dump the chain (blocks + hashes + events)
qlabcoin verify-chain # check integrity + replay
qlabcoin state        # derived registry (replayed from the chain)
qlabcoin reproduce    # append an independent corroboration of a broken level
```

`submit`, `transition`, and `reproduce` append a block and save the chain; they
never edit prior blocks.
