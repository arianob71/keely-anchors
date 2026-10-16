# Keely anchor log

A public, append-only record of Keely's rental-record anchors.

Every evening Keely takes the fingerprints of that day's rental records —
inspection photos, damage notes, signed contracts, and every change to a
booking — builds a Merkle tree, and writes the root into a short manifest. The
manifest's SHA-256 is submitted to the [OpenTimestamps](https://opentimestamps.org)
calendars, and a few hours later a Bitcoin block commits to it.

Records sealed before October 2026 are labelled sayara (`sayara-anchor v1`/`v2`,
`sayara-anchor-…` files, `SY-` refs); later ones are labelled Keely. Both are
accepted for good by `tools/verify_keely_proof.py`, and nothing about the older records changed.
`tools/verify_sayara_proof.py` is an identical copy kept for old links.

This repository is the copy nobody at Keely can quietly rewrite. If a record
is ever disputed, what is published here is what was published then.

## What is in each folder

`anchors/<date>-<HHMM>/`

| file | what it is |
|---|---|
| `manifest.txt` | the four-line file that was timestamped — these exact bytes |
| `leaves.txt` | every leaf hash in the tree, sorted, one per line |
| `*.ots` | the OpenTimestamps proof from each calendar |
| `block.txt` | the Bitcoin block that commits to it, once confirmed |

`leaves.txt` holds hashes and nothing else — no booking references, no names,
no dates. You can confirm a record is in the tree, but the file tells you
nothing about anyone.

## Verifying an anchor

With the standard OpenTimestamps client:

```bash
pip install opentimestamps-client
ots verify -f manifest.txt alice.btc.calendar.opentimestamps.org.ots
```

Or with `tools/verify_keely_proof.py` from this repo, which needs only Python 3
and reads block headers from two independent explorers:

```bash
python3 tools/verify_keely_proof.py alice.btc.calendar.opentimestamps.org.ots manifest.txt
```

## Verifying one booking

An operator can export a booking's `path.json`. Pass it as a third argument:

```bash
python3 tools/verify_keely_proof.py <proof.ots> manifest.txt KY-ABC123-path.json
```

That recomputes the booking's leaf, replays its Merkle path to the root, and
checks the root against the manifest the Bitcoin block commits to.

`docs/evidence-format.md` in this repo documents every hash formula, so the
checks can be reimplemented from scratch rather than taken on trust.

## What this proves

That the record existed in exactly this form no later than the Bitcoin block's
timestamp, and has not changed since. Alter any byte and the chain breaks;
remove an entry and the links either side no longer meet.

## What it does not prove

- **Not that a photo is truthful.** It proves the image was recorded and is
  unaltered. It cannot say the damage shown is that car's.
- **Not when a photo was taken.** The timestamp is when the server received it.
  A photo taken Monday and uploaded Wednesday is anchored Wednesday. This is an
  upper bound on age, never a lower one.
- **Not who signed.** A signature is proven captured and unaltered, not made by
  the named person. Identity rests on the documents the operator collected.
- **Nothing after the last anchor.** Records since then are chained but not yet
  witnessed by Bitcoin.
