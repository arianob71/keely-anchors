# Keely evidence format

Records sealed before October 2026 are labelled sayara (`sayara-anchor v1`/`v2`,
`sayara-anchor-…` files, `SY-` refs); later ones are labelled Keely. Both are
accepted for good, and nothing about the older records changed.

How a Keely rental record is sealed, and how anyone can check it without
Keely's cooperation. Everything here is reproducible from the data an operator
can export plus `sha256` and the public OpenTimestamps and Bitcoin networks.

Three layers:

| layer | table | what it fixes |
|---|---|---|
| evidence chain | `booking_evidence` | each photo, note and contract, in the order they were recorded |
| audit chain | `booking_audit_log` | every change to the booking row itself |
| anchor | `anchors`, `anchor_leaves` | both chains, as of a Bitcoin block |

All hashes are SHA-256, written as 64 lower-case hex characters. All pre-images
are UTF-8. `|` is a literal pipe. A genesis `prev_hash` is 64 `0` characters.

---

## 1. Evidence entries

`created_iso` is the hashed timestamp, to microseconds, exactly as stored:
`YYYY-MM-DDTHH:MM:SS.ffffffZ`. Always hash the stored string — never re-render
it from `created_at`, which may print differently.

### v1 (`format = 1`)

```
entry_hash = sha256( prev_hash |booking_id |kind |file_sha256 |created_iso )
```

### v2 (`format = 2`, everything written after migration 0068)

```
entry_hash = sha256( prev_hash |booking_id |kind |label |storage_path
                     |file_sha256 |created_iso )
```

A NULL `label` or `storage_path` is the empty string, so two pipes appear with
nothing between them.

v2 exists because v1 left the label and the path outside the hash: the same
bytes could be relabelled, or pointed at a different object, without breaking
the chain. **A v1 row is always checked with the v1 formula.** It was hashed
that way; re-hashing it under v2 would read as tampering.

`kind` is one of `inspection_out_photo`, `inspection_in_photo`, `damage_note`,
`contract`.

`file_sha256` is the SHA-256 of the exact stored bytes. For `damage_note` there
is no file: `storage_path` is `<table>/<id>/<column>` and the hash is of that
column's text.

### Checking one chain

1. Order the booking's rows by `id`. That is the chain order.
2. The first row's `prev_hash` must be 64 zeros; every later row's must equal
   the previous row's `entry_hash`.
3. Recompute each `entry_hash` with the formula for that row's `format`.
4. Download each `storage_path` and confirm it hashes to `file_sha256`. Fetch
   the original object — never a thumbnail or a transformed URL.

A break tells you where: the first row whose `prev_hash` does not match is the
earliest point something was removed or reordered.

---

## 2. Audit entries

```
entry_hash = sha256( prev_hash |booking_id |action |actor_id |changed
                     |created_iso )
```

- `action` is `INSERT`, `UPDATE` or `DELETE`.
- `actor_id` is the acting user's uuid, or the empty string for a server-side
  write with no signed-in user.
- `changed` is the `jsonb` column rendered with Postgres's `::text` output.
  **Use the value exactly as the column returns it** — re-serialising the JSON
  yourself will reorder keys or change spacing and the hash will not match.
- `INSERT` records the whole row; `UPDATE` records only the changed keys as
  `{"from": …, "to": …}`; `DELETE` records just the `booking_ref`.
- Personal fields are stored as the literal string `[redacted]`. The log proves
  *that* a field changed without copying renter identity into a second table.
  `updated_at` is excluded, so a touch-only write logs nothing.

Rows written before migration 0068 were chained by its backfill, in `id` order.
Those hashes fix that history in place from the moment the migration ran; they
do not prove anything about the period before it.

---

## 3. Anchor

### Leaves

```
v1   leaf = sha256( booking_id |evidence_head )
v2   leaf = sha256( booking_id |evidence_head |audit_head )
```

A head is that chain's last `entry_hash`, or 64 zeros when the chain is empty —
so "this booking had no audit entries" is itself anchored. The manifest's first
line says which version built the leaves.

### Merkle tree

- Leaves are sorted by `booking_id`.
- `parent = sha256( left_bytes || right_bytes )` — raw 32-byte concatenation,
  not hex.
- An odd node is **promoted unchanged** to the next level. It is not duplicated:
  duplicating the last leaf is the Bitcoin convention and brings the
  CVE-2012-2459 duplicate-root ambiguity with it.

`anchor_leaves.path` is that leaf's route to the root, bottom-up:
`[{ "side": "L" | "R", "hash": "<hex>" }]`. `side` is where the *sibling* sits.
Replay it:

```
h = leaf
for step in path:
    h = sha256(step.hash || h)  if step.side == "L"
    h = sha256(h || step.hash)  if step.side == "R"
assert h == root
```

### Manifest

Four lines, with a trailing newline, and this is the file that gets timestamped:

```
keely-anchor v3
date:2026-10-15
root:<64 hex>
leaves:<count>
```

The first line is `keely-anchor v3`; v3 follows exactly the v2 rules and only the
name changed. Older anchors start `sayara-anchor v2` (or `v1`, one-chain leaves).

`digest = sha256( manifest bytes )`. Several anchors may share a date; each is
a separate run covering everything newer than the previous one.

### OpenTimestamps

`digest` is submitted to three independent calendars:

- `https://alice.btc.calendar.opentimestamps.org`
- `https://bob.btc.calendar.opentimestamps.org`
- `https://finney.calendar.eternitywall.com`

Each returns a detached `.ots` proof. Hours later a Bitcoin block commits to it
and the proof is upgraded in place. An upgrade is only stored after the block
header is fetched independently and bytes 36..68 of it — the merkle root — are
confirmed to equal the attested digest. A calendar claiming a block that does
not commit to the digest is logged and discarded.

### Public log

Every anchor is also mirrored to a public GitHub repository, one folder per run:
`manifest.txt` (the exact bytes), `leaves.txt` (every leaf hash, sorted, one per
line, no booking ids), one `.ots` per calendar, and `block.txt` once a Bitcoin
block confirms it. `anchors.public_url` points at the folder.

That matters for a reason the hashes alone cannot cover: it puts the history
somewhere Keely does not control. A proof you only ever receive from the party
it indicts is worth less than the same proof published before the dispute.
Mirroring is best effort — a failed publish is retried on the next run and never
affects the anchor itself.

---

## 4. Verifying a bundle, start to finish

The downloaded bundle is `keely-anchor-<date>-<HHMM>.txt` (the manifest), one
`.ots` per calendar, and `KY-<ref>-path.json`.

```bash
# 1. The manifest's digest is what was timestamped.
sha256sum keely-anchor-2026-10-15-2300.txt

# 2. Bitcoin confirms the timestamp. Needs the standard client:
#    pip install opentimestamps-client
ots verify -f keely-anchor-2026-10-15-2300.txt \
           keely-anchor-2026-10-15-2300-alice.btc.calendar.opentimestamps.org.ots
# → "Success! Bitcoin block <height> attests existence as of <date>"
```

3. Open `KY-<ref>-path.json`. Recompute the leaf from `booking_id`,
   `evidence_head` and `audit_head` with the v2 formula and check it equals
   `leaf`.
4. Replay `path` as above and check you reach `root`.
5. Check that `root` is the `root:` line of the manifest you just verified.
   The booking is now tied to a Bitcoin block.
6. To go further, ask the operator for the booking's `booking_evidence` and
   `booking_audit_log` rows and the stored files, then run the checks in
   sections 1 and 2. The heads you recompute must equal the ones in the JSON.

Steps 1–5 need nothing from Keely beyond the files themselves. Step 6 needs
the rows, but it needs no trust: anything altered fails.

---

## 5. What this proves, and what it does not

**Proves.** That the record existed in exactly this form no later than the
Bitcoin block's timestamp, and that it has not changed since. Every file,
label, path, note and booking-field change is inside a hash committed to that
block. Alter any byte and the chain breaks; remove an entry and the links
either side no longer meet. Nobody — operator, renter or Keely — can
retroactively edit, insert or delete without it showing.

**Does not prove.**

- **That a photo is truthful.** It proves the image was recorded and has not
  been altered since. It cannot say the damage shown is this car's, or that the
  photo was not staged.
- **When a photo was taken.** `created_iso` is when the *server received* the
  entry. A photo taken on Monday and uploaded on Wednesday is anchored
  Wednesday. The anchor is an upper bound on age, never a lower one.
- **Who the signer was.** A signature proves a signature was captured on a
  device at a time, and the record proves it has not changed. It does not
  establish that the named person made it. Identity rests on the licence and
  passport the operator collected, not on this chain.
- **Anything before the anchor.** An anchor fixes a moment. Between the last
  anchor and now, records are chained but not yet witnessed by Bitcoin.
- **Anything about the audit log before migration 0068.** Rows older than that
  were chained retroactively by its backfill.
