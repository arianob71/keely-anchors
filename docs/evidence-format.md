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

### v3 (`format = 3`, everything written after migration 0100)

```
entry_hash = sha256( prev_hash |booking_id |kind |label |storage_path
                     |file_sha256 |btc_block_height |btc_block_hash |phash
                     |created_iso )
```

NULLs are the empty string, as in v2; `btc_block_height` is written in decimal.
The three new fields are filled by the app when the entry is made:

- `btc_block_height`, `btc_block_hash`: the newest Bitcoin block the app could
  see (mempool.space, with blockstream.info as fallback), cached for at most 60
  seconds. Both are NULL when neither explorer could be reached; the entry is
  still made.
- `phash`: for an inspection photo, a 64-bit perceptual hash of the image as
  16 hex characters (pHash: 32×32 greyscale, 2-D DCT, the 8×8 lowest
  frequencies, one bit each for "above their median"). NULL for other kinds.

**Not-before.** A block's hash cannot be known before the block is mined, so an
entry that carries one was made *after* that block. The anchor (section 3)
already gives an upper bound on an entry's age; the block gives a lower bound,
and neither depends on Keely's clock. To check it:

1. Look the block up by hash on mempool.space or blockstream.info
   (`GET /api/block/<btc_block_hash>`). It must exist.
2. Its `height` must equal `btc_block_height`.
3. Its `timestamp` must be no later than `created_iso` plus 10 minutes. Block
   timestamps are set by miners and may run a little ahead of real time.

Read the result as "recorded after block N". A block that does not exist, or one
mined after the entry, means the claim is false. The entry's hash still holds,
because the claim was hashed as written, but it proves nothing about time.

**Perceptual hash.** Near-identical images (re-saved, resized, recompressed) land
a few bits apart, while unrelated scenes differ in about 32 of the 64 bits.
Compare by Hamming distance and never by equality: another decoder may differ by
a bit or two. Keely flags photos within 10 bits of a photo from a different
booking (`similar_photos`). That is a signal to look at, not a finding.

`kind` is one of `inspection_out_photo`, `inspection_in_photo`, `damage_note`,
`contract`, `invoice_issued`, `renter_confirmation`, `dispute_reply`, `photo_check`,
`documents_submitted`, `identity_verified_in_person`.

`file_sha256` is the SHA-256 of the exact stored bytes. A `damage_note` or an
`invoice_issued` entry has no file. Its `storage_path` is `<table>/<id>/<column>`,
and the hash is of that column's text. For an invoice or credit note, that
column is `invoices/<id>/issued_json`, the JSON it was issued with, and `label`
is the invoice number.

A `renter_confirmation` entry is the renter's own answer to a handover or return
inspection, given from a one-time link on their phone (migration 0101). It has
no file of its own. Its `storage_path` is
`inspection_confirmations/<id>/evidence_json`, and that column holds the exact
text that was hashed:

```
{"ts": "<created, to microseconds, UTC>", "note": <text or null>, "status": "confirmed" | "disputed",
 "client_ts": <the phone's own time for an answer queued offline, or null>,
 "photo_sha256": <sha256 of the renter's photo, or null>, "inspection_id": "<uuid>",
 "disputed_photo_ids": ["<photo id>", …]}
```

When the driver continues without the renter (no phone, no internet, refused,
other), the entry still exists, with `status` `skipped` and its reason:
`{"ts": …, "note": <text or null>, "reason": "no_phone" | "no_internet" | "refused" | "other", "status": "skipped", "inspection_id": …}`,
labelled `Renter did not confirm handover condition`. Answers written before
migration 0102 have no `client_ts` key.

After a dispute the driver can retake the flagged photos (each retake is a new
photo entry; the first photo stays in the chain) and the renter answers again on
the same link (migration 0105). That answer is a new `renter_confirmation` entry,
never an edit of the first one: `storage_path` is
`inspection_reconfirmations/<id>/evidence_json`, holding
`{"ts": …, "note": …, "round": 2, "status": "confirmed" | "disputed", "retaken": ["<photo id>", …], "client_ts": …, "photo_sha256": …, "inspection_id": …, "disputed_photo_ids": […]}`,
with the same label form as the first answer.

Instead of a retake, the driver can add the flagged damage (migration 0107). That
is a `damage_note` entry of its own, never an edit of `inspections.damage_notes`:
`storage_path` is `handover_flag_actions/<id>/evidence_json`, holding
`{"ts": …, "note": "<text>", "angle": "<photo id>", "round": 1, "action": "damage_agreed", "by_role": "owner" | "manager" | "driver", "resolution": "agreed_with_renter", "session_id": …, "inspection_id": …}`,
labelled `Damage agreed with renter: <photo id>`. When every flagged photo is
agreed this way, the flag is resolved with no new answer from the renter.

A `dispute_reply` entry is the driver's later answer to a dispute (migration
0102). It is a new entry and never an edit: `storage_path` is
`dispute_replies/<id>/evidence_json`, holding
`{"ts": …, "reply": "<text>", "by_role": "owner" | "manager" | "driver", "confirmation_id": "<uuid>"}`.

A `photo_check` entry is the result of an AI photo check (migration 0112): an
inspection photo read by the model and compared with what was typed: the
`plate`, the `odometer` (±1%), the `fuel` gauge (±1/8), or a return photo against
the pickup photo of the same angle (`damage_diff`). Only the photo-check function
writes one. `storage_path` is `photo_checks/<id>/evidence_json`, holding
`{"ts": …, "kind": "plate" | "odometer" | "fuel" | "damage_diff", "model": "claude-haiku-5-5", "result": "match" | "mismatch" | "unreadable", "details": {…}, "check_id": "<uuid>", "booking_id": …, "read_value": <text or null>, "evidence_ids": [<photo entry id>, …], "inspection_id": …}`,
labelled `AI photo check: <kind> <result>`. `evidence_ids` names the photo entries
it read, so the result is tied to those exact bytes. A `damage_diff` finding
(`details.findings`: angle, description, confidence) is a prompt for a person to
look, never a charge.

This is Postgres's `jsonb` text form, so the key order is fixed: shortest key
first, then alphabetical. As with the audit log, hash the stored text exactly as
it is. `label` reads `Renter confirmed handover condition`, `Renter disputed
return condition` and so on. When the renter attached a photo, it is stored in
`inspection-photos` under the booking, and `photo_sha256` fixes its bytes.

A `documents_submitted` entry seals the renter's identity documents as sent from
their upload link (migration 0121), without the images. `storage_path` is
`car_passes/<id>/docs_manifest`, holding one `kind|side|sha256` line per document
(`id_front|front|…`, `passport||…`), sorted, joined by `\n`; `file_sha256` is the
SHA-256 of that text, which is also the digest the car pass is bound to. The
document images stay private to the company; a replaced photo adds a new entry.
Labelled `Renter documents · <n> photos`.

An `identity_verified_in_person` entry is a staff answer at pickup: the person
compared with the face crop and the original document. Each answer is its own
entry (a "doesn't match" can be followed by a match, which uses the car pass).
`storage_path` is `identity_checks/<id>/statement`, holding
`{"at": "<UTC>", "by": "<user id>", "type": "identity_verified_in_person", "match": true | false, "reason": <text or null>, "pass_id": …, "booking_id": …, "docs_digest": …, "original_seen": true | false | null}`
(Postgres `jsonb` text), labelled `Identity verified in person` or
`Identity did not match`.

### Checking one chain

1. Order the booking's rows by `id`. That is the chain order.
2. The first row's `prev_hash` must be 64 zeros; every later row's must equal
   the previous row's `entry_hash`.
3. Recompute each `entry_hash` with the formula for that row's `format`.
4. Download each `storage_path` and confirm it hashes to `file_sha256`. Fetch
   the original object — never a thumbnail or a transformed URL.
5. For a v3 row with a block, run the not-before check above.

`tools/verify_keely_proof.py --entries rows.json` does steps 1–3 and 5 for one
booking's exported rows (a JSON array of `booking_evidence` rows). For a text
entry (`damage_note`, `invoice_issued`, `renter_confirmation`, `dispute_reply`, `photo_check`,
`documents_submitted`, `identity_verified_in_person`), add the
hashed text to the row as `payload` and it is checked against `file_sha256` too; a
renter confirmation is then printed with its answer and time, a photo check with its result.

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

From `keely-anchor v4` (same leaf rules as v2) the manifest is signed by Keely and
is exactly seven lines:

```
keely-anchor v4
date:2026-11-02
root:<64 hex>
leaves:<count>
key_id:<8 hex>
key_sha256:<64 hex>
sig:<88 base64>
```

`key_sha256` is sha256 of Keely's 32-byte public key and `key_id` its first 8 hex.
`sig` is Keely's Ed25519 signature of the canonical JSON (see *Keely signature*
below) of
`{"type": "keely-anchor", "v": 1, "date": …, "root": …, "leaves": <integer>, "key_sha256": …, "key_id": …}`.
The whole file, signature included, is what gets timestamped, so the signing key's
fingerprint and the signature are in Bitcoin together with the root.

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

### Keely signature

Keely signs anchor manifests and rental record certificates with one Ed25519 key
(RFC 8032). The private key lives only in Keely's signing function; it is never
logged or returned.

- **Public key**: `https://keely.ae/.well-known/keely-signing-key.json`, also
  `.well-known/keely-signing-key.json` in the public log:
  `{"alg": "Ed25519", "key_id": "<8 hex>", "public_key": "<base64, 32 bytes>", "key_sha256": "<64 hex>", "valid_from": "YYYY-MM-DD", "status": "active"}`.
  `key_id` is the first 8 hex of sha256(public key), so a key id cannot point at a
  different key. A replaced key moves to `"previous"` with `"status": "retired"`
  and still verifies what it signed; `"revoked"` never verifies.
- **Signed text**: the canonical JSON of the payload — object keys sorted, no
  whitespace, UTF-8; strings, integers, booleans, null, arrays and objects only.
  In Python: `json.dumps(p, sort_keys=True, separators=(',', ':'), ensure_ascii=False)`.
  Every payload has a `type` (`keely-anchor` or `keely-certificate`), a version `v`
  and the `key_id`, so a signature for one kind of document never passes as another.
- **Certificate**: page 2 of a rental record certificate prints the signed text, the
  signature (base64) and the key id. The payload is built by Keely from the booking:
  `{"type": "keely-certificate", "v": 1, "booking_ref": "KY-…", "record_code": "<12 hex>", "head": "<64 hex>", "anchor_root": "<64 hex>" | null, "anchor_date": "YYYY-MM-DD" | null, "issued_at": "YYYY-MM-DDTHH:MM:SSZ", "key_id": …}`
  — `head` is the booking's evidence chain tip, `anchor_root` the root of the newest
  anchor holding the booking.
- **Check**: `python3 tools/verify_keely_proof.py --sig signed.json` with
  `{"payload": {…}, "sig": "…", "key_id": "…"}` (or `"canonical": "<the printed text>"`);
  anchors with a v4 manifest are checked as part of the normal anchor run. Add
  `--key keely-signing-key.json` to use a saved copy of the public key.

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
   For the evidence rows: `python3 verify_keely_proof.py --entries rows.json
   KY-<ref>-path.json` re-checks the chain and v3 blocks, and confirms that the
   anchored head is in it.

Steps 1–5 need nothing from Keely beyond the files themselves. Step 6 needs
the rows, but it needs no trust: anything altered fails.

---

## 5. What this proves, and what it does not

**Proves.** That the record existed in exactly this form no later than the
Bitcoin block's timestamp, and that it has not changed since. For v3 entries
with a block, also that each entry was made no earlier than that block was
mined: an upper and a lower bound, both from Bitcoin. Every file,
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
  Wednesday. The anchor is an upper bound on age. A v3 block is a lower bound
  on when the *entry* was made, not on when the photo was taken: an old photo
  can still be uploaded today. The perceptual hash helps here, because a photo
  reused from another booking is flagged as similar.
- **Who the signer was.** A signature proves a signature was captured on a
  device at a time, and the record proves it has not changed. It does not
  establish that the named person made it. Identity rests on the licence and
  passport the operator collected, not on this chain.
- **Anything before the anchor.** An anchor fixes a moment. Between the last
  anchor and now, records are chained but not yet witnessed by Bitcoin.
- **Anything about the audit log before migration 0068.** Rows older than that
  were chained retroactively by its backfill.
