"""Verify a Keely rental-record anchor against Bitcoin, without trusting Keely.

Usage:  python3 verify_keely_proof.py <proof.ots> <anchor.txt> [path.json]
        python3 verify_keely_proof.py --entries <rows.json> [path.json]
        python3 verify_keely_proof.py --sig <signed.json>
        add --key <keely-signing-key.json> to any of them to use a saved copy of
        Keely's public key instead of https://keely.ae/.well-known/keely-signing-key.json

With two arguments it proves the anchor itself: the .txt is what the .ots is a
proof of, and a Bitcoin block commits to it.

With a booking's path.json as a third argument it also proves that booking is
inside the anchor: the leaf is recomputed from the chain heads, its Merkle path
is replayed, and the result is compared with the anchor's root line.

With --entries it checks one booking's evidence rows (a JSON array of
booking_evidence rows): every link and entry hash under the row's own format
(1, 2 or 3), and for v3 rows the not-before block: it must exist, have the
recorded height, and be mined no later than created_iso + 10 minutes. A text
entry (damage_note, invoice_issued, renter_confirmation, dispute_reply, photo_check, documents_submitted,
identity_verified_in_person) that carries its
hashed text as "payload" is checked against file_sha256, and a renter confirmation is
printed with its answer (an AI photo check with its result). With a path.json it also confirms the anchored
evidence head is in the chain.

From keely-anchor v4 on, the manifest is also signed by Keely: it names the
signing key (key_id, and the sha256 of the public key) and ends with a sig: line,
an Ed25519 signature of its fields. All of it is timestamped, so the key and the
signature are in Bitcoin with the root. The signature is checked against Keely's
public key.

With --sig it checks a signed Keely document on its own, such as the signature
printed on a rental record certificate: a JSON file
{"payload": {...}, "sig": "<base64>", "key_id": "<8 hex>"} (or "canonical": the
exact signed text instead of "payload").

Needs only Python 3 and internet. Reads block headers from two independent
public Bitcoin explorers (mempool.space and blockstream.info).

Records sealed before October 2026 are labelled sayara (sayara-anchor v1/v2);
later ones keely-anchor v3. All three are accepted. tools/verify_sayara_proof.py
in the public log is an identical copy, kept so old links keep working.
"""
import base64, hashlib, json, re, sys, urllib.request, urllib.error, datetime

MAGIC = bytes.fromhex('004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294')
BITCOIN = bytes.fromhex('0588960d73d71901')
PENDING = bytes.fromhex('83dfe30d2ef90c8e')
# Every manifest header ever issued. v3 has the same rules as v2.
HEADERS = {'sayara-anchor v1': 1, 'sayara-anchor v2': 2, 'keely-anchor v3': 3, 'keely-anchor v4': 4}
KEY_URL = 'https://keely.ae/.well-known/keely-signing-key.json'
KEY_FILE = None   # --key


# ── Ed25519 verification (RFC 8032 section 5.1), pure Python ────────────────
_P = 2 ** 255 - 19
_L = 2 ** 252 + 27742317777372353535851937790883648493
_D = -121665 * pow(121666, _P - 2, _P) % _P
_I = pow(2, (_P - 1) // 4, _P)


def _inv(x): return pow(x, _P - 2, _P)


def _xrecover(y, sign):
    xx = (y * y - 1) * _inv(_D * y * y + 1) % _P
    x = pow(xx, (_P + 3) // 8, _P)
    if (x * x - xx) % _P: x = x * _I % _P
    if (x * x - xx) % _P: return None
    if x == 0 and sign: return None
    return _P - x if (x & 1) != sign else x


_BY = 4 * _inv(5) % _P
_BX = _xrecover(_BY, 0)
_B = (_BX, _BY, 1, _BX * _BY % _P)


def _add(p, q):
    (x1, y1, z1, t1), (x2, y2, z2, t2) = p, q
    a, b = (y1 - x1) * (y2 - x2) % _P, (y1 + x1) * (y2 + x2) % _P
    c, d = t1 * 2 * _D * t2 % _P, z1 * 2 * z2 % _P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % _P, g * h % _P, f * g % _P, e * h % _P)


def _mul(s, p):
    q = (0, 1, 1, 0)
    while s > 0:
        if s & 1: q = _add(q, p)
        p = _add(p, p); s >>= 1
    return q


def _enc(p):
    x, y, z, _ = p
    zi = _inv(z); x, y = x * zi % _P, y * zi % _P
    return (y | ((x & 1) << 255)).to_bytes(32, 'little')


def _dec(b):
    if len(b) != 32: return None
    y = int.from_bytes(b, 'little'); sign = y >> 255; y &= (1 << 255) - 1
    if y >= _P: return None
    x = _xrecover(y, sign)
    return None if x is None else (x, y, 1, x * y % _P)


def ed25519_verify(pub, msg, sig):
    if len(pub) != 32 or len(sig) != 64: return False
    a, r = _dec(pub), _dec(sig[:32])
    if a is None or r is None: return False
    s = int.from_bytes(sig[32:], 'little')
    if s >= _L: return False
    h = int.from_bytes(hashlib.sha512(sig[:32] + pub + msg).digest(), 'little') % _L
    p, q = _mul(s, _B), _add(r, _mul(h, a))
    return (p[0] * q[2] - q[0] * p[2]) % _P == 0 and (p[1] * q[2] - q[1] * p[2]) % _P == 0


# ── Keely signature ──────────────────────────────────────────────────────────
def canonical(obj):
    """The signed text: JSON, keys sorted, no spaces, UTF-8, integers only."""
    return json.dumps(obj, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


_KEYS = None


def keely_keys():
    """key_id -> (public key bytes, status), from --key or keely.ae. None if unreachable."""
    global _KEYS
    if _KEYS is not None: return _KEYS
    try:
        doc = json.load(open(KEY_FILE)) if KEY_FILE else json.loads(get(KEY_URL))
    except Exception:
        return None
    out = {}
    for k in [doc] + list(doc.get('previous') or []):
        if not k.get('key_id') or not k.get('public_key'): continue
        pub = base64.b64decode(k['public_key'])
        if hashlib.sha256(pub).hexdigest()[:8] != k['key_id']: continue   # a key id is its key's fingerprint
        out[k['key_id']] = (pub, k.get('status') or 'active')
    _KEYS = out
    return out


def check_keely_sig(payload_text, sig_b64, key_id):
    """-> ('ok' | 'bad' | 'unknown' | 'revoked' | 'offline', public key or None)"""
    keys = keely_keys()
    if keys is None: return ('offline', None)
    if key_id not in keys: return ('unknown', None)
    pub, status = keys[key_id]
    if status == 'revoked': return ('revoked', pub)
    try:
        sig = base64.b64decode(sig_b64, validate=True)
    except Exception:
        return ('bad', pub)
    return ('ok' if ed25519_verify(pub, payload_text.encode(), sig) else 'bad', pub)


V4 = re.compile(r'\Akeely-anchor v4\ndate:(\d{4}-\d{2}-\d{2})\nroot:([0-9a-f]{64})\nleaves:(\d{1,9})\n'
                r'key_id:([0-9a-f]{8})\nkey_sha256:([0-9a-f]{64})\nsig:([A-Za-z0-9+/]{86}==)\n\Z')


def check_manifest_sig(text):
    """keely-anchor v4: exactly these lines; Keely signed the canonical JSON of the fields."""
    m = V4.match(text)
    if not m: sys.exit('FAIL  a keely-anchor v4 manifest must be exactly: header, date, root, leaves, key_id, key_sha256, sig')
    date, root, leaves, kid, ksha, sig = m.groups()
    payload = canonical({'type': 'keely-anchor', 'v': 1, 'date': date, 'root': root, 'leaves': int(leaves), 'key_sha256': ksha, 'key_id': kid})
    res, pub = check_keely_sig(payload, sig, kid)
    if res == 'offline': print('WAIT  Keely\'s public key could not be fetched: the signature was not checked (pass --key to use a saved copy)')
    elif res == 'unknown': sys.exit(f'FAIL  key {kid} is not one of Keely\'s signing keys')
    elif res == 'revoked': sys.exit(f'FAIL  key {kid} has been revoked')
    elif res != 'ok': sys.exit('FAIL  the manifest signature does not match: not signed by Keely, or changed')
    elif hashlib.sha256(pub).hexdigest() != ksha: sys.exit('FAIL  the key named in the manifest is not the key that signed it')
    else: print(f'OK    Signed by Keely · key {kid}  (Ed25519; the key\'s sha256 is timestamped with the manifest)')


def check_sig_file(path):
    doc = json.load(open(path))
    key_id, sig = doc.get('key_id') or '', doc.get('sig') or ''
    text = doc['canonical'] if isinstance(doc.get('canonical'), str) and not doc.get('payload') else canonical(doc.get('payload') or {})
    p = json.loads(text)
    if p.get('key_id') and p['key_id'] != key_id:
        sys.exit(f'FAIL  the payload names key {p["key_id"]} but the signature says key {key_id}')
    res, _ = check_keely_sig(text, sig, key_id)
    if res == 'offline': sys.exit('WAIT  Keely\'s public key could not be fetched; try again online or pass --key')
    if res == 'unknown': sys.exit(f'FAIL  key {key_id} is not one of Keely\'s signing keys')
    if res == 'revoked': sys.exit(f'FAIL  key {key_id} has been revoked')
    if res != 'ok': sys.exit(f'FAIL  the signature does not match this text: it was changed or not signed by Keely')
    print(f'OK    Signed by Keely · key {key_id}  (Ed25519)')
    for k in ('type', 'booking_ref', 'record_code', 'anchor_root', 'anchor_date', 'issued_at'):
        if p.get(k) is not None: print(f'      {k}: {p[k]}')
    print('\nVERIFIED  Keely signed exactly this text.')


class Reader:
    def __init__(self, data): self.d, self.i = data, 0
    def byte(self):
        b = self.d[self.i]; self.i += 1; return b
    def take(self, n):
        out = self.d[self.i:self.i + n]; self.i += n; return out
    def varuint(self):
        v, shift = 0, 0
        while True:
            b = self.byte(); v |= (b & 0x7f) << shift; shift += 7
            if not b & 0x80: return v
    def varbytes(self): return self.take(self.varuint())


def walk(r, msg, found):
    """Replay one timestamp node; collect (attestation, message) pairs."""
    while True:
        tag = r.byte()
        last = tag != 0xff
        if not last: tag = r.byte()
        if tag == 0x00:  # attestation
            kind = r.take(8); payload = Reader(r.varbytes())
            if kind == BITCOIN: found.append(('bitcoin', payload.varuint(), msg))
            elif kind == PENDING: found.append(('pending', payload.varbytes().decode(), msg))
            else: found.append(('unknown', kind.hex(), msg))
        else:  # operation, then its child node
            if tag == 0x08: nxt = hashlib.sha256(msg).digest()
            elif tag == 0xf0: nxt = msg + r.varbytes()
            elif tag == 0xf1: nxt = r.varbytes() + msg
            else: raise ValueError(f'unsupported operation 0x{tag:02x}')
            walk(r, nxt, found)
        if last: return


EXPLORERS = (('mempool.space', 'https://mempool.space/api'),
             ('blockstream.info', 'https://blockstream.info/api'))
ZERO = '0' * 64
SKEW = 600   # a block's timestamp may run up to 10 minutes ahead of created_iso
TEXT_KINDS = ('damage_note', 'invoice_issued', 'renter_confirmation', 'dispute_reply', 'photo_check',
              'documents_submitted', 'identity_verified_in_person')


def get(url):
    req = urllib.request.Request(url, headers={'User-Agent': 'keely-verify/1'})
    return urllib.request.urlopen(req, timeout=20).read().decode().strip()


def header(url_base, height):
    block_hash = get(f'{url_base}/block-height/{height}')
    return bytes.fromhex(get(f'{url_base}/block/{block_hash}/header'))


def leaf_of(p):
    """Recompute a booking's leaf. v2 commits to both chains, v1 to one.

       v1  leaf = sha256( booking_id |head )
       v2  leaf = sha256( booking_id |evidence_head |audit_head )

    64 zeros stand in for a chain with no entries.
    """
    zero = '0' * 64
    bid = p['booking_id']
    if p.get('evidence_head') or p.get('audit_head'):
        pre = '|'.join([bid, p.get('evidence_head') or zero, p.get('audit_head') or zero])
        version = 2
    else:
        pre = '|'.join([bid, p.get('head') or zero])
        version = 1
    return version, pre, hashlib.sha256(pre.encode()).hexdigest()


def check_path(path_json, anchor_text):
    p = json.load(open(path_json))
    version, pre, leaf = leaf_of(p)
    print(f'\n--- booking inclusion (leaf format v{version}) ---')
    if p.get('leaf') and p['leaf'].lower() != leaf:
        sys.exit(f'FAIL  recomputed leaf {leaf[:16]}... does not match the stored {p["leaf"][:16]}...')
    print(f'OK    leaf recomputed from the chain heads  ({leaf[:16]}...)')

    h = bytes.fromhex(leaf)
    for step in p.get('path') or []:
        sib = bytes.fromhex(step['hash'])
        # side is where the SIBLING sits
        h = hashlib.sha256(sib + h).digest() if step['side'] == 'L' else hashlib.sha256(h + sib).digest()
    root = h.hex()
    print(f'OK    Merkle path replayed  ({len(p.get("path") or [])} steps -> {root[:16]}...)')

    m = re.search(r'^root:([0-9a-f]{64})$', anchor_text, re.M)
    if not m:
        sys.exit('FAIL  the anchor file has no root: line')
    if m.group(1) != root:
        sys.exit(f'FAIL  path leads to {root[:16]}... but the anchor root is {m.group(1)[:16]}...')
    if p.get('root') and p['root'].lower() != root:
        sys.exit('FAIL  path.json root disagrees with the replayed path')

    ref = re.sub(r'-path\.json$', '', path_json.split('/')[-1]) or p['booking_id']
    print(f'OK    root matches the anchor that Bitcoin commits to')
    print(f'\nOK  booking {ref} is in this anchor')


def preimage(r):
    """The hashed text of one booking_evidence row, by its format (docs/evidence-format.md).

       v1  prev |booking_id |kind |file_sha256 |created_iso
       v2  prev |booking_id |kind |label |storage_path |file_sha256 |created_iso
       v3  prev |booking_id |kind |label |storage_path |file_sha256
                |btc_block_height |btc_block_hash |phash |created_iso
    NULL is the empty string.
    """
    nz = lambda v: '' if v is None else str(v)
    f = int(r.get('format') or 1)
    if f >= 3:
        parts = [r['prev_hash'], r['booking_id'], r['kind'], nz(r.get('label')), nz(r.get('storage_path')),
                 r['file_sha256'], nz(r.get('btc_block_height')), nz(r.get('btc_block_hash')), nz(r.get('phash')),
                 r['created_iso']]
    elif f == 2:
        parts = [r['prev_hash'], r['booking_id'], r['kind'], nz(r.get('label')), nz(r.get('storage_path')),
                 r['file_sha256'], r['created_iso']]
    else:
        parts = [r['prev_hash'], r['booking_id'], r['kind'], r['file_sha256'], r['created_iso']]
    return '|'.join(parts)


def block_by_hash(block_hash):
    """-> ('found', explorer, height, unix_time) | ('missing',) | ('unreachable',)"""
    missing = 0
    for name, base in EXPLORERS:
        try:
            j = json.loads(get(f'{base}/block/{block_hash}'))
        except urllib.error.HTTPError as e:
            if e.code in (400, 404): missing += 1
            continue
        except Exception:
            continue
        if j.get('id') == block_hash:
            return ('found', name, int(j['height']), int(j['timestamp']))
    return ('missing',) if missing == len(EXPLORERS) else ('unreachable',)


def check_entries(rows_path, path_json=None):
    rows = sorted(json.load(open(rows_path)), key=lambda r: int(r['id']))
    if not rows: sys.exit('FAIL  no rows in ' + rows_path)
    print(f'--- evidence chain ({len(rows)} entries, booking {rows[0]["booking_id"]}) ---')
    prev, formats = ZERO, {}
    for i, r in enumerate(rows, 1):
        f = int(r.get('format') or 1); formats[f] = formats.get(f, 0) + 1
        if r['prev_hash'] != prev:
            sys.exit(f'FAIL  entry {i} (id {r["id"]}) does not link to the one before it: something was removed or reordered')
        if hashlib.sha256(preimage(r).encode()).hexdigest() != r['entry_hash']:
            sys.exit(f'FAIL  entry {i} (id {r["id"]}, format {f}) does not hash to its entry_hash: it was changed')
        prev = r['entry_hash']
    print('OK    every link and hash holds  (formats: ' + ', '.join(f'v{k} x{v}' for k, v in sorted(formats.items())) + f')  head {prev[:16]}...')

    for i, r in enumerate(rows, 1):
        if r.get('kind') not in TEXT_KINDS or r.get('payload') is None: continue
        if hashlib.sha256(str(r['payload']).encode()).hexdigest() != r['file_sha256']:
            sys.exit(f'FAIL  entry {i} ({r["kind"]}): the payload does not hash to its file_sha256')
        if r['kind'] == 'damage_note' and str(r['payload']).startswith('{'):
            try:
                p = json.loads(r['payload'])
            except ValueError:
                p = {}
            if p.get('resolution') == 'agreed_with_renter':
                print(f'OK    entry {i}: damage added for the flagged {p.get("angle")} photo, agreed with the renter (round {p.get("round")}) at {p.get("ts")}')
            continue
        if r['kind'] == 'renter_confirmation':
            try:
                p = json.loads(r['payload'])
            except ValueError:
                sys.exit(f'FAIL  entry {i}: the renter confirmation payload is not JSON')
            if p.get('status') == 'skipped':
                print(f'OK    entry {i}: not confirmed by the renter (driver continued: {p.get("reason")}) at {p.get("ts")}')
                continue
            extra = (f', {len(p.get("disputed_photo_ids") or [])} photo(s) disputed' if p.get('status') == 'disputed' else '') + \
                    (', with a photo' if p.get('photo_sha256') else '') + (', with a note' if p.get('note') else '') + \
                    (f', answered offline at {p.get("client_ts")}' if p.get('client_ts') else '') + \
                    (f', round {p.get("round")} after the driver retook {", ".join(p.get("retaken") or []) or "photos"}' if p.get('round') else '')
            print(f'OK    entry {i}: renter {p.get("status")} the inspection {p.get("inspection_id", "")[:8]}... at {p.get("ts")}{extra}')
        elif r['kind'] == 'dispute_reply':
            try:
                p = json.loads(r['payload'])
            except ValueError:
                sys.exit(f'FAIL  entry {i}: the dispute reply payload is not JSON')
            print(f'OK    entry {i}: reply to the dispute by the {p.get("by_role")} at {p.get("ts")}')
        elif r['kind'] == 'photo_check':
            try:
                p = json.loads(r['payload'])
            except ValueError:
                sys.exit(f'FAIL  entry {i}: the photo check payload is not JSON')
            n = len((p.get('details') or {}).get('findings') or [])
            extra = f', read {p.get("read_value")}' if p.get('read_value') else (f', {n} finding(s) for review' if p.get('kind') == 'damage_diff' else '')
            print(f'OK    entry {i}: AI photo check ({p.get("kind")}) {p.get("result")}{extra}, {len(p.get("evidence_ids") or [])} photo(s), {p.get("model") or "no model call"}, at {p.get("ts")}')
        elif r['kind'] == 'documents_submitted':
            lines = [x for x in r['payload'].split('\n') if x]
            if not all(len(x.split('|')) == 3 and len(x.split('|')[2]) == 64 for x in lines):
                sys.exit(f'FAIL  entry {i}: the document list is not "kind|side|sha256" lines')
            print(f'OK    entry {i}: renter documents sent: {", ".join(x.split("|")[0] for x in lines)}')
        elif r['kind'] == 'identity_verified_in_person':
            try:
                p = json.loads(r['payload'])
            except ValueError:
                sys.exit(f'FAIL  entry {i}: the identity check payload is not JSON')
            seen_ = ', original ID seen' if p.get('original_seen') else ''
            print(f'OK    entry {i}: identity {"matched" if p.get("match") else "did not match"} in person{seen_} at {p.get("at")}')
        else:
            print(f'OK    entry {i}: {r["kind"]} text matches its hash')

    seen = {}
    for i, r in enumerate(rows, 1):
        h = r.get('btc_block_hash')
        if int(r.get('format') or 1) < 3 or not h: continue
        if h not in seen: seen[h] = block_by_hash(h)
        res = seen[h]
        if res[0] == 'unreachable':
            print(f'WAIT  entry {i}: block {r.get("btc_block_height")} could not be checked (explorers unreachable)'); continue
        if res[0] == 'missing':
            sys.exit(f'FAIL  entry {i} names block {h[:16]}... which does not exist: its not-before claim is false')
        _, name, height, ts = res
        if r.get('btc_block_height') is not None and int(r['btc_block_height']) != height:
            sys.exit(f'FAIL  entry {i} says block {r["btc_block_height"]} but that hash is block {height}')
        created = datetime.datetime.fromisoformat(r['created_iso'].replace('Z', '+00:00')).timestamp()
        mined = datetime.datetime.fromtimestamp(ts, datetime.timezone.utc)
        if ts > created + SKEW:
            sys.exit(f'FAIL  entry {i}: block {height} was mined {mined:%Y-%m-%d %H:%M} UTC, after the entry was made')
        print(f'OK    entry {i} recorded after block {height}  (mined {mined:%Y-%m-%d %H:%M} UTC, checked on {name})')

    if path_json:
        p = json.load(open(path_json))
        anchored = p.get('evidence_head') or p.get('head') or ZERO
        hashes = [r['entry_hash'] for r in rows]
        if anchored == ZERO:
            print('OK    the anchor was taken before this booking had evidence entries')
        elif anchored not in hashes:
            sys.exit('FAIL  the anchored evidence head is not in these rows')
        else:
            k = hashes.index(anchored) + 1
            later = len(rows) - k
            print(f'OK    entries 1-{k} are the ones the anchor commits to' + (f'; {later} later entr{"y is" if later == 1 else "ies are"} not anchored yet' if later else ''))
    print('\nVERIFIED  The entries are intact' + (' and each v3 block checks out.' if seen else '.'))


def main(ots_path, txt_path, path_json=None):
    data = open(ots_path, 'rb').read()
    if not data.startswith(MAGIC): sys.exit('FAIL  not an OpenTimestamps proof file')
    r = Reader(data); r.take(len(MAGIC))
    if r.varuint() != 1 or r.byte() != 0x08: sys.exit('FAIL  unexpected proof format')
    digest = r.take(32)

    anchor_text = open(txt_path, 'rb').read().decode('utf-8', 'replace')
    head = anchor_text.split('\n', 1)[0].strip()
    if head not in HEADERS: sys.exit(f'FAIL  unrecognised anchor header {head[:40]!r}')
    file_hash = hashlib.sha256(open(txt_path, 'rb').read()).digest()
    if file_hash != digest: sys.exit('FAIL  the .txt does not match this proof')
    print(f'OK    file fingerprint matches the proof  ({digest.hex()[:16]}...)  [{head}]')
    if HEADERS[head] >= 4: check_manifest_sig(anchor_text)

    found = []; walk(r, digest, found)
    btc = [f for f in found if f[0] == 'bitcoin']
    if not btc:
        sys.exit('WAIT  proof is still pending, no Bitcoin attestation yet')

    for _, height, merkle_root in btc:
        for name, base in EXPLORERS:
            h = header(base, height)
            if h[36:68] != merkle_root:
                sys.exit(f'FAIL  block {height} on {name} does not contain this record')
            when = datetime.datetime.fromtimestamp(int.from_bytes(h[68:72], 'little'), datetime.timezone.utc)
            print(f'OK    Bitcoin block {height} contains it  (checked on {name}, mined {when:%Y-%m-%d %H:%M} UTC)')
    print('\nVERIFIED  This exact record existed no later than that block, and has not changed since.')

    if path_json:
        check_path(path_json, anchor_text)


if __name__ == '__main__':
    if '--key' in sys.argv:
        i = sys.argv.index('--key')
        if i + 1 >= len(sys.argv): sys.exit(__doc__)
        KEY_FILE = sys.argv[i + 1]; del sys.argv[i:i + 2]
    if len(sys.argv) == 3 and sys.argv[1] == '--sig':
        check_sig_file(sys.argv[2])
    elif len(sys.argv) in (3, 4) and sys.argv[1] == '--entries':
        check_entries(*sys.argv[2:])
    elif len(sys.argv) in (3, 4):
        main(*sys.argv[1:])
    else:
        sys.exit(__doc__)
