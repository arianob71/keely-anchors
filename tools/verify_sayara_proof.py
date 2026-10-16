"""Verify a Sayara rental-record anchor against Bitcoin, without trusting Sayara.

Usage:  python3 verify_sayara_proof.py <proof.ots> <anchor.txt> [path.json]

With two arguments it proves the anchor itself: the .txt is what the .ots is a
proof of, and a Bitcoin block commits to it.

With a booking's path.json as a third argument it also proves that booking is
inside the anchor: the leaf is recomputed from the chain heads, its Merkle path
is replayed, and the result is compared with the anchor's root line.

Needs only Python 3 and internet. Reads block headers from two independent
public Bitcoin explorers (mempool.space and blockstream.info).
"""
import hashlib, json, re, sys, urllib.request, datetime

MAGIC = bytes.fromhex('004f70656e54696d657374616d7073000050726f6f6600bf89e2e884e89294')
BITCOIN = bytes.fromhex('0588960d73d71901')
PENDING = bytes.fromhex('83dfe30d2ef90c8e')


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


def header(url_base, height):
    ua = {'User-Agent': 'sayara-verify/1'}
    get = lambda u: urllib.request.urlopen(urllib.request.Request(u, headers=ua), timeout=20).read().decode().strip()
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


def main(ots_path, txt_path, path_json=None):
    data = open(ots_path, 'rb').read()
    if not data.startswith(MAGIC): sys.exit('FAIL  not an OpenTimestamps proof file')
    r = Reader(data); r.take(len(MAGIC))
    if r.varuint() != 1 or r.byte() != 0x08: sys.exit('FAIL  unexpected proof format')
    digest = r.take(32)

    anchor_text = open(txt_path, 'rb').read().decode('utf-8', 'replace')
    file_hash = hashlib.sha256(open(txt_path, 'rb').read()).digest()
    if file_hash != digest: sys.exit('FAIL  the .txt does not match this proof')
    print(f'OK    file fingerprint matches the proof  ({digest.hex()[:16]}...)')

    found = []; walk(r, digest, found)
    btc = [f for f in found if f[0] == 'bitcoin']
    if not btc:
        sys.exit('WAIT  proof is still pending, no Bitcoin attestation yet')

    for _, height, merkle_root in btc:
        for name, base in (('mempool.space', 'https://mempool.space/api'),
                           ('blockstream.info', 'https://blockstream.info/api')):
            h = header(base, height)
            if h[36:68] != merkle_root:
                sys.exit(f'FAIL  block {height} on {name} does not contain this record')
            when = datetime.datetime.fromtimestamp(int.from_bytes(h[68:72], 'little'), datetime.timezone.utc)
            print(f'OK    Bitcoin block {height} contains it  (checked on {name}, mined {when:%Y-%m-%d %H:%M} UTC)')
    print('\nVERIFIED  This exact record existed no later than that block, and has not changed since.')

    if path_json:
        check_path(path_json, anchor_text)


if __name__ == '__main__':
    if len(sys.argv) not in (3, 4): sys.exit(__doc__)
    main(*sys.argv[1:])
