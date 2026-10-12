"""Extract every .c (and config.cpp) from the PBOs of the mods listed in mods.tsv.
Usage: extract.py mods.tsv <mods_root> <out_dir>
Writes <out_dir>/<n>/<pbo>/<path>, and <out_dir>/manifest.json with per-PBO notes."""
import sys, os, struct, glob, json, re


def read_cstr(f):
    b = bytearray()
    while True:
        c = f.read(1)
        if not c or c == b'\0':
            return bytes(b)
        b += c


def pbo_entries(path):
    with open(path, 'rb') as f:
        entries = []
        props = {}
        first = True
        while True:
            name = read_cstr(f)
            hdr = f.read(20)
            if len(hdr) < 20:
                break
            mime, orig, res, ts, size = struct.unpack('<5I', hdr)
            if first and not name and mime == 0x56657273:
                while True:
                    k = read_cstr(f)
                    if not k:
                        break
                    props[k.decode('latin1')] = read_cstr(f).decode('latin1')
                first = False
                continue
            first = False
            if not name:
                break
            entries.append((name.decode('latin1').replace('\\', '/'), mime, orig, size))
        data_start = f.tell()
        out = []
        off = data_start
        for name, mime, orig, size in entries:
            out.append((name, mime, orig, size, off))
            off += size
        return props, out


def lzss(data, outlen):
    """BI LZSS as used in packed PBO entries (data is followed by a 4-byte checksum)."""
    out = bytearray()
    i = 0
    n = len(data)
    while len(out) < outlen and i < n:
        flags = data[i]
        i += 1
        for b in range(8):
            if len(out) >= outlen or i >= n:
                break
            if flags & (1 << b):
                out.append(data[i])
                i += 1
            else:
                lo, hi = data[i], data[i + 1]
                i += 2
                rpos = len(out) - (lo | ((hi & 0xF0) << 4))
                rlen = (hi & 0x0F) + 3
                for k in range(rlen):
                    if len(out) >= outlen:
                        break
                    p = rpos + k
                    out.append(out[p] if p >= 0 else 0x20)
    return bytes(out)


def main():
    mods = [l.rstrip('\n').split('\t') for l in open(sys.argv[1], encoding='utf-8') if l.strip()]
    root, outdir = sys.argv[2], sys.argv[3]
    manifest = {}
    used = set()
    for n, kind, m in ((a.strip(), b.strip(), c.strip()) for a, b, c in mods):
        info = manifest.setdefault(n, {'mod': m, 'kind': kind, 'pbos': {}})
        for p in sorted(glob.glob(os.path.join(root, m, '[Aa]ddons', '*.pbo'))):
            pb = os.path.basename(p)
            props, ents = pbo_entries(p)
            note = {'prefix': props.get('prefix', ''), 'c_files': 0, 'compressed': 0, 'unreadable': 0}
            with open(p, 'rb') as f:
                for name, mime, orig, size, off in ents:
                    low = name.lower()
                    if not (low.endswith('.c') or low.endswith('config.cpp')):
                        continue
                    f.seek(off)
                    data = f.read(size)
                    if mime == 0x43707273 or (orig and orig != size):
                        try:
                            data = lzss(data, orig)
                        except IndexError:
                            note['unreadable'] += 1
                            continue
                        note['compressed'] += 1
                        if len(data) != orig:
                            note['unreadable'] += 1
                            continue
                    parts = [re.sub(r'[^\w.-]', '_', s).strip(' .') or '_' for s in name.split('/') if s]
                    if not parts or '..' in name.split('/'):
                        note['unreadable'] += 1
                        continue
                    # scrambled names can collide once cleaned up (and Windows ignores case)
                    key = '/'.join([n, pb] + parts).lower()
                    k = 2
                    base = parts[-1]
                    while key in used:
                        dot = base.rfind('.')
                        parts[-1] = base[:dot] + '~' + str(k) + base[dot:] if dot > 0 else base + '~' + str(k)
                        key = '/'.join([n, pb] + parts).lower()
                        k += 1
                    used.add(key)
                    dst = os.path.join(outdir, n, pb, *parts)
                    try:
                        os.makedirs(os.path.dirname(dst), exist_ok=True)
                        with open(dst, 'wb') as o:
                            o.write(data)
                    except OSError:
                        note['unreadable'] += 1
                        continue
                    if low.endswith('.c'):
                        note['c_files'] += 1
            info['pbos'][pb] = note
    json.dump(manifest, open(os.path.join(outdir, 'manifest.json'), 'w'), indent=1)


main()
