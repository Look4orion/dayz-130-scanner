"""Mod-to-mod dependencies from CfgPatches (requiredAddons), read straight from the PBOs.
Usage: deps.py mods.tsv <mods_root> <out.json>
Reads config.cpp (text) and config.bin (rapified) from every PBO, maps each CfgPatches class to
the mod that defines it, and resolves every mod's requiredAddons to the mods providing them."""
import sys, os, re, glob, json, struct


def read_cstr_buf(b, i):
    j = b.index(b'\0', i)
    return b[i:j].decode('latin1'), j + 1


def pbo_files(path, want):
    """Yield (name, bytes) for entries whose lowercased basename is in want."""
    return pbo_entries_all(path, lambda name: os.path.basename(name).lower() in want)


def pbo_entries_all(path, keep=None):
    with open(path, 'rb') as f:
        data = f.read()
    i = 0
    entries = []
    first = True
    while True:
        name, i = read_cstr_buf(data, i)
        mime, orig, res, ts, size = struct.unpack_from('<5I', data, i)
        i += 20
        if first and not name and mime == 0x56657273:
            while True:
                k, i = read_cstr_buf(data, i)
                if not k:
                    break
                _, i = read_cstr_buf(data, i)
            first = False
            continue
        first = False
        if not name:
            break
        entries.append((name.replace('\\', '/'), mime, orig, size))
    off = i
    for name, mime, orig, size in entries:
        blob = data[off:off + size]
        off += size
        if keep is None or keep(name):
            if mime == 0x43707273 or (orig and orig != size):
                blob = lzss(blob, orig)
            yield name, blob


def lzss(data, outlen):
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
                for k in range((hi & 0x0F) + 3):
                    if len(out) >= outlen:
                        break
                    p = rpos + k
                    out.append(out[p] if p >= 0 else 0x20)
    return bytes(out)


# ---- rapified config ----
def cint(b, i):
    v = 0
    s = 0
    while True:
        c = b[i]
        i += 1
        v |= (c & 0x7F) << s
        s += 7
        if not c & 0x80:
            return v, i


def rap_array(b, i):
    n, i = cint(b, i)
    out = []
    for _ in range(n):
        t = b[i]
        i += 1
        if t == 0:
            s, i = read_cstr_buf(b, i)
            out.append(s)
        elif t in (1, 2):
            i += 4
            out.append(None)
        elif t == 3:
            sub, i = rap_array(b, i)
            out.append(sub)
        elif t == 6:
            i += 8
            out.append(None)
        else:
            raise ValueError('array elem type %d' % t)
    return out, i


def rap_class(b, off):
    """Return dict name -> ('class', offset) | ('value', v) | ('array', list)."""
    _, i = read_cstr_buf(b, off)  # inherited
    n, i = cint(b, i)
    out = {}
    for _ in range(n):
        t = b[i]
        i += 1
        if t == 0:
            name, i = read_cstr_buf(b, i)
            o = struct.unpack_from('<I', b, i)[0]
            i += 4
            out[name] = ('class', o)
        elif t == 1:
            st = b[i]
            i += 1
            name, i = read_cstr_buf(b, i)
            if st == 0 or st == 4:
                v, i = read_cstr_buf(b, i)
            elif st == 6:
                i += 8
                v = None
            else:
                i += 4
                v = None
            out[name] = ('value', v)
        elif t == 2:
            name, i = read_cstr_buf(b, i)
            arr, i = rap_array(b, i)
            out[name] = ('array', arr)
        elif t in (3, 4):
            name, i = read_cstr_buf(b, i)
        elif t == 5:
            i += 4
            name, i = read_cstr_buf(b, i)
            arr, i = rap_array(b, i)
            out[name] = ('array', arr)
        else:
            raise ValueError('entry type %d' % t)
    return out


def patches_from_bin(b):
    if b[:4] != b'\0raP':
        return {}
    root = rap_class(b, 16)
    res = {}
    if 'CfgPatches' not in {k for k in root} and not any(k.lower() == 'cfgpatches' for k in root):
        return res
    key = next(k for k in root if k.lower() == 'cfgpatches')
    pt = rap_class(b, root[key][1])
    for name, (kind, val) in pt.items():
        if kind != 'class':
            continue
        body = rap_class(b, val)
        req = []
        for k, (kk, vv) in body.items():
            if k.lower() == 'requiredaddons' and kk == 'array':
                req = [x for x in vv if isinstance(x, str)]
        res[name] = req
    return res


# ---- text config ----
def strip_comments(s):
    s = re.sub(r'//[^\n]*', '', s)
    return re.sub(r'/\*.*?\*/', '', s, flags=re.S)


def patches_from_cpp(txt):
    s = strip_comments(txt)
    m = re.search(r'class\s+CfgPatches\s*\{', s, re.I)
    if not m:
        return {}
    i = m.end()
    depth = 1
    j = i
    while j < len(s) and depth:
        if s[j] == '{':
            depth += 1
        elif s[j] == '}':
            depth -= 1
        j += 1
    body = s[i:j - 1]
    res = {}
    for cm in re.finditer(r'class\s+(\w+)\s*(?::\s*\w+\s*)?\{', body):
        k = cm.end()
        d = 1
        e = k
        while e < len(body) and d:
            if body[e] == '{':
                d += 1
            elif body[e] == '}':
                d -= 1
            e += 1
        inner = body[k:e - 1]
        ra = re.search(r'requiredAddons\s*\[\s*\]\s*\+?=\s*\{(.*?)\}', inner, re.S | re.I)
        req = re.findall(r'"([^"]+)"', ra.group(1)) if ra else []
        res[cm.group(1)] = req
    return res


def main():
    mods = [l.rstrip('\n').split('\t') for l in open(sys.argv[1], encoding='utf-8') if l.strip()]
    root = sys.argv[2]
    addon_owner = {}
    mod_req = {}
    errors = []
    for n, kind, m in ((a.strip(), b.strip(), c.strip()) for a, b, c in mods):
        req = set()
        for p in sorted(glob.glob(os.path.join(root, m, '[Aa]ddons', '*.pbo'))):
            try:
                for name, blob in pbo_files(p, {'config.bin', 'config.cpp'}):
                    if name.lower().endswith('.bin'):
                        pt = patches_from_bin(blob)
                    else:
                        pt = patches_from_cpp(blob.decode('utf-8', 'replace'))
                    for cls, r in pt.items():
                        addon_owner.setdefault(cls.lower(), set()).add(m)
                        req.update(x.lower() for x in r)
            except Exception as e:
                errors.append('%s %s: %s' % (m, os.path.basename(p), e))
        mod_req[m] = req
    deps = {}
    unresolved = {}
    for m, req in mod_req.items():
        owners = set()
        miss = set()
        for a in req:
            if a.startswith('dz_'):
                continue  # vanilla addon; some mods re-declare these names (BallerZ, APES)
            o = addon_owner.get(a)
            if o:
                owners |= o
            elif not a.startswith(('dz_', 'jm_cf', 'cf_')) and a not in ('a3_data_f', 'dz_data'):
                miss.add(a)
        owners.discard(m)
        deps[m] = sorted(owners)
        if miss:
            unresolved[m] = sorted(miss)
    json.dump({'deps': deps, 'unresolved': unresolved, 'errors': errors}, open(sys.argv[3], 'w'), indent=1)
    for m in deps:
        print(m.ljust(48), ', '.join(deps[m]))
    print('errors:', len(errors))
    for e in errors[:20]:
        print('  ', e)


if __name__ == '__main__':
    main()
