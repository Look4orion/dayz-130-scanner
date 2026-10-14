"""Build vanilla.json from each version's dta/scripts.pbo (or an unpacked scripts folder).
Usage: vanilla.py <1.29 scripts> <1.30 scripts> <out.json> [<1.29 build> <1.30 build>]"""
import sys, os, json, glob, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from enfparse import parse, strip, call_args, call_arities
from deps import pbo_entries_all

OBSOLETE = re.compile(r'\[\s*Obsolete[^\]]*\]\s*(?:\w+\s+)*?(\w+)\s*\(')
# A body that does nothing, or only returns a constant.
STUB = re.compile(r'^\s*(?:return\s*(?:true|false|null|NULL|-?[\d.]+f?|""|vector\.Zero|string\.Empty)?\s*;\s*)?$')


def sources(root):
    if os.path.isfile(root):
        files = [(name, blob) for name, blob in pbo_entries_all(root) if name.lower().endswith('.c')]
    else:
        files = []
        for f in glob.glob(os.path.join(root, '**', '*.c'), recursive=True):
            with open(f, 'rb') as fh:
                files.append((os.path.relpath(f, root).replace('\\', '/'), fh.read()))
    files.sort(key=lambda x: x[0].lower())
    return [(n, b.decode('utf-8', 'replace').replace('\r\n', '\n').replace('\r', '\n')) for n, b in files]


def obsolete_defs(s):
    """(name, parameter count, required parameter count, stub) for each [Obsolete] method in stripped s."""
    out = []
    for m in OBSOLETE.finditer(s):
        args = call_args(s, m.end() - 1)
        if args is None:
            continue
        params = [a for a in args if a.strip()]
        rest = s[m.end() + len(','.join(args)) + 1:].lstrip()
        # proto (engine) methods are declared without a body but still do something
        stub = rest.startswith(';') and not re.search(r'\bproto\b', m.group(0))
        if rest.startswith('{'):
            d, j = 1, 1
            while j < len(rest) and d:
                d += {'{': 1, '}': -1}.get(rest[j], 0)
                j += 1
            stub = bool(STUB.match(rest[1:j - 1]))
        out.append((m.group(1), len(params), sum('=' not in p for p in params), stub))
    return out


def index(root):
    cls = {}
    aliases = {}
    obsolete = set()
    defs = {}
    texts = []
    for _, src in sources(root):
        parsed = parse(src)
        s = strip(src)
        texts.append(s)
        for name, n, req, stub in obsolete_defs(s):
            obsolete.add(name)
            for c in parsed:
                if any(x['obsolete'] for x in c['methods'].get(name, [])):
                    defs.setdefault(c['name'] + '.' + name, []).append({'n': n, 'req': req, 'stub': stub})
                    break
        for c in parsed:
            e = cls.setdefault(c['name'], {'base': None, 'methods': {}, 'fields': set()})
            if c['base'] and not c['modded']:
                e['base'] = c['base']
            for k, v in c['methods'].items():
                e['methods'].setdefault(k, []).extend(v)
            e['fields'] |= c['fields']
        # "typedef ItemBase Inventory_Base;": mods extend the alias, so it needs a link in the class chain
        for a, b in re.findall(r'^\s*typedef\s+(\w+)\s+(\w+)\s*;', src, re.M):
            aliases.setdefault(b, a)
    for b, a in aliases.items():
        if a in cls and b not in cls:
            cls[b] = {'base': a, 'methods': {}, 'fields': set()}
    # Argument counts vanilla still calls each obsolete name with; super.X() inside an override does not count.
    calls = {n: set() for n in obsolete}
    for t in texts:
        for n in obsolete:
            if n in t:
                calls[n] |= call_arities(t, n, skip_super=True)
    return cls, obsolete, defs, {n: sorted(a) for n, a in calls.items()}


def main():
    out = {'versions': {'129': sys.argv[4] if len(sys.argv) > 5 else '1.29',
                        '130': sys.argv[5] if len(sys.argv) > 5 else '1.30'}}
    for tag, root in (('129', sys.argv[1]), ('130', sys.argv[2])):
        ix, obsolete, defs, calls = index(root)
        out[tag] = {k: {'base': v['base'],
                        'methods': {m: [{'ret': s['ret'], 'params': list(s['params']), 'obsolete': s['obsolete'],
                                         'access': s['access']} for s in ss] for m, ss in v['methods'].items()},
                        'fields': sorted(v['fields'])} for k, v in ix.items()}
        if tag == '130':
            out['obsolete130'] = sorted(obsolete)
            out['obsoleteDefs130'] = defs
            out['obsoleteCalls130'] = calls
        print(tag, len(ix), 'classes', sum(len(v['methods']) for v in ix.values()), 'methods')
    with open(sys.argv[3], 'w') as f:
        json.dump(out, f, separators=(',', ':'))


if __name__ == '__main__':
    main()
