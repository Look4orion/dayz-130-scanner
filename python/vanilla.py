"""Build vanilla.json from each version's dta/scripts.pbo (or an unpacked scripts folder).
Usage: vanilla.py <1.29 scripts> <1.30 scripts> <out.json> [<1.29 build> <1.30 build>]"""
import sys, os, json, glob, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from enfparse import parse
from deps import pbo_entries_all

OBSOLETE = re.compile(r'\[\s*Obsolete[^\]]*\]\s*(?:\w+\s+)*?(\w+)\s*\(')


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


def index(root):
    cls = {}
    aliases = {}
    obsolete = set()
    for _, src in sources(root):
        for c in parse(src):
            e = cls.setdefault(c['name'], {'base': None, 'methods': {}, 'fields': set()})
            if c['base'] and not c['modded']:
                e['base'] = c['base']
            for k, v in c['methods'].items():
                e['methods'].setdefault(k, []).extend(v)
            e['fields'] |= c['fields']
        # "typedef ItemBase Inventory_Base;": mods extend the alias, so it needs a link in the class chain
        for a, b in re.findall(r'^\s*typedef\s+(\w+)\s+(\w+)\s*;', src, re.M):
            aliases.setdefault(b, a)
        obsolete.update(m.group(1) for m in OBSOLETE.finditer(src))
    for b, a in aliases.items():
        if a in cls and b not in cls:
            cls[b] = {'base': a, 'methods': {}, 'fields': set()}
    return cls, obsolete


def main():
    out = {'versions': {'129': sys.argv[4] if len(sys.argv) > 5 else '1.29',
                        '130': sys.argv[5] if len(sys.argv) > 5 else '1.30'}}
    for tag, root in (('129', sys.argv[1]), ('130', sys.argv[2])):
        ix, obsolete = index(root)
        out[tag] = {k: {'base': v['base'],
                        'methods': {m: [{'ret': s['ret'], 'params': list(s['params']), 'obsolete': s['obsolete'],
                                         'access': s['access']} for s in ss] for m, ss in v['methods'].items()},
                        'fields': sorted(v['fields'])} for k, v in ix.items()}
        if tag == '130':
            out['obsolete130'] = sorted(obsolete)
        print(tag, len(ix), 'classes', sum(len(v['methods']) for v in ix.values()), 'methods')
    with open(sys.argv[3], 'w') as f:
        json.dump(out, f, separators=(',', ':'))


if __name__ == '__main__':
    main()
