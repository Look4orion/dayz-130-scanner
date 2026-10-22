"""Usage: before_after.py <old report.json> <new report.json> [--levels L1,L2,...]
Hit counts per level, then every hit only one report has. Always exits 0."""
import json, re, sys
from collections import Counter

args = sys.argv[1:]
levels = None
if '--levels' in args:
    i = args.index('--levels')
    levels = args[i + 1].split(',')
    del args[i:i + 2]
a = json.load(open(args[0], encoding='utf-8'))
b = json.load(open(args[1], encoding='utf-8'))
LEVEL = re.compile(r'^(BREAK|RISK|INFO)(_\w+)?$')
ORDER = ('BREAK', 'RISK', 'INFO')
if levels is None:
    found = {k for r in list(a.values()) + list(b.values()) for k in r if LEVEL.match(k)}
    levels = sorted(found, key=lambda k: (k != k.split('_')[0], k.split('_', 1)[1:], ORDER.index(k.split('_')[0])))


def hits(rep, lv):
    out = Counter()
    for n, r in rep.items():
        for msg, wheres in r.get(lv, {}).items():
            for w in wheres:
                out[(r['mod'], msg, w)] += 1
    return out


diffs = []
for lv in levels:
    ha, hb = hits(a, lv), hits(b, lv)
    print('%s %d -> %d' % (lv, sum(ha.values()), sum(hb.values())))
    diffs += [('-', lv, h) for h in sorted((ha - hb).elements())] + [('+', lv, h) for h in sorted((hb - ha).elements())]
for sign, lv, (mod, msg, w) in diffs:
    print(sign, lv, mod, msg, w)
print('differences', len(diffs))
