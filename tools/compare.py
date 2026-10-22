"""Usage: compare.py <python report.json> <js report.json>"""
import json, sys

LEVELS = ('BREAK', 'RISK', 'INFO', 'BREAK_EXP', 'RISK_EXP', 'INFO_EXP')
a = json.load(open(sys.argv[1], encoding='utf-8'))
b = json.load(open(sys.argv[2], encoding='utf-8'))
diffs = 0
hits = 0
for n in sorted(set(a) | set(b), key=lambda k: (len(k), k)):
    ra, rb = a.get(n), b.get(n)
    if ra is None or rb is None:
        print(n, 'missing from', 'python' if ra is None else 'js')
        diffs += 1
        continue
    for k in ('files', 'unscanned_pbos', 'packed_pbos', 'mod'):
        if ra[k] != rb[k]:
            print(n, ra['mod'], k, ra[k], '!=', rb[k])
            diffs += 1
    for lv in LEVELS:
        if lv not in ra and lv not in rb:
            continue
        if (lv in ra) != (lv in rb):
            print(n, ra['mod'], lv, 'only in', 'python' if lv in ra else 'js')
            diffs += 1
            continue
        for msg in sorted(set(ra[lv]) | set(rb[lv])):
            la, lb = sorted(ra[lv].get(msg, [])), sorted(rb[lv].get(msg, []))
            hits += len(la)
            if la != lb:
                diffs += 1
                print(n, ra['mod'], lv, msg)
                print('   only python:', [x for x in la if x not in lb][:5])
                print('   only js    :', [x for x in lb if x not in la][:5])
print('mods', len(a), 'hits', hits, 'differences', diffs)
sys.exit(1 if diffs else 0)
