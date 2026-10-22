"""Usage: rules.py [vanilla.json] [--rules hand_rules.json]
Lists the hand-written checks last verified on an older build than the current stable one, and any
whose message is missing from either scanner. Exit 1 when there is anything to review."""
import json, os, re, sys

ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
args = sys.argv[1:]
rules_path = os.path.join(ROOT, 'tools', 'hand_rules.json')
if '--rules' in args:
    i = args.index('--rules')
    rules_path = args[i + 1]
    del args[i:i + 2]
vanilla = args[0] if args else os.path.join(ROOT, 'docs', 'vanilla.json')


def ver(s):
    return tuple(int(x) for x in re.findall(r'\d+', s)[:3])


stable = json.load(open(vanilla))['versions']['stable']
rules = json.load(open(rules_path))
code = {f: open(os.path.join(ROOT, f), encoding='utf-8').read() for f in ('python/scan130.py', 'docs/js/scan.js')}
problems = 0
for r in rules:
    missing = [f for f, t in code.items() if r['what'] not in t]
    if missing:
        print('MISSING %s: "%s" not found in %s' % (r['id'], r['what'], ', '.join(missing)))
        problems += 1
for r in rules:
    if ver(r['verified']) < ver(stable):
        print('STALE %s (verified %s, stable %s): %s' % (r['id'], r['verified'], stable, r['what']))
        problems += 1
print('stale', sum(ver(r['verified']) < ver(stable) for r in rules))
sys.exit(1 if problems else 0)
