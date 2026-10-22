import json, os, subprocess, sys, tempfile

ROOT = os.path.join(os.path.dirname(__file__), '..', '..')
TOOL = os.path.join(ROOT, 'tools', 'rules.py')
VANILLA = os.path.join(ROOT, 'docs', 'vanilla.json')
RULES = os.path.join(ROOT, 'tools', 'hand_rules.json')


def run(*args):
    p = subprocess.run([sys.executable, '-I', TOOL, *args], capture_output=True, text=True)
    return p.returncode, p.stdout.strip().splitlines()


def vanilla_with_stable(version):
    v = json.load(open(VANILLA))
    v['versions']['stable'] = version
    p = os.path.join(tempfile.mkdtemp(), 'v.json')
    json.dump(v, open(p, 'w'))
    return p


def test_current_data_has_no_stale_rules():
    code, out = run()
    assert out == ['stale 0'] and code == 0, out


def test_newer_stable_flags_every_rule():
    code, out = run(vanilla_with_stable('1.30.164300'))
    n = len(json.load(open(RULES)))
    assert code == 1 and out[-1] == 'stale %d' % n and n >= 20, (n, out[-1])


def test_unknown_message_fails():
    rules = json.load(open(RULES)) + [{'id': 'ghost', 'what': 'no scanner says this', 'verified': '9.99.1'}]
    p = os.path.join(tempfile.mkdtemp(), 'r.json')
    json.dump(rules, open(p, 'w'))
    code, out = run(VANILLA, '--rules', p)
    assert code == 1 and any('ghost' in l and 'not found' in l for l in out), out


if __name__ == '__main__':
    for n, f in list(globals().items()):
        if n.startswith('test_'):
            f()
            print('ok', n)
