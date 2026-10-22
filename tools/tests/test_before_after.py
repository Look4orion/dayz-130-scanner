import json, os, subprocess, sys, tempfile

TOOL = os.path.join(os.path.dirname(__file__), '..', 'before_after.py')


def report(levels):
    return {'1': {'mod': '@M', 'files': 1, 'unscanned_pbos': [], 'packed_pbos': [], **levels}}


def run(a, b, *extra):
    d = tempfile.mkdtemp()
    pa, pb = os.path.join(d, 'a.json'), os.path.join(d, 'b.json')
    json.dump(a, open(pa, 'w'))
    json.dump(b, open(pb, 'w'))
    p = subprocess.run([sys.executable, '-I', TOOL, pa, pb, *extra], capture_output=True, text=True)
    return p.returncode, p.stdout.strip().splitlines()


def test_identical():
    r = report({'BREAK': {'m': ['f.c']}, 'RISK': {}, 'INFO': {}})
    code, out = run(r, r)
    assert code == 0 and out[-1] == 'differences 0', out


def test_one_removed():
    a = report({'BREAK': {'m': ['f.c', 'g.c']}, 'RISK': {}, 'INFO': {}})
    b = report({'BREAK': {'m': ['f.c']}, 'RISK': {}, 'INFO': {}})
    code, out = run(a, b)
    assert code == 0 and out[-1] == 'differences 1', out
    assert '- BREAK @M m g.c' in out, out
    assert 'BREAK 2 -> 1' in out, out


def test_level_filter_and_new_level():
    a = report({'BREAK': {}, 'RISK': {}, 'INFO': {}})
    b = report({'BREAK': {}, 'RISK': {}, 'INFO': {}, 'RISK_EXP': {'x': ['h.c']}})
    assert run(a, b, '--levels', 'BREAK,RISK,INFO')[1][-1] == 'differences 0'
    code, out = run(a, b)
    assert '+ RISK_EXP @M x h.c' in out and out[-1] == 'differences 1', out


def test_ignores_non_level_keys():
    r = report({'BREAK': {'m': ['f.c']}, 'RISK': {}, 'INFO': {}, 'note': 'text', 'extra': {'k': 1}})
    code, out = run(r, r)
    assert code == 0 and out[-1] == 'differences 0', out


def test_counts_duplicate_hits():
    a = report({'BREAK': {'m': ['f.c', 'f.c']}, 'RISK': {}, 'INFO': {}})
    b = report({'BREAK': {'m': ['f.c']}, 'RISK': {}, 'INFO': {}})
    code, out = run(a, b)
    assert 'BREAK 2 -> 1' in out and out[-1] == 'differences 1', out


if __name__ == '__main__':
    for n, f in list(globals().items()):
        if n.startswith('test_'):
            f()
            print('ok', n)
