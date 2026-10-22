import json, os, subprocess, sys, tempfile

ROOT = os.path.join(os.path.dirname(__file__), '..', '..')
TOOL = os.path.join(ROOT, 'python', 'vanilla.py')
OLD = {
    'versions': {'129': '1.29.163709', '130': '1.30.164200'},
    '129': {'A': {'base': '', 'methods': {}, 'fields': []}},
    '130': {'A': {'base': '', 'methods': {}, 'fields': ['f']}},
    'workbench130': ['W'], 'obsolete130': ['o'], 'obsoleteDefs130': {'A.o': []},
    'obsoleteCalls130': {'o': []}, 'obsoleteUse130': {'o': ['p']},
}
EXTRAS = ('workbench', 'obsolete', 'obsoleteDefs', 'obsoleteCalls', 'obsoleteUse')


def tmp():
    return tempfile.mkdtemp()


def run(*args):
    p = subprocess.run([sys.executable, '-I', TOOL, *args], capture_output=True, text=True)
    return p.returncode, p.stdout + p.stderr


def scripts(d, body):
    os.makedirs(os.path.join(d, '4_World'), exist_ok=True)
    with open(os.path.join(d, '4_World', 'x.c'), 'w') as f:
        f.write(body)
    return d


def converted():
    d = tmp()
    src, out = os.path.join(d, 'old.json'), os.path.join(d, 'roles.json')
    json.dump(OLD, open(src, 'w'))
    code, msg = run('convert', src, out)
    assert code == 0, msg
    return out


def test_convert():
    v = json.load(open(converted()))
    assert v['versions'] == {'previous': '1.29.163709', 'stable': '1.30.164200'}, v['versions']
    assert set(v) == {'versions', 'previous', 'stable', *EXTRAS}, set(v)
    assert v['stable'] == OLD['130'] and v['previous'] == OLD['129']
    assert v['workbench'] == {'stable': ['W']} and v['obsoleteUse'] == {'stable': {'o': ['p']}}


def test_set_refuses_exp_not_newer():
    p = converted()
    code, msg = run('set', p, 'exp', scripts(tmp(), 'class B {};'), '1.30.164200')
    assert code != 0 and '1.30.164200' in msg, (code, msg)
    assert 'exp' not in json.load(open(p))


def test_set_exp_then_rotate_then_clear():
    p = converted()
    code, msg = run('set', p, 'exp', scripts(tmp(), 'class B { void m(); };'), '1.31.165000')
    assert code == 0, msg
    v = json.load(open(p))
    assert v['versions']['exp'] == '1.31.165000' and 'B' in v['exp'] and 'exp' in v['obsolete']
    code, msg = run('rotate', p, scripts(tmp(), 'class C {};'), '1.31.165100')
    assert code == 0, msg
    v = json.load(open(p))
    assert v['versions'] == {'previous': '1.30.164200', 'stable': '1.31.165100'}, v['versions']
    assert v['previous'] == OLD['130'] and 'C' in v['stable'] and 'exp' not in v
    assert v['workbench']['previous'] == ['W'] and all('exp' not in v[k] for k in EXTRAS)
    run('set', p, 'exp', scripts(tmp(), 'class D {};'), '1.32.1')
    code, msg = run('clear-exp', p)
    v = json.load(open(p))
    assert code == 0 and 'exp' not in v and 'exp' not in v['versions'] and all('exp' not in v[k] for k in EXTRAS)


if __name__ == '__main__':
    for n, f in list(globals().items()):
        if n.startswith('test_'):
            f()
            print('ok', n)
