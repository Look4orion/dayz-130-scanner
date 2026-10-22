import json, os, subprocess, sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
sys.path.insert(0, os.path.join(ROOT, 'python'))


def py(v):
    from enfparse import defines_for
    return defines_for(v)


def js(v):
    code = "import('./docs/js/enfparse.js').then(m => console.log(JSON.stringify(m.definesFor(%s))))" % json.dumps(v)
    p = subprocess.run(['node', '-e', code], cwd=ROOT, capture_output=True, text=True)
    assert p.returncode == 0, p.stderr
    return json.loads(p.stdout)


def check(f):
    d = f('1.31.165000')
    assert d['DAYZ_1_31'] is True and d['DAYZ_1_30'] is False and d['DAYZ_1_29'] is False, d
    assert sum(d.values()) == 1, d


def test_python_defines():
    check(py)
    assert py('1.30.164200')['DAYZ_1_30'] is True and py('1.30.164200')['DAYZ_1_29'] is False


def test_js_matches_python():
    for v in ('1.30.164200', '1.31.165000', '2.1.5'):
        assert js(v) == py(v), (v, js(v), py(v))


def test_preprocess_drops_other_versions():
    from enfparse import preprocess, defines_for
    src = '#ifdef DAYZ_1_30\na\n#endif\n#ifndef DAYZ_1_29\nb\n#endif\n#ifdef DAYZ_1_31\nc\n#endif'
    out = [x for x in preprocess(src, defines_for('1.31.165000')).split('\n') if x]
    assert out == ['b', 'c'], out


if __name__ == '__main__':
    for n, f in list(globals().items()):
        if n.startswith('test_'):
            f()
            print('ok', n)
