import json, os, subprocess, sys, tempfile

ROOT = os.path.join(os.path.dirname(__file__), '..', '..')
SCAN = os.path.join(ROOT, 'python', 'scan130.py')
VANILLA = os.path.join(ROOT, 'docs', 'vanilla.json')

MOD = '''
class T
{
    void Run()
    {
        string name;
        int attr;
        FindFile("$profile:x/*", name, attr, -1);
    }
}
modded class PlayerBase
{
    void Later()
    {
        GetGame().GetMission();
    }
}
'''


def scan(src, vanilla=VANILLA):
    d = tempfile.mkdtemp()
    os.makedirs(os.path.join(d, '1', 'P', '4_World'))
    with open(os.path.join(d, '1', 'P', '4_World', 't.c'), 'w') as f:
        f.write(src)
    json.dump({'1': {'mod': '@T', 'kind': 'mod', 'pbos': {}}}, open(os.path.join(d, 'manifest.json'), 'w'))
    out = os.path.join(d, 'out.json')
    p = subprocess.run([sys.executable, '-I', SCAN, vanilla, d, out], capture_output=True, text=True)
    assert p.returncode == 0, p.stderr[-2000:]
    return json.load(open(out))['1']


def levels(r):
    return {k for k in r if k.split('_')[0] in ('BREAK', 'RISK', 'INFO')}


def test_stable_only_levels():
    assert levels(scan(MOD)) == {'BREAK', 'RISK', 'INFO'}, levels(scan(MOD))


def test_no_findfile_129_hit():
    r = scan(MOD)
    assert not any('1.29' in m for lv in levels(r) for m in r[lv]), r


if __name__ == '__main__':
    for n, f in list(globals().items()):
        if n.startswith('test_'):
            f()
            print('ok', n)
