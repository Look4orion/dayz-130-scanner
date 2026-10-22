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


def scan(src, vanilla=VANILLA, path='4_World/t.c'):
    d = tempfile.mkdtemp()
    f = os.path.join(d, '1', 'P', *path.split('/'))
    os.makedirs(os.path.dirname(f))
    with open(f, 'w') as fh:
        fh.write(src)
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


STANDIN = os.path.join(ROOT, 'notes', 'standin.json')
CROSS = '''
class T
{
    vector Run(vector a)
    {
        return a.Cross(a);
    }
}
'''


def test_exp_levels_with_exp_data():
    assert levels(scan(MOD, STANDIN)) == {'BREAK', 'RISK', 'INFO', 'BREAK_EXP', 'RISK_EXP', 'INFO_EXP'}


def test_exp_reports_what_exp_removed():
    r = scan(CROSS, STANDIN)
    hits = [m for m in r['RISK_EXP'] if 'Cross' in m]
    assert hits and all('Exp 1.30.164200' in m for m in hits), r


def test_exp_not_newer_is_ignored():
    v = json.load(open(STANDIN))
    v['versions']['exp'] = v['versions']['stable']
    p = os.path.join(tempfile.mkdtemp(), 'v.json')
    json.dump(v, open(p, 'w'))
    assert levels(scan(MOD, p)) == {'BREAK', 'RISK', 'INFO'}


OLD_OBSOLETE = '''
modded class CarScript
{
    override bool IsVitalTruckBattery()
    {
        return false;
    }
}
'''
WB_USE = '''
class P
{
    void Run()
    {
        Workbench.GetModule(WorkbenchPluginAttribute);
    }
}
'''


def test_exp_skips_already_obsolete():
    r = scan(OLD_OBSOLETE, STANDIN)
    assert not any('IsVitalTruckBattery' in m for lv in ('BREAK_EXP', 'RISK_EXP', 'INFO_EXP') for m in r[lv]), r


def test_exp_skips_workbench_only_folder():
    r = scan(WB_USE, STANDIN, 'Editor/Plugins/x.c')
    assert not r['RISK_EXP'], r
    r = scan(WB_USE, STANDIN, '5_Mission/x.c')
    assert any('Workbench' in m for m in r['RISK_EXP']), r


if __name__ == '__main__':
    for n, f in list(globals().items()):
        if n.startswith('test_'):
            f()
            print('ok', n)
