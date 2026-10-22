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


def test_version_gate_follows_stable():
    v = json.load(open(VANILLA))
    v['versions']['stable'] = '1.31.1'
    p = os.path.join(tempfile.mkdtemp(), 'v.json')
    json.dump(v, open(p, 'w'))
    r = scan('#ifdef DAYZ_1_31\nclass G {};\n#endif\n#ifdef DAYZ_1_30\nclass H {};\n#endif\n', p)
    msgs = [m for m in r['RISK'] if 'switches the code off again' in m]
    assert msgs == ['#ifdef DAYZ_1_31 switches the code off again on 1.32 (use #ifndef DAYZ_1_30)'], r['RISK']


def with_versions(base, **versions):
    v = json.load(open(base))
    v['versions'].update(versions)
    p = os.path.join(tempfile.mkdtemp(), 'v.json')
    json.dump(v, open(p, 'w'))
    return p


def test_ifdef_on_exp_version():
    r = scan('#ifdef DAYZ_1_31\nclass G {};\n#endif\n')
    assert '#ifdef DAYZ_1_31 switches the code off again on 1.32 (use #ifndef DAYZ_1_30)' in r['RISK'], r['RISK']


def test_ifndef_gate_says_ifndef():
    r = scan('#ifndef DAYZ_1_30\nclass G {};\n#endif\n')
    assert not any('DAYZ_1_30' in m for m in r['RISK']), r['RISK']
    assert '#ifndef DAYZ_1_30 only skips the code on 1.30: 1.31 compiles it again' in r['INFO'], r['INFO']


EXP_ONLY = '''
modded class Transport
{
    override bool HasCrew()
    {
        return true;
    }
}
class F : FishingSplashEffect
{
}
'''
EXP_ONLY_USE = '''
class U
{
    bool Run(Transport t)
    {
        return t.HasCrew();
    }
}
'''
WHO = 'which only Exp 1.30.164200 has, but stable 1.30.164078 compiles this code too'


def test_stable_code_using_exp_only_names():
    r = scan(EXP_ONLY, STANDIN)
    assert 'overrides Transport.HasCrew(), ' + WHO + ' and fails' in r['BREAK'], r['BREAK']
    assert 'class extends FishingSplashEffect, ' + WHO + ' and fails' in r['BREAK'], r['BREAK']
    r = scan(EXP_ONLY_USE, STANDIN)
    assert 'uses Transport.HasCrew(), ' + WHO + ' (check its version gate)' in r['RISK'], r['RISK']


def test_exp_only_name_declared_by_the_mod_is_its_own():
    r = scan(EXP_ONLY_USE + 'class W\n{\n    bool HasCrew() { return false; }\n}\n', STANDIN)
    assert not any('which only Exp' in m for m in r['RISK']), r['RISK']


def test_exp_only_names_behind_exp_gate_pass():
    p = with_versions(STANDIN, exp='1.31.1')
    r = scan('#ifdef DAYZ_1_31\n' + EXP_ONLY + '#endif\n', p)
    assert not any('which only Exp' in m for lv in ('BREAK', 'RISK') for m in r[lv]), r
    r = scan('#ifndef DAYZ_1_29\n' + EXP_ONLY + '#endif\n', p)
    assert any('which only Exp 1.31.1 has' in m for m in r['BREAK']), r['BREAK']


if __name__ == '__main__':
    for n, f in list(globals().items()):
        if n.startswith('test_'):
            f()
            print('ok', n)
