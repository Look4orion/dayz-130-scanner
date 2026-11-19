"""Calls to a vanilla method whose signature changed, made the old way (Exp 1.30.164393 cases)."""
import json, os, sys

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'python'))
from test_scan_levels import scan, VANILLA  # noqa: E402
from enfparse import parse  # noqa: E402


def hits(r, level):
    return [m for m in r.get(level, {})]


def test_parser_counts_required_params():
    c = parse('class A { bool F(string pin, bool sync = true, bool strict = true) { return true; } }')[0]
    assert c['methods']['F'][0]['req'] == 1


def test_data_has_required_counts():
    v = json.load(open(VANILLA))
    s = v['exp']['CodeLockComponent']['methods']['SetLockCode'][0]
    assert s['params'] == ['string', 'bool', 'bool'] and s['req'] == 1, s


OLD_CALL = '''
class T
{
    bool Run(ConstructionBase cb, ItemBase tool)
    {
        EConstructionInfoCategories cat;
        return cb.CanBuildPartEx("x", tool, cat);
    }
}
'''


def test_old_call_to_changed_method_breaks_on_exp():
    r = scan(OLD_CALL)
    assert any('CanBuildPartEx' in m for m in hits(r, 'BREAK_EXP')), r


MISSING_ARG = '''
modded class ConstructionPart
{
    void Later(EntityAI parent, vector pos)
    {
        PlayConstructionParticle(parent, pos);
    }
}
'''


def test_call_missing_new_required_arg_breaks_on_exp():
    r = scan(MISSING_ARG)
    assert any('PlayConstructionParticle' in m for m in hits(r, 'BREAK_EXP')), r


DEFAULTED = '''
modded class CodeLockComponent
{
    void Later(string pin)
    {
        SetLockCode(pin, false);
        ValidatePIN(pin);
    }
}
'''


def test_call_still_fits_with_new_defaults_is_not_reported():
    r = scan(DEFAULTED)
    assert not any('SetLockCode' in m or 'ValidatePIN' in m for lv in r if lv.split('_')[0] in ('BREAK', 'RISK', 'INFO') for m in r[lv]), r


NEW_CALL = '''
class T
{
    bool Run(ConstructionBase cb, ConstructionPartBuildData data)
    {
        return cb.CanBuildPartEx("x", data);
    }
}
'''


def test_call_with_new_signature_is_not_reported():
    r = scan(NEW_CALL)
    assert not any('CanBuildPartEx' in m for lv in r if lv.split('_')[0] in ('BREAK', 'RISK', 'INFO') for m in r[lv]), r


OWN = '''
class MyBuilder
{
    bool CanBuildPartEx(string name, ItemBase tool, int cat) { return true; }
    bool Run(ItemBase tool)
    {
        return CanBuildPartEx("x", tool, 0);
    }
}
'''


def test_mod_own_method_of_same_name_is_not_reported():
    r = scan(OWN)
    assert not any('CanBuildPartEx' in m for lv in r if lv.split('_')[0] in ('BREAK', 'RISK', 'INFO') for m in r[lv]), r


if __name__ == '__main__':
    fails = 0
    for k, f in sorted(globals().items()):
        if k.startswith('test_') and callable(f):
            try:
                f()
                print('ok', k)
            except Exception as e:
                fails += 1
                print('FAIL', k, type(e).__name__, str(e)[:300])
    sys.exit(1 if fails else 0)
