"""Vanilla field declarations whose ';' ended up inside a trailing comment (1.30 ConstructionBase and others)."""
import json, os, sys

sys.path.insert(0, os.path.dirname(__file__))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'python'))
from test_scan_levels import scan, VANILLA  # noqa: E402
from enfparse import parse  # noqa: E402

SRC = '''
class ConstructionBase
{
	protected ref map<string, ref ConstructionPart> m_ConstructionParts //! INSTANCED construction part data;
	protected ref array<ConstructionPart> m_ConstructionPartArray; //ordered array for easier access
	protected int m_Plain;
	protected int m_A, m_B;
	protected ref map<string,
		int> m_Wrapped;
}
'''


def test_parser_keeps_field_without_semicolon():
    f = parse(SRC)[0]['fields']
    assert {'m_ConstructionParts', 'm_ConstructionPartArray', 'm_Plain', 'm_A', 'm_B', 'm_Wrapped'} <= f, f


def test_parser_adds_nothing_extra():
    f = parse(SRC)[0]['fields']
    assert f == {'m_ConstructionParts', 'm_ConstructionPartArray', 'm_Plain', 'm_A', 'm_B', 'm_Wrapped'}, f


def test_data_has_the_five_fields():
    v = json.load(open(VANILLA))
    want = (('ConstructionBase', 'm_ConstructionParts'), ('DynamicMusicPlayer', 'm_LocationsDynamic'),
            ('DynamicMusicPlayer', 'm_RequestedPlaybackMode'), ('DayZPlayerImplement', 'm_StepCounterVegetation'),
            ('TrapSpawnBase', 'm_PlaceableWaterType'))
    for role in ('stable', 'exp'):
        missing = [c + '.' + f for c, f in want if f not in v[role][c]['fields']]
        assert not missing, (role, missing)


USE = '''
modded class Construction
{
    int CountParts()
    {
        return m_ConstructionParts.Count();
    }
}
'''


def test_construction_parts_use_is_not_reported():
    r = scan(USE)
    assert not any('m_ConstructionParts' in m for lv in r if lv.split('_')[0] in ('BREAK', 'RISK', 'INFO') for m in r[lv]), r


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
