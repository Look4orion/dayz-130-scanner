import os, re

ROOT = os.path.join(os.path.dirname(__file__), '..', '..')
HTML = open(os.path.join(ROOT, 'docs', 'index.html'), encoding='utf-8').read()
APP = open(os.path.join(ROOT, 'docs', 'js', 'app.js'), encoding='utf-8').read()


def test_exp_legend_hidden_until_a_scan_has_exp():
    for part in ('exp-legend-term', 'exp-legend-text'):
        assert re.search(r'id="%s"[^>]*\bhidden\b' % part, HTML), part
        assert "$('%s').hidden = !exp" % part in APP, part


def test_status_says_when_there_is_no_newer_exp():
    assert '(no newer experimental build)' in APP


if __name__ == '__main__':
    for n, f in list(globals().items()):
        if n.startswith('test_'):
            f()
            print('ok', n)
