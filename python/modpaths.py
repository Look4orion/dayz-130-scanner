"""List each mod's CfgMods script-module paths and flag backslashes.
Usage: modpaths.py mods.tsv <mods_root>"""
import sys, os, glob, re
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from deps import pbo_files, rap_class, strip_comments


def from_bin(b):
    out = []
    root = rap_class(b, 16)
    key = next((k for k in root if k.lower() == 'cfgmods'), None)
    if not key:
        return out
    for mn, (k, o) in rap_class(b, root[key][1]).items():
        if k != 'class':
            continue
        d = rap_class(b, o)
        dk = next((x for x in d if x.lower() == 'defs'), None)
        if not dk:
            continue
        for dn, (k2, o2) in rap_class(b, d[dk][1]).items():
            if k2 != 'class':
                continue
            for fk, (k3, v) in rap_class(b, o2).items():
                if fk.lower() == 'files' and k3 == 'array':
                    out += [(mn, dn, x) for x in v if isinstance(x, str)]
    return out


def from_cpp(t):
    out = []
    s = strip_comments(t)
    for m in re.finditer(r'class\s+(\w+ScriptModule)\s*\{[^{}]*?files\[\]\s*=\s*\{([^}]*)\}', s, re.S | re.I):
        out += [('?', m.group(1), x) for x in re.findall(r'"([^"]*)"', m.group(2))]
    return out


def backslash_paths(mod_dir):
    """(pbo, module, path) for every CfgMods script path with a backslash; (pbo, None, error) for unreadable PBOs."""
    bad = []
    for p in sorted(glob.glob(os.path.join(mod_dir, '[Aa]ddons', '*.pbo'))):
        paths = []
        try:
            for name, b in pbo_files(p, {'config.bin', 'config.cpp'}):
                paths += from_bin(b) if b[:4] == b'\0raP' else from_cpp(b.decode('utf-8', 'replace'))
        except Exception as e:
            bad.append((os.path.basename(p), None, str(e)))
            continue
        bad += sorted({(os.path.basename(p), d, x) for _, d, x in paths if '\\' in x})
    return bad


if __name__ == '__main__':
    mods = [l.rstrip('\n').split('\t') for l in open(sys.argv[1], encoding='utf-8') if l.strip()]
    for n, kind, m in ((a.strip(), b.strip(), c.strip()) for a, b, c in mods):
        found = backslash_paths(os.path.join(sys.argv[2], m))
        for pbo, _, err in (x for x in found if x[1] is None):
            print('  skip', m, pbo, err)
        bad = sorted({(d, x) for _, d, x in found if d})
        if bad:
            print('%-50s %d backslash path(s): %s' % (m, len(bad), '; '.join('%s=%s' % (d.replace('ScriptModule', ''), x) for d, x in bad[:4])))
