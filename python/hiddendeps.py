"""Undeclared mod-to-mod dependencies: what a mod USES, not what its requiredAddons declare.
Usage: hiddendeps.py mods.tsv <mods_root> <modsrc dir> <vanilla.json> <vanilla config root> <deps.json> <out.json>

Config: a class whose base class is defined only by another mod (vanilla classes excluded).
Scripts: a class name defined only by another mod's scripts, used in this mod's scripts.
  'hard'     = used outside any #ifdef/#ifndef/#if block, so it must compile against that mod
  'optional' = used only inside such blocks (usually guarded by that mod's CfgMods define)"""
import sys, os, re, glob, json, struct
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from deps import pbo_files, rap_class, read_cstr_buf, cint, strip_comments
from enfparse import parse

MIN_NAME = 5


# ---- config classes: (defined, bases used) ----
def rap_walk(b, off, defined, bases, depth=0):
    if depth > 40:
        return
    inherited, _ = read_cstr_buf(b, off)
    body = rap_class(b, off)
    for name, (kind, val) in body.items():
        if kind == 'class':
            inh, _ = read_cstr_buf(b, val)
            defined.add(name.lower())
            if inh:
                bases.add(inh.lower())
            rap_walk(b, val, defined, bases, depth + 1)


CLS_DEF = re.compile(r'\bclass\s+(\w+)\s*(?::\s*(\w+))?\s*\{')


def cpp_walk(txt, defined, bases):
    s = strip_comments(txt)
    for m in CLS_DEF.finditer(s):
        defined.add(m.group(1).lower())
        if m.group(2):
            bases.add(m.group(2).lower())


def config_classes(mod_dir):
    defined, bases = set(), set()
    for p in sorted(glob.glob(os.path.join(mod_dir, '[Aa]ddons', '*.pbo'))):
        for name, blob in pbo_files(p, {'config.bin', 'config.cpp'}):
            try:
                if name.lower().endswith('.bin'):
                    if blob[:4] == b'\0raP':
                        rap_walk(blob, 16, defined, bases)
                else:
                    cpp_walk(blob.decode('utf-8', 'replace'), defined, bases)
            except Exception:
                pass
    return defined, bases


def vanilla_config(root):
    defined, bases = set(), set()
    for f in glob.glob(os.path.join(root, '**', 'config.cpp'), recursive=True):
        cpp_walk(open(f, encoding='utf-8', errors='replace').read(), defined, bases)
    return defined


# ---- script classes ----
PP_OPEN = re.compile(r'^\s*#\s*(ifdef|ifndef|if)\b')
PP_CLOSE = re.compile(r'^\s*#\s*endif\b')
IDENT = re.compile(r'\b[A-Za-z_]\w*\b')


def guarded_tokens(raw):
    """Return (tokens outside any #if block, tokens inside one). Comments/strings removed per line."""
    hard, opt = set(), set()
    depth = 0
    src = re.sub(r'/\*.*?\*/', ' ', raw, flags=re.S)
    for line in src.split('\n'):
        if PP_OPEN.match(line):
            depth += 1
            continue
        if PP_CLOSE.match(line):
            depth = max(0, depth - 1)
            continue
        if line.lstrip().startswith('#'):
            continue
        line = re.sub(r'//.*', '', line)
        line = re.sub(r'"(?:\\.|[^"\\])*"', '""', line)
        toks = set(IDENT.findall(line))
        (opt if depth else hard).update(toks)
    return hard, opt


def used_as_class(text, c):
    """True if name c appears where a class goes, not as a method, field or comment word."""
    e = re.escape(c)
    pats = [
        r'\b(?:new|extends|ref|autoptr|typename|modded\s+class)\s+' + e + r'\b',
        r'\bclass\s+\w+\s*(?::|extends)\s*' + e + r'\b',
        r'(?<![.\w])' + e + r'\s+[A-Za-z_]\w*\s*(?:[;=,)\[])',          # declaration: C name;
        r'(?<![.\w])' + e + r'\s*\.\s*\w+\s*\(',                          # static call: C.Method(
        r'[<,]\s*' + e + r'\s*[>,]',                                       # template argument
        r'\b(?:AddAction|IsInherited|IsKindOf|CastTo|Cast|RemoveAction)\s*\(\s*' + e + r'\b',
    ]
    return any(re.search(p, text) for p in pats)


def main():
    mods_tsv, mods_root, modsrc, vjson, vcfg_root, deps_json, out = sys.argv[1:8]
    mods = [l.rstrip('\n').split('\t') for l in open(mods_tsv, encoding='utf-8') if l.strip()]
    mods = [(a.strip(), b.strip(), c.strip()) for a, b, c in mods]
    declared = json.load(open(deps_json))['deps']

    # config
    vcfg = vanilla_config(vcfg_root)
    cfg_def, cfg_base = {}, {}
    for n, kind, m in mods:
        d, b = config_classes(os.path.join(mods_root, m))
        cfg_def[m], cfg_base[m] = d, b
    cfg_owner = {}
    for m, d in cfg_def.items():
        for c in d - vcfg:
            cfg_owner.setdefault(c, set()).add(m)

    # scripts
    V = json.load(open(vjson))
    vscript = {c.lower() for c in V['129']} | {c.lower() for c in V['130']}
    scr_def, scr_hard, scr_opt, scr_files = {}, {}, {}, {}
    for n, kind, m in mods:
        defs, hard, opt = set(), set(), set()
        files = [f for f in glob.glob(os.path.join(modsrc, n, '**', '*.c'), recursive=True) if os.path.isfile(f)]
        scr_files[m] = files
        for f in files:
            raw = open(f, encoding='utf-8', errors='replace').read()
            try:
                for c in parse(raw):
                    if not c['modded']:
                        defs.add(c['name'])
            except Exception:
                pass
            h, o = guarded_tokens(raw)
            hard |= h
            opt |= o
        scr_def[m], scr_hard[m], scr_opt[m] = defs, hard, opt
    scr_owner = {}
    for m, d in scr_def.items():
        for c in d:
            if c.lower() not in vscript and len(c) >= MIN_NAME:
                scr_owner.setdefault(c, set()).add(m)

    report = {}
    for n, kind, m in mods:
        r = {'config': {}, 'script_hard': {}, 'script_optional': {}}
        for base in cfg_base[m] - cfg_def[m]:
            for o in cfg_owner.get(base, ()):
                if o != m:
                    r['config'].setdefault(o, []).append(base)
        own_lower = {c.lower() for c in scr_def[m]}
        cands = []
        for c, owners in scr_owner.items():
            if len(owners) != 1 or c.lower() in own_lower:
                continue
            o = next(iter(owners))
            if o == m:
                continue
            if c in scr_hard[m]:
                cands.append((c, o, 'script_hard'))
            elif c in scr_opt[m]:
                cands.append((c, o, 'script_optional'))
        if cands:
            names = {c for c, _, _ in cands}
            text = []
            for f in scr_files[m]:
                raw = open(f, encoding='utf-8', errors='replace').read()
                if any(nm in raw for nm in names):
                    text.append(re.sub(r'"(?:\\.|[^"\\])*"', '""', re.sub(r'//[^\n]*', '', re.sub(r'/\*.*?\*/', ' ', raw, flags=re.S))))
            text = '\n'.join(text)
            for c, o, k in cands:
                if used_as_class(text, c):
                    r[k].setdefault(o, []).append(c)
        for k in r:
            r[k] = {o: sorted(v)[:6] for o, v in sorted(r[k].items())}
        r['undeclared'] = sorted((set(r['config']) | set(r['script_hard'])) - set(declared.get(m, [])))
        report[m] = r
    json.dump(report, open(out, 'w'), indent=1)
    for m, r in report.items():
        if r['undeclared'] or r['script_optional']:
            print(m)
            for o in r['undeclared']:
                print('   UNDECLARED', o, '| config:', r['config'].get(o, [])[:3], '| script:', r['script_hard'].get(o, [])[:3])
            for o, v in r['script_optional'].items():
                print('   optional  ', o, v[:3])


if __name__ == '__main__':
    main()
