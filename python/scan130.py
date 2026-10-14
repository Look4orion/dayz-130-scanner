"""Static 1.30 compatibility scan of mod scripts against the vanilla 1.29 -> 1.30 diff.
Usage: scan130.py vanilla.json --pbo mods.tsv <mods root> <out.json>   (reads the PBOs directly)
   or: scan130.py vanilla.json <modsrc dir> <out.json> [mods.tsv <mods root>]   (extract.py output)
With mods.tsv and the mods root, CfgMods script paths are checked too."""
import sys, os, json, re, glob
sys.path.insert(0, os.path.dirname(__file__))
from enfparse import parse, strip, preprocess, nocomment, call_args, call_types, sig_fits, V129, V130

V = json.load(open(sys.argv[1]))
A, B = V['129'], V['130']
if sys.argv[2] == '--pbo':
    SRC, OUT = None, sys.argv[5]
    PATHS = sys.argv[3:5]
else:
    SRC, OUT = sys.argv[2], sys.argv[3]
    PATHS = sys.argv[4:6] if len(sys.argv) >= 6 else None


def chain(ix, name, seen=None):
    out = []
    seen = seen or set()
    while name and name in ix and name not in seen:
        seen.add(name)
        out.append(name)
        name = ix[name]['base']
    return out


def find_method(ix, cls, meth):
    for c in chain(ix, cls):
        ms = ix[c]['methods'].get(meth)
        if ms:
            return c, ms
    return None, None


def has_field(ix, cls, f):
    return any(f in ix[c]['fields'] for c in chain(ix, cls))


def sig(m):
    return tuple(m['params'])


def names(ix):
    out = set(ix)
    for c in ix.values():
        out.update(c['methods'])
        out.update(c['fields'])
    return out


# Names defined anywhere in vanilla (classes, methods, fields): a usage of these is not "removed" / "new".
ALL129, ALL130 = names(A), names(B)

REMOVED_CLASSES = {c for c in A if c not in B}
NEW_CLASSES = {c for c in B if c not in A}
# Methods and fields that exist nowhere in 1.29 vanilla: code using them does not compile on 1.29
# (unless another mod defines the name, which the scan checks).
NEW_METHODS = {}  # name -> "Class.method()"
for cn, c in B.items():
    for m in c['methods']:
        if m not in ALL129:
            NEW_METHODS.setdefault(m, cn + '.' + m + '()')

# Methods vanilla ADDED in 1.30 (name not on that class in 1.29). A mod method of the same name
# on an ancestor or descendant now collides with it.
CHILDREN = {}
for cn, c in B.items():
    if c['base']:
        CHILDREN.setdefault(c['base'], []).append(cn)


def descendants(cn):
    out, todo = [], [cn]
    seen = set()
    while todo:
        x = todo.pop()
        for ch in CHILDREN.get(x, []):
            if ch not in seen:
                seen.add(ch)
                out.append(ch)
                todo.append(ch)
    return out


def added_in_130(cn, m):
    return m in B.get(cn, {}).get('methods', {}) and m not in A.get(cn, {}).get('methods', {})


LOWER130 = {cn.lower(): cn for cn in B}


def is_subtype(sub, sup):
    return sub == sup or (sub in LOWER130 and any(x.lower() == sup for x in chain(B, LOWER130[sub])))


def overrides_cleanly(cn, m, ovs):
    """Vanilla's new cn.m() is a valid override of the mod's m(): same parameters, and its return
    type is the mod's or a subclass of it (Code Lock's ItemBase GetCodeLock() vs 1.30's
    DigitalCodeLock Fence.GetCodeLock() compiles, measured 2026-10-08)."""
    return all(any(sig(o) == sig(v) and is_subtype(v['ret'], o['ret']) for o in ovs) for v in B[cn]['methods'][m])
REMOVED_MEMBERS = {}  # name -> "Class.member"
for cn, c in A.items():
    if cn not in B:
        continue
    for m in c['methods']:
        if find_method(B, cn, m)[0] is None and m not in ALL130:
            REMOVED_MEMBERS.setdefault(m, cn + '.' + m + '()')
    for f in c['fields']:
        if not has_field(B, cn, f) and f not in ALL130:
            REMOVED_MEMBERS.setdefault(f, cn + '.' + f)

# Methods public in 1.29 that 1.30 made protected/private, where no 1.30 class keeps a public one of that name.
PUBLIC130 = {m for c in B.values() for m, ss in c['methods'].items() if any(s.get('access', 'public') == 'public' for s in ss)}
NOW_PROTECTED = {}  # name -> "Class.method"
for cn, c in A.items():
    for m, ss in c['methods'].items():
        s30 = B.get(cn, {}).get('methods', {}).get(m)
        if s30 and m not in PUBLIC130 and any(s.get('access', 'public') == 'public' for s in ss):
            NOW_PROTECTED.setdefault(m, cn + '.' + m + '()')

# [Obsolete] methods in 1.30 (vanilla.py collects them)
OBSOLETE = set(V['obsolete130'])
OBS_DEFS = V.get('obsoleteDefs130', {})  # "Class.method" -> [{n, req, stub, params}]
# Argument types vanilla still calls each obsolete name with ('' = unknown), calls that fit a current overload left out.
OBS_CALLS = {n: [tuple(c) for c in a] for n, a in V.get('obsoleteCalls130', {}).items()}
# Parameter lists of current (not obsolete) methods sharing an obsolete name: a call that fits one may be one of them.
LIVE_SIGS = {}
LIVE_CLASS = {}  # first class (by name) with a current method of that name
for _cn in sorted(B):
    for _m, _ss in B[_cn]['methods'].items():
        if _m in OBSOLETE:
            live = [s['params'] for s in _ss if not s.get('obsolete')]
            LIVE_SIGS.setdefault(_m, []).extend(live)
            if live:
                LIVE_CLASS.setdefault(_m, _cn)
# Obsolete overrides with their own, more specific note in PATTERNS.
OBS_NOTED = {'OnCEUpdate', 'CreateFrontLight', 'CreateRearLight', 'GetNoiseReduction', 'GetNoiseReductionByWeather'}


def obs_fits(d, call):
    return sig_fits(call, d['params'], d['req'])


def obs_called(key, params):
    """Whether 1.30 vanilla still calls the obsolete Class.method with these parameter types."""
    ds = OBS_DEFS.get(key, [])
    ds = [d for d in ds if d['params'] == list(params)] or [d for d in ds if d['n'] == len(params)] or ds
    return not ds or any(obs_fits(d, c) for d in ds for c in OBS_CALLS.get(key.split('.')[1], ()))

# Matched against the code a 1.30 server compiles (inactive #ifdef branches and comments removed).
PATTERNS = [
    ('RISK', 'modded class GameConstants: fails to compile on 1.30 Experimental 164014; reported fixed on the playtest build and Bohemia says resolved for 1.30 stable (DZEXP-93). Check it compiles once stable ships',re.compile(r'modded\s+class\s+GameConstants\b')),
    ('RISK', 'ChangeGameFocus with no device (global focus freezes input on 1.30 client)', re.compile(r'\bChangeGameFocus\s*\(\s*(?:[^,();]|\([^()]*\))*\)')),
    ('RISK', 'GetFluidCapacityScript returns int on 1.30', re.compile(r'\bGetFluidCapacityScript\b')),
    # Silent breakers: compile on 1.30, but vanilla no longer calls or reads them.
    ('RISK', 'overrides OnCEUpdate(), which 1.30 never calls (use OnCEIterate(currentTime, elapsedTime))', re.compile(r'\boverride\s+void\s+OnCEUpdate\s*\(')),
    ('INFO', 'overrides CarScript.CreateFrontLight/CreateRearLight, which 1.30 never calls: the car gets vanilla default headlights (VehicleLightsComponent), not its own brightness/range/colour', re.compile(r'\boverride\s+\w+\s+Create(?:Front|Rear)Light\s*\(')),
    ('RISK', 'AddExplosionEffectForSurface: 1.30 never reads these registrations (surface effects moved to AmmoTypes)', re.compile(r'\bAddExplosionEffectForSurface\s*\(')),
    ('RISK', 'overrides the old weather noise reduction, which 1.30 vanilla no longer calls (it calls the ...Ex versions)', re.compile(r'\boverride\s+\w+\s+GetNoiseReduction(?:ByWeather)?\s*\(')),
    ('INFO', 'uses ActionFillBottleBase/CCTWaterSurface, obsolete in 1.30 (vanilla now uses ActionObtainLiquidBase/CCTLiquid)', re.compile(r'\b(?:ActionFillBottleBase|CCTWaterSurface)\b')),
    ('INFO', 'Is3rdPersonDisabled() is obsolete in 1.30 and reads the vehicles-only third-person mode as enabled', re.compile(r'\bIs3rdPersonDisabled\s*\(')),
    ('INFO', 'CreateInInventory now refuses items that do not fit (no log line)', re.compile(r'\bCreateInInventory\s*\(')),
    ('INFO', 'Fill() lands a frame late on 1.30', re.compile(r'\.\s*Fill\s*\(\s*CarFluid')),
]
# Matched against the whole file (directives included).
RAW_PATTERNS = [
    ('BREAK', '#include "$profile:..." silently does nothing on 1.30 (DZEXP-85)', re.compile(r'#include\s+"\$profile', re.I)),
    ('RISK', '#ifdef DAYZ_1_30 switches the code off again on 1.31 (use #ifndef DAYZ_1_29)', re.compile(r'^\s*#\s*if(?:n?def)?\s+(?:defined\s*\(?\s*)?DAYZ_1_30\b', re.M)),
    ('RISK', 'BUILD_EXPERIMENTAL used as a version gate: it is gone on 1.30 stable', re.compile(r'^\s*#\s*if(?:n?def)?\s+(?:defined\s*\(?\s*)?BUILD_EXPERIMENTAL\b', re.M)),
]
# Removed names that are also ordinary words: only count them with supporting context in the same file.
GENERIC = {
    'other': r'\bCarContactData\b',
    'impulse': r'\bCarContactData\b',
    'localPos': r'\bCarContactData\b',
    'Settings': r'(?:\bnew\s+Settings\b|\bSettings\s+\w+\s*[;=,)]|\bSettings\s*\.)',
    'GameSettings': r'(?:\bnew\s+GameSettings\b|\bGameSettings\s+\w+\s*[;=,)]|\bGameSettings\s*\.)',
}
IDENT = re.compile(r'\b[A-Za-z_]\w*\b')
# Only an admin's debug spawn runs these, and the parts go to attachment slots.
SKIP_IN_DEBUG_SPAWN = {'CreateInInventory now refuses items that do not fit (no log line)'}
DEBUG_SPAWN = re.compile(r'\bOnDebugSpawn\s*\([^)]*\)\s*\{')
# FindFile calls are checked one at a time: flags -1 is the DZEXP-134 workaround.
FF_PROFILE_MSG = 'FindFile on $profile/$mission/$saves lists the game folder on 1.30 (DZEXP-134)'
FF_MSG = 'FindFile used (folder listing broken for prefixed/absolute paths on 1.30)'
FF_FIXED_MSG = 'FindFile passes flags -1, the DZEXP-134 workaround: lists $profile:/$mission: on 1.30'
FF_129_MSG = ('FindFile with flags -1 lists nothing on 1.29, and the call has no retry '
              '(retry with FindFileFlags.ALL when -1 finds nothing, or gate with #ifdef DAYZ_1_29)')
FF_CALL = re.compile(r'\bFindFile\s*\(')
FF_PREFIXED = re.compile(r'\$(profile|mission|saves)', re.I)
MINUS_ONE = re.compile(r'-\s*1')
FLAG_ARG = re.compile(r'(?:\w+\s*\.\s*)*(\w+)\s*(\(.*\))?', re.S)
FUNC_HEAD = re.compile(r'\b(\w+)\s*\(([^;{}()]*)\)\s*\{')
BLOCK_WORDS = {'if', 'while', 'for', 'foreach', 'switch', 'catch', 'return'}
SCRIPT_PATH_MSG = 'CfgMods script path with backslashes: 1.30 compiles none of these scripts, silently'
OTHER_PATH_MSG = ("CfgMods script path with backslashes into another mod's folder: 1.30 skips the entry, so code that "
                  "needs that mod's scripts (often its #define for optional support) can compile out")


def debug_spans(src):
    spans = []
    for m in DEBUG_SPAWN.finditer(src):
        depth, i = 1, m.end()
        while i < len(src) and depth:
            if src[i] == '{':
                depth += 1
            elif src[i] == '}':
                depth -= 1
            i += 1
        spans.append((m.start(), i))
    return spans


def method_bodies(src, name):
    out = []
    for m in re.finditer(r'\b' + name + r'\s*\([^;{}]*\)\s*\{', src):
        depth, i = 1, m.end()
        while i < len(src) and depth:
            if src[i] == '{':
                depth += 1
            elif src[i] == '}':
                depth -= 1
            i += 1
        out.append(src[m.end():i])
    return out


def enclosing_function(src, heads, pos):
    """(name, parameters, body start) of the function whose body holds src[pos], or None."""
    for h in reversed(heads):
        if h.end() > pos:
            continue
        if h.group(1) not in BLOCK_WORDS and same_block(src, h.end(), pos):
            return h.group(1), [x.strip() for x in h.group(2).split(',')], h.end()
    return None


def flags_minus_one(a, modsrc, src, heads, pos, memo):
    """A FindFile flags argument that is -1: the literal, a const or static the mod sets to -1, a
    method of the mod that returns -1, or a variable or parameter of the calling function that the
    function sets to -1 or that its callers pass -1 into."""
    if a.startswith('FindFileFlags'):
        return False
    if MINUS_ONE.fullmatch(a):
        return True
    m = FLAG_ARG.fullmatch(a)
    if not m:
        return False
    name = m.group(1)
    if m.group(2) is not None:
        if ('ret', name) not in memo:
            memo[('ret', name)] = any(re.search(r'\breturn\s*-\s*1\s*;', b) for b in method_bodies(modsrc, name))
        return memo[('ret', name)]
    if ('decl', name) not in memo:
        memo[('decl', name)] = bool(re.search(r'\b(?:const|static)\b[^;{}=()]*\b' + name + r'\s*=\s*-\s*1\s*;', modsrc))
    if memo[('decl', name)]:
        return True
    if '.' in a:
        return False
    fn = enclosing_function(src, heads, pos)
    if not fn:
        return False
    fname, params, start = fn
    if re.search(r'\b' + name + r'\s*=\s*-\s*1\b', src[start:pos]):
        return True
    idx = [k for k, x in enumerate(params) if re.search(r'\b' + name + r'\s*(?:=.*)?$', x)]
    if not idx:
        return False
    key = ('pass', fname, idx[0])
    if key not in memo:
        memo[key] = False
        for c in re.finditer(r'\b' + fname + r'\s*\(', modsrc):
            got = call_args(modsrc, c.end() - 1)
            if got and len(got) > idx[0] and MINUS_ONE.fullmatch(got[idx[0]].strip()):
                memo[key] = True
                break
    return memo[key]


def findfile_hits(src, modsrc, memo):
    """(offset, prefixed path, flags -1) for each FindFile call in src."""
    out = []
    heads = None
    for m in FF_CALL.finditer(src):
        args = call_args(src, m.end() - 1)
        end = src.find(';', m.end())
        prefixed = bool(FF_PREFIXED.search(src[m.end():end if end >= 0 else len(src)]))
        fixed = False
        if args and len(args) >= 4:
            if heads is None:
                heads = list(FUNC_HEAD.finditer(src))
            fixed = flags_minus_one(args[3].strip(), modsrc, src, heads, m.start(), memo)
        out.append((m.start(), prefixed, fixed))
    return out


def same_block(src, a, b):
    """src[b] is in the block that holds src[a] (or deeper): the braces between never close it."""
    depth = 0
    for c in src[a:b]:
        if c == '{':
            depth += 1
        elif c == '}':
            depth -= 1
            if depth < 0:
                return False
    return True


def is_fallback(src, hits, k):
    """An unfixed call after a -1 call in the same function: the retry of the version-proof fix."""
    return any(fixed and at < hits[k][0] and same_block(src, at, hits[k][0]) for at, _, fixed in hits[:k])


def has_retry(src, hits, k):
    """A -1 call followed by another call in the same function (1.29 gets its answer there)."""
    return any(not fixed and same_block(src, hits[k][0], at) for at, _, fixed in hits[k + 1:])


def owns_path(pbos, path):
    p = path.replace('\\', '/').strip('/').lower()
    for pb, note in pbos.items():
        pre = (note.get('prefix') or pb[:-4]).replace('\\', '/').strip('/').lower()
        if pre and (p == pre or p.startswith(pre + '/')):
            return True
    return False


def load(raw):
    out = {'raw': raw}
    for tag, defs in (('130', V130), ('129', V129)):
        src = preprocess(nocomment(raw), defs)
        try:
            cls = parse(src)
        except Exception:
            cls = []
        out[tag] = (src, cls)
    return out


def own_classes(parsed):
    """Classes the mod declares (not modded), by name."""
    out = {}
    for _, p in parsed:
        for tag in ('130', '129'):
            for c in p[tag][1]:
                if not c['modded']:
                    out.setdefault(c['name'], c)
    return out


def vanilla_base(c, modclasses, ix):
    """The vanilla class (in ix) a mod class is, or derives from through the mod's own classes."""
    if c['modded']:
        return c['name']
    b, seen = c['base'], set()
    while b and b in modclasses and b not in ix and b not in seen:
        seen.add(b)
        b = modclasses[b]['base']
    return b if b in ix else None


def scan_files(files):
    res = {'BREAK': {}, 'RISK': {}, 'INFO': {}, 'BREAK_129': {}, 'RISK_129': {}}

    def add(level, msg, where):
        res[level].setdefault(msg, [])
        if len(res[level][msg]) < 100000:
            res[level][msg].append(where)

    parsed = [(rel, load(src)) for rel, src in files]
    modclasses = own_classes(parsed)
    # methods and fields the mod declares in any of its files (overrides excluded)
    mod_own = set()
    mod_overrides = set()  # a call to one of these may reach the mod's own body
    for _, p in parsed:
        for tag in ('130', '129'):
            for c in p[tag][1]:
                mod_own.update(m for m, o in c['methods'].items() if not any(v['override'] for v in o))
                mod_overrides.update(m for m, o in c['methods'].items() if any(v['override'] for v in o))
                mod_own.update(c['fields'])
    mod30 = '\n'.join(p['130'][0] for _, p in parsed)
    mod29 = '\n'.join(p['129'][0] for _, p in parsed)
    all29 = 'FindFileFlags.ALL' in mod29
    memo30, memo29 = {}, {}
    for rel, p in parsed:
        src30, cls = p['130']
        src29, cls29 = p['129']
        for level, msg, rx in RAW_PATTERNS:
            for m in rx.finditer(p['raw']):
                add(level, msg, rel + ':' + str(p['raw'].count('\n', 0, m.start()) + 1))
        spans = debug_spans(src30)
        for level, msg, rx in PATTERNS:
            for m in rx.finditer(src30):
                if msg in SKIP_IN_DEBUG_SPAWN and any(a <= m.start() < b for a, b in spans):
                    continue
                add(level, msg, rel + ':' + str(src30.count('\n', 0, m.start()) + 1))
        hits = findfile_hits(src30, mod30, memo30)
        for k, (at, prefixed, fixed) in enumerate(hits):
            where = rel + ':' + str(src30.count('\n', 0, at) + 1)
            if fixed:
                add('INFO', FF_FIXED_MSG, where)
                continue
            if is_fallback(src30, hits, k):
                continue
            if prefixed:
                add('RISK', FF_PROFILE_MSG, where)
            add('RISK', FF_MSG, where)
        if not all29:
            hits29 = findfile_hits(src29, mod29, memo29)
            for k, (at, _, fixed) in enumerate(hits29):
                if fixed and not has_retry(src29, hits29, k):
                    add('RISK_129', FF_129_MSG, rel + ':' + str(src29.count('\n', 0, at) + 1))

        # ---- 1.30: what a 1.30 server compiles from this file
        for c in cls:
            name = c['name']
            if c['modded']:
                if name in REMOVED_CLASSES:
                    add('BREAK', 'modded class of class removed in 1.30: ' + name, rel)
            elif c['base'] in REMOVED_CLASSES:
                add('BREAK', 'class extends class removed in 1.30: ' + c['base'], rel + ' (' + name + ')')
            vbase = vanilla_base(c, modclasses, A)
            if vbase and vbase in B:
                # new-in-1.30 vanilla method with the same name as one this mod adds (no override)
                for mn, ovs in c['methods'].items():
                    if any(ov['override'] for ov in ovs) or mn in (name, vbase) or mn.startswith('~'):
                        continue  # overrides, constructors and destructors
                    anc = [x for x in chain(B, vbase) if added_in_130(x, mn)]
                    desc = [x for x in descendants(vbase) if added_in_130(x, mn) and not overrides_cleanly(x, mn, ovs)] if c['modded'] else []
                    if anc:
                        add('BREAK', 'adds %s.%s(), but 1.30 vanilla now defines %s() in %s (name clash)' % (name, mn, mn, anc[0]), rel)
                    elif desc:
                        add('BREAK', 'adds %s() to every %s, but 1.30 vanilla now defines %s() in subclass %s (name clash)' % (mn, name, mn, ', '.join(desc[:3])), rel)
            if not vbase or vbase not in A:
                continue
            for mn, ovs in c['methods'].items():
                for ov in ovs:
                    if not ov['override']:
                        continue
                    vc, ms29 = find_method(A, vbase, mn)
                    if not vc:
                        continue
                    s = sig(ov)
                    if s not in {sig(m) for m in ms29}:
                        continue  # mod didn't match 1.29 either (parser noise, mod-side base, or 1.30 code); skip
                    vc30, ms30 = find_method(B, vbase if vbase in B else vc, mn)
                    if not vc30:
                        add('BREAK', 'overrides ' + vc + '.' + mn + '() which no longer exists in 1.30', rel)
                    elif s not in {sig(m) for m in ms30}:
                        new = ' | '.join('(' + ', '.join(m['params']) + ')' for m in ms30)
                        add('BREAK', 'override signature changed: ' + vc30 + '.' + mn + '(' + ', '.join(s) + ') is now ' + new, rel)
                    else:
                        r29 = {m['ret'] for m in ms29 if sig(m) == s}
                        r30 = {m['ret'] for m in ms30 if sig(m) == s}
                        if r29 and r30 and not (r29 & r30):
                            add('BREAK', 'override return type changed: ' + vc30 + '.' + mn + ' ' + '/'.join(sorted(r29)) + ' -> ' + '/'.join(sorted(r30)), rel)
                        if mn not in OBS_NOTED and any(m.get('obsolete') for m in ms30 if sig(m) == s):
                            live30 = {sig(m) for m in ms30 if not m.get('obsolete')}
                            also = [sig(o) for o in ovs if o['override'] and sig(o) in live30]
                            what = 'overrides ' + vc30 + '.' + mn + '(' + ', '.join(s) + '), marked [Obsolete] in 1.30'
                            if also:
                                add('INFO', what + '; the same class also overrides the current (' + ', '.join(also[0]) + ') version, so nothing is lost', rel)
                            elif obs_called(vc30 + '.' + mn, s):
                                add('INFO', what, rel)
                            else:
                                add('RISK', what + ' and never called by 1.30 vanilla: the override does not run', rel)
        body = strip(src30)
        own = set(modclasses) | mod_own
        for c in cls:
            own.update(c['methods'])
            own.update(c['fields'])
        toks = set(IDENT.findall(body))
        for t in toks & set(REMOVED_MEMBERS):
            if t in GENERIC and not re.search(GENERIC[t], body):
                continue
            if t not in own:
                add('RISK', 'uses ' + REMOVED_MEMBERS[t] + ', removed in 1.30', rel)
        for t in toks & REMOVED_CLASSES:
            if t in GENERIC and not re.search(GENERIC[t], body):
                continue
            if t not in own:
                add('RISK', 'uses class ' + t + ', removed in 1.30', rel)
        for t in toks & OBSOLETE:
            if t in own:
                continue
            calls = call_types(body, t)
            mine = [d for k, v in OBS_DEFS.items() if k.split('.')[1] == t for d in v]
            if mine:
                calls = {c for c in calls if any(obs_fits(d, c) for d in mine)}
            if not calls:
                continue  # no call, or only the current overloads are called
            ar = {c for c in calls if not any(sig_fits(c, p, len(p)) for p in LIVE_SIGS.get(t, []))}
            ds = [d for d in mine if any(obs_fits(d, c) for c in ar)]
            if not ar:
                obs = sorted(k for k in OBS_DEFS if k.split('.')[1] == t)
                add('INFO', 'calls ' + t + '(): ' + ', '.join(obs) + '() is [Obsolete] in 1.30 but ' + LIVE_CLASS[t] + '.' + t + '() is not; check which one this call reaches', rel)
            elif ds and all(d['stub'] for d in ds) and t not in mod_overrides:
                add('RISK', 'calls ' + t + '(), which 1.30 left as a placeholder (empty, or returns a fixed value): it compiles but does nothing', rel)
            else:
                add('INFO', 'calls ' + t + '() marked [Obsolete] in 1.30', rel)
        for t in toks & set(NOW_PROTECTED):
            if t in own:
                continue
            for m in re.finditer(r'(\w+)\s*\.\s*' + t + r'\s*\(', body):
                if m.group(1) not in ('super', 'this'):
                    add('RISK', 'calls ' + NOW_PROTECTED[t] + ' from outside the class; 1.30 made it protected (unverified whether that compiles)', rel)
                    break

        # ---- 1.29: does what a 1.29 server compiles from this file use anything 1.29 lacks?
        own29 = set(modclasses)
        for c in cls29:
            own29.update(c['methods'])
            own29.update(c['fields'])
        for c in cls29:
            name = c['name']
            if c['modded'] and name in NEW_CLASSES and name not in GLOBAL_CLASSES:
                add('BREAK_129', 'modded class ' + name + ', which only exists from 1.30', rel)
            elif not c['modded'] and c['base'] in NEW_CLASSES and c['base'] not in GLOBAL_CLASSES:
                add('BREAK_129', 'class extends ' + c['base'] + ', which only exists from 1.30', rel + ' (' + name + ')')
            vbase = vanilla_base(c, modclasses, B) or vanilla_base(c, modclasses, A)
            if not vbase:
                continue
            # nearest class 1.29 has: a class new in 1.30 still inherits 1.29 methods from its old ancestors
            base29 = next((x for x in chain(B, vbase) if x in A), vbase if vbase in A else None)
            added = set()  # methods mods add (not override) to this class's vanilla chain or the mod's own bases
            for x in chain(A, vbase) + chain(B, vbase):
                added |= MODDED_ADDS.get(x, set())
            b, seen = c['base'], set()
            while b and b in modclasses and b not in seen:
                seen.add(b)
                added |= {m for m, o in modclasses[b]['methods'].items() if not any(v['override'] for v in o)}
                b = modclasses[b]['base']
            for mn, ovs in c['methods'].items():
                for ov in ovs:
                    if not ov['override'] or mn in added:
                        continue
                    vc, ms29 = find_method(A, base29, mn) if base29 else (None, None)
                    vc30, ms30 = find_method(B, vbase, mn)
                    s = sig(ov)
                    if not vc and vc30 and s in {sig(m) for m in ms30}:
                        add('BREAK_129', 'overrides ' + vc30 + '.' + mn + '(), which only exists from 1.30', rel)
                    elif vc and vc30 and s not in {sig(m) for m in ms29} and s in {sig(m) for m in ms30}:
                        old = ' | '.join('(' + ', '.join(m['params']) + ')' for m in ms29)
                        add('BREAK_129', 'override uses the 1.30 signature of ' + vc30 + '.' + mn + '(' + ', '.join(s) + '); 1.29 has ' + old, rel)
        body29 = strip(src29)
        toks29 = set(IDENT.findall(body29))
        # methods only, called as name(...): new field names (ammoType, orientation, OFF) are ordinary words
        for t in toks29 & set(NEW_METHODS):
            if t in own29 or t in GLOBAL_NAMES:
                continue
            if re.search(r'\b' + t + r'\s*\(', body29):
                add('RISK_129', 'calls ' + NEW_METHODS[t] + ', which only exists from 1.30', rel)
        for t in toks29 & NEW_CLASSES:
            if t not in own29 and t not in GLOBAL_CLASSES:
                add('RISK_129', 'uses class ' + t + ', which only exists from 1.30', rel)
    return res


def text(data):
    return data.decode('utf-8', 'replace').replace('\r\n', '\n').replace('\r', '\n')


# FILES: n -> [(path as in the report, script text)]
if SRC is None:
    from extract import read_mods
    manifest, _raw = read_mods(PATHS[0], PATHS[1])
    FILES = {n: [(p, text(d)) for p, d, is_c in fs if is_c] for n, fs in _raw.items()}
    del _raw
else:
    manifest = json.load(open(os.path.join(SRC, 'manifest.json')))
    FILES = {}
    for n in manifest:
        FILES[n] = []
        for f in glob.glob(os.path.join(SRC, n, '**', '*.c'), recursive=True):
            if os.path.isfile(f):
                with open(f, 'rb') as fh:
                    FILES[n].append((os.path.relpath(f, SRC).replace('\\', '/'), text(fh.read())))

# Names any scanned mod declares: another mod may mod or call them, so they don't count as "new in 1.30".
GLOBAL_CLASSES, GLOBAL_METHODS, GLOBAL_NAMES = set(), set(), set()
MODDED_ADDS = {}  # vanilla class -> methods some mod adds to it with "modded class" (not override)
for fs in FILES.values():
    for _, src in fs:
        try:
            cls = parse(src)
        except Exception:
            continue
        for c in cls:
            if not c['modded']:
                GLOBAL_CLASSES.add(c['name'])
            for mn, ovs in c['methods'].items():
                if not any(o['override'] for o in ovs):
                    GLOBAL_METHODS.add(mn)
                    if c['modded']:
                        MODDED_ADDS.setdefault(c['name'], set()).add(mn)
            GLOBAL_NAMES.update(c['fields'])
GLOBAL_NAMES |= GLOBAL_CLASSES | GLOBAL_METHODS

SCRIPT_PATHS = {}
if PATHS:
    from modpaths import backslash_paths
    for line in open(PATHS[0], encoding='utf-8'):
        if line.strip():
            n, kind, m = (x.strip() for x in line.rstrip('\n').split('\t'))
            SCRIPT_PATHS[n] = backslash_paths(os.path.join(PATHS[1], m))

report = {}
for n, info in manifest.items():
    files = FILES[n]
    r = scan_files(files) if files else {'BREAK': {}, 'RISK': {}, 'INFO': {}, 'BREAK_129': {}, 'RISK_129': {}}
    for pbo, mod_, path in SCRIPT_PATHS.get(n, []):
        if mod_ and mod_.lower().endswith('scriptmodule'):
            if owns_path(info['pbos'], path):
                r['BREAK'].setdefault(SCRIPT_PATH_MSG, []).append(pbo + ': ' + mod_ + ' = ' + path)
            else:
                r['RISK'].setdefault(OTHER_PATH_MSG, []).append(pbo + ': ' + mod_ + ' = ' + path)
    r['unscanned_pbos'] = [k for k, p in info['pbos'].items() if p['unreadable']]
    r['packed_pbos'] = [k for k, p in info['pbos'].items() if p['compressed']]
    r['mod'] = info['mod']
    r['kind'] = info['kind']
    r['files'] = len(files)
    report[n] = r
json.dump(report, open(OUT, 'w'), indent=1)
print('removed classes', len(REMOVED_CLASSES), 'removed members', len(REMOVED_MEMBERS), 'obsolete', len(OBSOLETE),
      'new classes', len(NEW_CLASSES), 'new methods', len(NEW_METHODS), 'now protected', len(NOW_PROTECTED))
for n, r in sorted(report.items(), key=lambda kv: int(kv[0])):
    print(n, r['mod'], 'B=%d R=%d I=%d | 1.29: B=%d R=%d' % (len(r['BREAK']), len(r['RISK']), len(r['INFO']), len(r['BREAK_129']), len(r['RISK_129'])),
          'unscanned:' + ','.join(r['unscanned_pbos']) if r['unscanned_pbos'] else '')
