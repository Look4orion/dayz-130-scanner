"""Static scan of mod scripts against the vanilla diff from the previous to the current stable build.
Usage: scan130.py vanilla.json --pbo mods.tsv <mods root> <out.json>   (reads the PBOs directly)
   or: scan130.py vanilla.json <modsrc dir> <out.json> [mods.tsv <mods root>]   (extract.py output)
With mods.tsv and the mods root, CfgMods script paths are checked too."""
import sys, os, json, re, glob
sys.path.insert(0, os.path.dirname(__file__))
from enfparse import parse, strip, preprocess, nocomment, call_args, call_types, sig_fits, defines_for

V = json.load(open(sys.argv[1]))
A, B = V['previous'], V['stable']
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
STABLE_DEFS = defines_for(V['versions']['stable'])


def extras(role):
    return {k: V.get(k, {}).get(role, {}) for k in ('workbench', 'obsolete', 'obsoleteDefs', 'obsoleteCalls', 'obsoleteUse')}


class Delta:
    """What changed from one vanilla build (old) to the next (new); messages name the new one by label."""

    def __init__(self, old, new, ex, label, keep_classes=(), old_obsolete=None):
        self.old, self.new, self.label = old, new, label
        # classes new declares only for Workbench: gone for game scripts, not for Workbench-only folders
        self.wb_only = set(ex['workbench'] or [])
        self.only_new_obsolete = old_obsolete is not None
        self.all_new = names(new)
        self.removed_classes = {c for c in old if c not in new and c not in keep_classes}
        self.children = {}
        for cn, c in new.items():
            if c['base']:
                self.children.setdefault(c['base'], []).append(cn)
        self.lower = {cn.lower(): cn for cn in new}
        self.removed_members = {}  # name -> "Class.member"
        for cn, c in old.items():
            if cn not in new:
                continue
            for m in c['methods']:
                if find_method(new, cn, m)[0] is None and m not in self.all_new:
                    self.removed_members.setdefault(m, cn + '.' + m + '()')
            for f in c['fields']:
                if not has_field(new, cn, f) and f not in self.all_new:
                    self.removed_members.setdefault(f, cn + '.' + f)
        # public in old, protected/private in new, where no new class keeps a public one of that name
        public = {m for c in new.values() for m, ss in c['methods'].items() if any(s.get('access', 'public') == 'public' for s in ss)}
        self.now_protected = {}
        for cn, c in old.items():
            for m, ss in c['methods'].items():
                if new.get(cn, {}).get('methods', {}).get(m) and m not in public and any(s.get('access', 'public') == 'public' for s in ss):
                    self.now_protected.setdefault(m, cn + '.' + m + '()')
        self.obsolete = set(ex['obsolete'] or []) - set(old_obsolete or [])
        self.obs_defs = ex['obsoleteDefs'] or {}  # "Class.method" -> [{n, req, stub, params}]
        # Argument types vanilla still calls each obsolete name with ('' = unknown), calls that fit a current overload left out.
        self.obs_calls = {n: [tuple(c) for c in a] for n, a in (ex['obsoleteCalls'] or {}).items()}
        # Methods an obsolete method's message says to use instead ("1.30: use Transport.NeedElectricitySourceDevice").
        self.obs_use = ex['obsoleteUse'] or {}
        # Parameter lists of current (not obsolete) methods sharing an obsolete name: a call that fits one may be one of them.
        self.live_sigs, self.live_class = {}, {}
        for cn in sorted(new):
            for m, ss in new[cn]['methods'].items():
                if m in self.obsolete:
                    live = [s['params'] for s in ss if not s.get('obsolete')]
                    self.live_sigs.setdefault(m, []).extend(live)
                    if live:
                        self.live_class.setdefault(m, cn)

    def descendants(self, cn):
        out, todo = [], [cn]
        seen = set()
        while todo:
            x = todo.pop()
            for ch in self.children.get(x, []):
                if ch not in seen:
                    seen.add(ch)
                    out.append(ch)
                    todo.append(ch)
        return out

    def added(self, cn, m):
        """Vanilla added m to cn (a mod method of that name on an ancestor or descendant now collides)."""
        return m in self.new.get(cn, {}).get('methods', {}) and m not in self.old.get(cn, {}).get('methods', {})

    def is_subtype(self, sub, sup):
        return sub == sup or (sub in self.lower and any(x.lower() == sup for x in chain(self.new, self.lower[sub])))

    def overrides_cleanly(self, cn, m, ovs):
        """Vanilla's new cn.m() is a valid override of the mod's m(): same parameters, and its return
        type is the mod's or a subclass of it (Code Lock's ItemBase GetCodeLock() vs 1.30's
        DigitalCodeLock Fence.GetCodeLock() compiles, measured 2026-10-08)."""
        return all(any(sig(o) == sig(v) and self.is_subtype(v['ret'], o['ret']) for o in ovs) for v in self.new[cn]['methods'][m])

    def obs_called(self, key, params):
        """Whether vanilla still calls the obsolete Class.method with these parameter types."""
        ds = self.obs_defs.get(key, [])
        ds = [d for d in ds if d['params'] == list(params)] or [d for d in ds if d['n'] == len(params)] or ds
        return not ds or any(obs_fits(d, c) for d in ds for c in self.obs_calls.get(key.split('.')[1], ()))


def ver(s):
    return tuple(int(x) for x in re.findall(r'\d+', s)[:3])


# Types stable declares only under #ifdef WORKBENCH (vanilla.py leaves them out of its index): their own check.
WB_ONLY = set(V.get('workbench', {}).get('stable', []))
STABLE = Delta(A, B, extras('stable'), '.'.join(V['versions']['stable'].split('.')[:2]), WB_ONLY)
EXP = None
if 'exp' in V and ver(V['versions']['exp']) > ver(V['versions']['stable']):
    EXP = Delta(B, V['exp'], extras('exp'), 'Exp ' + V['versions']['exp'], old_obsolete=extras('stable')['obsolete'])
    EXP_DEFS = defines_for(V['versions']['exp'])
LEVELS = ('BREAK', 'RISK', 'INFO') + (('BREAK_EXP', 'RISK_EXP', 'INFO_EXP') if EXP else ())
ALL130 = STABLE.all_new
# Obsolete overrides with their own, more specific note in PATTERNS.
OBS_NOTED = {'OnCEUpdate', 'CreateFrontLight', 'CreateRearLight', 'GetNoiseReduction', 'GetNoiseReductionByWeather'}


def obs_fits(d, call):
    return sig_fits(call, d['params'], d['req'])


# Matched against the code a 1.30 server compiles (inactive #ifdef branches and comments removed).
PATTERNS = [
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
SCRIPT_PATH_MSG = ('CfgMods script path with backslashes: 1.30 compiles none of these scripts, silently, and other '
                   'loaded code uses what they declare, so the module fails to compile')
SKIP_LOST_MSG = ('CfgMods script path with backslashes: 1.30 compiles none of these scripts, silently, so what they do is '
                 'lost (nothing else uses them, so it still compiles)')
SKIP_EMPTY_MSG = 'CfgMods script path with backslashes points at a folder with no scripts: 1.30 skips it, and nothing is lost'
SKIP_STUB_MSG = ("CfgMods script path with backslashes: 1.30 skips these scripts, but they are only empty classes, so those "
                 "objects use their config parent's script and nothing is lost")
OTHER_PATH_INFO = ("CfgMods script path with backslashes into another mod's folder: 1.30 skips the entry, but this PBO's "
                   "scripts have no #ifdef, so they don't depend on that mod (it loads its own scripts)")
TOP_DECL = re.compile(r'^\s*(?:enum\s+(\w+)|typedef\s+[\w<>, ]+?\s+(\w+)\s*;)', re.M)
EMPTY_ONLY = re.compile(r'^(?:\s*class\s+\w+\s*(?::|extends)\s*\w+\s*\{\s*\}\s*;?)*\s*$')
IFDEF = re.compile(r'^\s*#\s*ifn?def\b', re.M)
CORE_DIR = re.compile(r'(^|/)1_core/', re.I)
CORE_GATE = re.compile(r'^[ \t]*#[ \t]*ifn?def[ \t]+DAYZ_1_\d+\b', re.M)
CORE_GATE_MSG = ('version gate (#ifdef/#ifndef DAYZ_1_xx) in a 1_Core script: the version defines are not set yet '
                 'when the Core module compiles, so it always takes the "not defined" branch')
WB_MSG = ('uses a class 1.30 declares only for Workbench (#ifdef WORKBENCH): outside an #ifdef WORKBENCH block '
          'the module does not compile ("Can\'t find variable")')
WB_GAME = dict(STABLE_DEFS, WORKBENCH=False)
STRING = re.compile(r'"(?:[^"\\\n]|\\.)*"')
CROSS_CALL = re.compile(r'\.\s*Cross\s*\(')
CROSS_MSG = ('calls vector.Cross(), which 1.30.164078 added and 1.30.164200 removed again: the module does not '
             'compile (write the cross product out)')
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


def owns_path(pbos, path):
    p = path.replace('\\', '/').strip('/').lower()
    for pb, note in pbos.items():
        pre = (note.get('prefix') or pb[:-4]).replace('\\', '/').strip('/').lower()
        if pre and (p == pre or p.startswith(pre + '/')):
            return True
    return False


def load(raw):
    out = {'raw': raw}
    for tag, defs in (('stable', STABLE_DEFS),) + ((('exp', EXP_DEFS),) if EXP else ()):
        if tag == 'exp' and defs == STABLE_DEFS:
            out[tag] = out['stable']
            continue
        src = preprocess(nocomment(raw), defs)
        try:
            cls = parse(src)
        except Exception:
            cls = []
        out[tag] = (src, cls)
    return out



PASSES = ('stable', 'exp') if EXP else ('stable',)

def own_classes(parsed):
    """Classes the mod declares (not modded), by name."""
    out = {}
    for _, p in parsed:
        for tag in PASSES:
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


def receivers(body, t, modclasses, ix):
    """{("Class.t", declared type)} for every x.t() call whose x has a declared type; empty if any call can't be resolved."""
    out = set()
    for m in re.finditer(r'(\.\s*)?\b(\w+)\s*\.\s*' + t + r'\s*\(', body):
        if m.group(1):
            return set()  # a.b.t(): receiver type unknown
        typ = next((d.group(1) for d in re.finditer(r'\b(\w+)\s+' + m.group(2) + r'\s*[=;,)]', body)
                    if d.group(1) not in ('return', 'new', 'delete', 'out', 'inout', 'ref', 'autoptr')), None)
        vc = typ if typ in ix else (vanilla_base(modclasses[typ], modclasses, ix) if typ in modclasses else None)
        cls, _ = find_method(ix, vc, t) if vc else (None, None)
        if not cls:
            return set()
        out.add((cls + '.' + t, typ))
    return out



def diff_checks(vd, rel, src, cls, modclasses, mod_own, mod_overrides, add):
    """Checks that follow from the vanilla diff d, on what a server of vd's new build compiles from this file."""
    for c in cls:
        name = c['name']
        if c['modded']:
            if name in vd.removed_classes:
                add('BREAK', 'modded class of class removed in ' + vd.label + ': ' + name, rel)
        elif c['base'] in vd.removed_classes:
            add('BREAK', 'class extends class removed in ' + vd.label + ': ' + c['base'], rel + ' (' + name + ')')
        vbase = vanilla_base(c, modclasses, vd.old)
        if vbase and vbase in vd.new:
            # vanilla method new in vd.new with the same name as one this mod adds (no override)
            for mn, ovs in c['methods'].items():
                if any(ov['override'] for ov in ovs) or mn in (name, vbase) or mn.startswith('~'):
                    continue  # overrides, constructors and destructors
                anc = [x for x in chain(vd.new, vbase) if vd.added(x, mn)]
                desc = [x for x in vd.descendants(vbase) if vd.added(x, mn) and not vd.overrides_cleanly(x, mn, ovs)] if c['modded'] else []
                if anc:
                    add('BREAK', 'adds %s.%s(), but %s vanilla now defines %s() in %s (name clash)' % (name, mn, vd.label, mn, anc[0]), rel)
                elif desc:
                    add('BREAK', 'adds %s() to every %s, but %s vanilla now defines %s() in subclass %s (name clash)' % (mn, name, vd.label, mn, ', '.join(desc[:3])), rel)
        if not vbase or vbase not in vd.old:
            continue
        for mn, ovs in c['methods'].items():
            for ov in ovs:
                if not ov['override']:
                    continue
                vc, ms29 = find_method(vd.old, vbase, mn)
                if not vc:
                    continue
                s = sig(ov)
                if s not in {sig(m) for m in ms29}:
                    continue  # mod didn't match the old build either (parser noise, mod-side base, or new-build code); skip
                vc30, ms30 = find_method(vd.new, vbase if vbase in vd.new else vc, mn)
                if not vc30:
                    add('BREAK', 'overrides ' + vc + '.' + mn + '() which no longer exists in ' + vd.label, rel)
                elif s not in {sig(m) for m in ms30}:
                    new = ' | '.join('(' + ', '.join(m['params']) + ')' for m in ms30)
                    add('BREAK', 'override signature changed: ' + vc30 + '.' + mn + '(' + ', '.join(s) + ') is now ' + new, rel)
                else:
                    r29 = {m['ret'] for m in ms29 if sig(m) == s}
                    r30 = {m['ret'] for m in ms30 if sig(m) == s}
                    if r29 and r30 and not (r29 & r30):
                        add('BREAK', 'override return type changed: ' + vc30 + '.' + mn + ' ' + '/'.join(sorted(r29)) + ' -> ' + '/'.join(sorted(r30)), rel)
                    if mn not in OBS_NOTED and any(m.get('obsolete') for m in ms30 if sig(m) == s) and not (
                            vd.only_new_obsolete and any(m.get('obsolete') for m in ms29 if sig(m) == s)):
                        live30 = {sig(m) for m in ms30 if not m.get('obsolete')}
                        also = [sig(o) for o in ovs if o['override'] and sig(o) in live30]
                        repl = [u for u in vd.obs_use.get(mn, []) if u != mn and any(o['override'] for o in c['methods'].get(u, []))]
                        what = 'overrides ' + vc30 + '.' + mn + '(' + ', '.join(s) + '), marked [Obsolete] in ' + vd.label
                        if also:
                            add('INFO', what + '; the same class also overrides the current (' + ', '.join(also[0]) + ') version, so nothing is lost', rel)
                        elif repl:
                            add('INFO', what + '; the same class also overrides ' + repl[0] + '(), its ' + vd.label + ' replacement, so nothing is lost', rel)
                        elif vd.obs_called(vc30 + '.' + mn, s):
                            add('INFO', what, rel)
                        else:
                            add('RISK', what + ' and never called by ' + vd.label + ' vanilla: the override does not run', rel)
    body = strip(src)
    own = set(modclasses) | mod_own
    for c in cls:
        own.update(c['methods'])
        own.update(c['fields'])
    toks = set(IDENT.findall(body))
    for t in toks & set(vd.removed_members):
        if t in GENERIC and not re.search(GENERIC[t], body):
            continue
        if t not in own:
            add('RISK', 'uses ' + vd.removed_members[t] + ', removed in ' + vd.label, rel)
    for t in toks & vd.removed_classes:
        if t in GENERIC and not re.search(GENERIC[t], body):
            continue
        if t in vd.wb_only and (not module_rank(rel) or WORKBENCH_DIR.search(rel)):
            continue
        if t not in own:
            add('RISK', 'uses class ' + t + ', removed in ' + vd.label, rel)
    for t in toks & vd.obsolete:
        if t in own:
            continue
        calls = call_types(body, t)
        mine = [d for k, v in vd.obs_defs.items() if k.split('.')[1] == t for d in v]
        if mine:
            calls = {c for c in calls if any(obs_fits(d, c) for d in mine)}
        if not calls:
            continue  # no call, or only the current overloads are called
        ar = {c for c in calls if not any(sig_fits(c, p, len(p)) for p in vd.live_sigs.get(t, []))}
        ds = [d for d in mine if any(obs_fits(d, c) for c in ar)]
        if not ar:
            reach = receivers(body, t, modclasses, vd.new)
            if reach and all(k in vd.obs_defs for k, _ in reach):
                if not all(d['stub'] for k, _ in reach for d in vd.obs_defs[k]):
                    k, typ = sorted(reach)[0]
                    add('INFO', 'calls ' + k + '() on a ' + typ + ': [Obsolete] in ' + vd.label + ' but still there, so it works (compile warning)', rel)
                    continue
            elif reach and not any(k in vd.obs_defs for k, _ in reach):
                continue  # every call reaches a current method
            obs = sorted(k for k in vd.obs_defs if k.split('.')[1] == t)
            add('INFO', 'calls ' + t + '(): ' + ', '.join(obs) + '() is [Obsolete] in ' + vd.label + ' but ' + vd.live_class[t] + '.' + t + '() is not; check which one this call reaches', rel)
        elif ds and all(d['stub'] for d in ds) and t not in mod_overrides:
            add('RISK', 'calls ' + t + '(), which ' + vd.label + ' left as a placeholder (empty, or returns a fixed value): it compiles but does nothing', rel)
        else:
            add('INFO', 'calls ' + t + '() marked [Obsolete] in ' + vd.label, rel)
    for t in toks & set(vd.now_protected):
        if t in own:
            continue
        for m in re.finditer(r'(\w+)\s*\.\s*' + t + r'\s*\(', body):
            if m.group(1) not in ('super', 'this'):
                add('RISK', 'calls ' + vd.now_protected[t] + ' from outside the class; ' + vd.label + ' made it protected (unverified whether that compiles)', rel)
                break

def scan_files(files):
    res = {lv: {} for lv in LEVELS}

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
        for tag in PASSES:
            for c in p[tag][1]:
                mod_own.update(m for m, o in c['methods'].items() if not any(v['override'] for v in o))
                mod_overrides.update(m for m, o in c['methods'].items() if any(v['override'] for v in o))
                mod_own.update(c['fields'])
    for rel, p in parsed:
        src30, cls = p['stable']
        for level, msg, rx in RAW_PATTERNS:
            for m in rx.finditer(p['raw']):
                add(level, msg, rel + ':' + str(p['raw'].count('\n', 0, m.start()) + 1))
        if CORE_DIR.search(rel):
            for m in CORE_GATE.finditer(p['raw']):
                add('RISK', CORE_GATE_MSG, rel + ':' + str(p['raw'].count('\n', 0, m.start()) + 1))
        if WB_ONLY & set(IDENT.findall(p['raw'])) and module_rank(rel) and not WORKBENCH_DIR.search(rel):
            seen = set()
            for i, line in enumerate(preprocess(nocomment(p['raw']), WB_GAME).split('\n')):
                for t in IDENT.findall(STRING.sub('""', line)):
                    if t in WB_ONLY and t not in seen and t not in modclasses and t not in mod_own:
                        seen.add(t)
                        add('BREAK', WB_MSG, rel + ':' + str(i + 1) + ' (' + t + ')')
        if 'Cross' not in mod_own:
            for m in CROSS_CALL.finditer(src30):
                args = call_args(src30, m.end() - 1)
                if args is not None and len([a for a in args if a.strip()]) == 1:
                    add('BREAK', CROSS_MSG, rel + ':' + str(src30.count('\n', 0, m.start()) + 1))
        spans = debug_spans(src30)
        for level, msg, rx in PATTERNS:
            for m in rx.finditer(src30):
                if msg in SKIP_IN_DEBUG_SPAWN and any(a <= m.start() < b for a, b in spans):
                    continue
                add(level, msg, rel + ':' + str(src30.count('\n', 0, m.start()) + 1))

        diff_checks(STABLE, rel, src30, cls, modclasses, mod_own, mod_overrides, add)
        if EXP:
            src_exp, cls_exp = p['exp']
            diff_checks(EXP, rel, src_exp, cls_exp, modclasses, mod_own, mod_overrides, lambda lv, msg, where: add(lv + '_EXP', msg, where))
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

SCRIPT_PATHS = {}
if PATHS:
    from modpaths import backslash_paths
    for line in open(PATHS[0], encoding='utf-8'):
        if line.strip():
            n, kind, m = (x.strip() for x in line.rstrip('\n').split('\t'))
            SCRIPT_PATHS[n] = backslash_paths(os.path.join(PATHS[1], m))

DECLS = {}  # rel -> (type names the file declares, {modded class: members it adds})
TEXTS = {}


def file_decls(rel, src):
    if rel not in DECLS:
        types, members = set(), {}
        try:
            cls = parse(src)
        except Exception:
            cls = []
        for c in cls:
            if not c['modded']:
                types.add(c['name'])
                continue
            for mn, ovs in c['methods'].items():
                if mn != c['name'] and not mn.startswith('~') and not any(o['override'] for o in ovs):
                    members.setdefault(c['name'], set()).add(mn)
            members.setdefault(c['name'], set()).update(c['fields'])
        s = strip(src)
        types.update(x for t in TOP_DECL.findall(s) for x in t if x)
        DECLS[rel] = (types, members)
        TEXTS[rel] = s
    return DECLS[rel]


def type_use(s, name):
    """Whether s uses name where only a type can stand (a variable of that name doesn't count)."""
    n = re.escape(name)
    return bool(re.search(r'(?<![\w.])' + n + r'\s+[A-Za-z_]\w*\s*[;=,)(\[]'
                          r'|\b(?:new|extends|ref|autoptr|class)\s+' + n + r'\b'
                          r'|[:<,]\s*' + n + r'\s*[>,{]'
                          r'|(?<![\w.])' + n + r'\s*\.\s*Cast(?:To)?\s*\(', s))


def folder_files(n, pbos, path):
    """The scanned scripts under a CfgMods script path."""
    p = path.replace('\\', '/').strip('/').lower()
    for pb, note in pbos.items():
        pre = (note.get('prefix') or pb[:-4]).replace('\\', '/').strip('/').lower()
        if pre and (p == pre or p.startswith(pre + '/')):
            head = (n + '/' + pb + '/').lower()
            sub = p[len(pre):].strip('/')
            return [(rel, src) for rel, src in FILES[n] if rel.lower().startswith(head)
                    and (not sub or rel[len(head):].lower().startswith(sub + '/'))]
    return []


def skipped_folder(n, pbos, path, skipped):
    """Grade a script folder 1.30 skips: (level, message, detail)."""
    fs = folder_files(n, pbos, path)
    if not fs:
        return 'INFO', SKIP_EMPTY_MSG, ''
    mine = {rel for rel, _ in fs}
    types, members = set(), {}
    for rel, src in fs:
        t, m = file_decls(rel, src)
        types |= t
        for k, v in m.items():
            members.setdefault(k, set()).update(v)
    others = [(rel, src) for fs2 in FILES.values() for rel, src in fs2 if rel not in mine and rel not in skipped]
    for rel, src in others:
        types -= file_decls(rel, src)[0]
    types -= VANILLA_NAMES
    # a member a modded class adds counts only when used through the class name (ParticleList.x)
    uses = [re.compile(r'\b' + k + r'\s*\.\s*(' + '|'.join(sorted(v)) + r')\b') for k, v in members.items() if v]
    for rel, src in others:
        used = {t for t in types & set(IDENT.findall(TEXTS[rel])) if type_use(TEXTS[rel], t)}
        if not used:
            used = {m.group(1) for u in uses for m in [u.search(TEXTS[rel])] if m}
        if used:
            return 'BREAK', SCRIPT_PATH_MSG, ' (' + rel + ' uses ' + sorted(used)[0] + ')'
    if all(EMPTY_ONLY.match(strip(src)) for _, src in fs):
        return 'INFO', SKIP_STUB_MSG, ''
    return 'RISK', SKIP_LOST_MSG, ''


WORKBENCH_DIR = re.compile(r'(?:^|/)workbench/', re.I)
MODULE_DIR = re.compile(r'(?:^|/)([1-5])_(?:core|gamelib|game|world|mission)/', re.I)
VAR_DECL = re.compile(r'\b([A-Za-z_]\w*)(?:\s*<[^<>;{}]*>)?\s+([A-Za-z_]\w*)\s*(?=[=;,)\[])')
NOT_TYPES = {'return', 'new', 'delete', 'class', 'extends', 'modded', 'typedef', 'case', 'else', 'out', 'inout',
             'ref', 'autoptr', 'notnull', 'const', 'static', 'private', 'protected', 'override', 'proto', 'native',
             'goto', 'throw', 'enum', 'sealed', 'event', 'external', 'volatile', 'reference'}
NAME_CLASH_MSG = ("variable named like another mod's class: with both mods loaded the module does not compile "
                  "(\"Variable name '...' already used as type name\")")
NAME_CLASH_RISK = ("variable named like another mod's class: fails to compile with both loaded if that class is "
                   "visible from this module (module of one of them unknown)")


def module_rank(rel):
    m = MODULE_DIR.search(rel)
    return int(m.group(1)) if m else None


TYPE_OWNERS = {}  # type name -> [(mod id, module rank)] for classes/enums/typedefs mods declare
for _n, _fs in FILES.items():
    for _rel, _src in _fs:
        for _t in file_decls(_rel, _src)[0]:
            TYPE_OWNERS.setdefault(_t, []).append((_n, module_rank(_rel)))


def name_clashes(n):
    """(level, location) for each variable this mod declares under a type name another scanned mod declares."""
    mine = {t for t, owners in TYPE_OWNERS.items() if any(o == n for o, _ in owners)}
    out = []
    for rel, src in FILES[n]:
        if WORKBENCH_DIR.search(rel):
            continue  # Workbench editor plugins are not compiled by the game
        file_decls(rel, src)
        rank = module_rank(rel)
        seen = set()
        for m in VAR_DECL.finditer(TEXTS[rel]):
            typ, var = m.group(1), m.group(2)
            if typ in NOT_TYPES or var in seen or var in mine or var in B or var not in TYPE_OWNERS:
                continue
            others = [(o, r) for o, r in TYPE_OWNERS[var] if o != n]
            known = [(o, r) for o, r in others if r is not None and rank is not None]
            hit = [o for o, r in known if r <= rank]
            where = rel + ' (' + var + ', a class in ' + manifest[(hit or [o for o, _ in others])[0]]['mod'] + ')'
            if hit:
                out.append(('BREAK', where))
            elif len(known) < len(others):
                out.append(('RISK', where))
            else:
                continue
            seen.add(var)
    return out


report = {}
_skips =[(n, pbo, mod_, path) for n in manifest for pbo, mod_, path in SCRIPT_PATHS.get(n, [])
          if mod_ and mod_.lower().endswith('scriptmodule')]
SKIPPED = {rel for n, _, _, path in _skips if owns_path(manifest[n]['pbos'], path)
           for rel, _ in folder_files(n, manifest[n]['pbos'], path)}
VANILLA_NAMES = ALL130
for n, info in manifest.items():
    files = FILES[n]
    r = scan_files(files) if files else {lv: {} for lv in LEVELS}
    for pbo, mod_, path in SCRIPT_PATHS.get(n, []):
        if mod_ and mod_.lower().endswith('scriptmodule'):
            where = pbo + ': ' + mod_ + ' = ' + path
            if owns_path(info['pbos'], path):
                level, msg, detail = skipped_folder(n, info['pbos'], path, SKIPPED)
                r[level].setdefault(msg, []).append(where + detail)
            elif any(rel.lower().startswith((n + '/' + pbo + '/').lower()) and IFDEF.search(src) for rel, src in files):
                r['RISK'].setdefault(OTHER_PATH_MSG, []).append(where)
            else:
                r['INFO'].setdefault(OTHER_PATH_INFO, []).append(where)
    for level, where in name_clashes(n):
        r[level].setdefault(NAME_CLASH_MSG if level == 'BREAK' else NAME_CLASH_RISK, []).append(where)
    r['unscanned_pbos'] = [k for k, p in info['pbos'].items() if p['unreadable']]
    r['packed_pbos'] = [k for k, p in info['pbos'].items() if p['compressed']]
    r['mod'] = info['mod']
    r['kind'] = info['kind']
    r['files'] = len(files)
    report[n] = r
json.dump(report, open(OUT, 'w'), indent=1)
print('removed classes', len(STABLE.removed_classes), 'removed members', len(STABLE.removed_members), 'obsolete', len(STABLE.obsolete),
      'now protected', len(STABLE.now_protected))
for n, r in sorted(report.items(), key=lambda kv: int(kv[0])):
    print(n, r['mod'], 'B=%d R=%d I=%d' % (len(r['BREAK']), len(r['RISK']), len(r['INFO']))
          + (' | exp: B=%d R=%d I=%d' % (len(r['BREAK_EXP']), len(r['RISK_EXP']), len(r['INFO_EXP'])) if EXP else ''),
          'unscanned:' + ','.join(r['unscanned_pbos']) if r['unscanned_pbos'] else '')
