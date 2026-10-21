// Port of python/scan130.py.
import { re, search, finditer, findall, fullmatch, countChar, strip as pyStrip } from './pyre.js?v=202610211251';
import { parse, strip, preprocess, nocomment, V129, V130 } from './enfparse.js?v=202610211251';

const LEVELS = ['BREAK', 'RISK', 'INFO', 'BREAK_129', 'RISK_129'];

function toIndex(raw) {
  const ix = new Map();
  for (const name of Object.keys(raw)) {
    const c = raw[name];
    ix.set(name, {
      base: c.base,
      methods: new Map(Object.keys(c.methods).map((m) => [m, c.methods[m]])),
      fields: new Set(c.fields),
    });
  }
  return ix;
}

function chain(ix, name) {
  const out = [];
  const seen = new Set();
  while (name && ix.has(name) && !seen.has(name)) {
    seen.add(name);
    out.push(name);
    name = ix.get(name).base;
  }
  return out;
}

function findMethod(ix, cls, meth) {
  for (const c of chain(ix, cls)) {
    const ms = ix.get(c).methods.get(meth);
    if (ms && ms.length) return [c, ms];
  }
  return [null, null];
}

function hasField(ix, cls, f) {
  return chain(ix, cls).some((c) => ix.get(c).fields.has(f));
}

const sig = (m) => JSON.stringify(m.params);
const sigs = (ms) => new Set(ms.map(sig));
const paramList = (m) => '(' + m.params.join(', ') + ')';

function names(ix) {
  const out = new Set(ix.keys());
  for (const c of ix.values()) {
    for (const m of c.methods.keys()) out.add(m);
    for (const f of c.fields) out.add(f);
  }
  return out;
}

// Matched against the code a 1.30 server compiles (inactive #ifdef branches and comments removed).
const PATTERNS = [
  ['RISK', 'ChangeGameFocus with no device (global focus freezes input on 1.30 client)', re('\\bChangeGameFocus\\s*\\(\\s*(?:[^,();]|\\([^()]*\\))*\\)')],
  ['RISK', 'GetFluidCapacityScript returns int on 1.30', re('\\bGetFluidCapacityScript\\b')],
  // Silent breakers: compile on 1.30, but vanilla no longer calls or reads them.
  ['RISK', 'overrides OnCEUpdate(), which 1.30 never calls (use OnCEIterate(currentTime, elapsedTime))', re('\\boverride\\s+void\\s+OnCEUpdate\\s*\\(')],
  ['INFO', 'overrides CarScript.CreateFrontLight/CreateRearLight, which 1.30 never calls: the car gets vanilla default headlights (VehicleLightsComponent), not its own brightness/range/colour', re('\\boverride\\s+\\w+\\s+Create(?:Front|Rear)Light\\s*\\(')],
  ['RISK', 'AddExplosionEffectForSurface: 1.30 never reads these registrations (surface effects moved to AmmoTypes)', re('\\bAddExplosionEffectForSurface\\s*\\(')],
  ['RISK', 'overrides the old weather noise reduction, which 1.30 vanilla no longer calls (it calls the ...Ex versions)', re('\\boverride\\s+\\w+\\s+GetNoiseReduction(?:ByWeather)?\\s*\\(')],
  ['INFO', 'uses ActionFillBottleBase/CCTWaterSurface, obsolete in 1.30 (vanilla now uses ActionObtainLiquidBase/CCTLiquid)', re('\\b(?:ActionFillBottleBase|CCTWaterSurface)\\b')],
  ['INFO', 'Is3rdPersonDisabled() is obsolete in 1.30 and reads the vehicles-only third-person mode as enabled', re('\\bIs3rdPersonDisabled\\s*\\(')],
  ['INFO', 'CreateInInventory now refuses items that do not fit (no log line)', re('\\bCreateInInventory\\s*\\(')],
  ['INFO', 'Fill() lands a frame late on 1.30', re('\\.\\s*Fill\\s*\\(\\s*CarFluid')],
];
// Matched against the whole file (directives included).
const RAW_PATTERNS = [
  ['RISK', '#ifdef DAYZ_1_30 switches the code off again on 1.31 (use #ifndef DAYZ_1_29)', re('^\\s*#\\s*if(?:n?def)?\\s+(?:defined\\s*\\(?\\s*)?DAYZ_1_30\\b', 'M')],
  ['RISK', 'BUILD_EXPERIMENTAL used as a version gate: it is gone on 1.30 stable', re('^\\s*#\\s*if(?:n?def)?\\s+(?:defined\\s*\\(?\\s*)?BUILD_EXPERIMENTAL\\b', 'M')],
];
// Removed names that are also ordinary words: only count them with supporting context in the same file.
const GENERIC = new Map([
  ['other', re('\\bCarContactData\\b')],
  ['impulse', re('\\bCarContactData\\b')],
  ['localPos', re('\\bCarContactData\\b')],
  ['Settings', re('(?:\\bnew\\s+Settings\\b|\\bSettings\\s+\\w+\\s*[;=,)]|\\bSettings\\s*\\.)')],
  ['GameSettings', re('(?:\\bnew\\s+GameSettings\\b|\\bGameSettings\\s+\\w+\\s*[;=,)]|\\bGameSettings\\s*\\.)')],
]);
const IDENT = re('\\b[A-Za-z_]\\w*\\b');
// Only an admin's debug spawn runs these, and the parts go to attachment slots.
const SKIP_IN_DEBUG_SPAWN = new Set(['CreateInInventory now refuses items that do not fit (no log line)']);
const DEBUG_SPAWN = re('\\bOnDebugSpawn\\s*\\([^)]*\\)\\s*\\{');
// FindFile calls are checked one at a time: flags -1 is the DZEXP-134 workaround.
const FF_PROFILE_MSG = 'FindFile on $profile/$mission/$saves lists the game folder on 1.30 (DZEXP-134)';
const FF_MSG = 'FindFile used (folder listing broken for prefixed/absolute paths on 1.30)';
const FF_FIXED_MSG = 'FindFile passes flags -1, the DZEXP-134 workaround: lists $profile:/$mission: on 1.30';
const FF_129_MSG = 'FindFile with flags -1 lists nothing on 1.29, and the call has no retry ' +
  '(retry with FindFileFlags.ALL when -1 finds nothing, or gate with #ifdef DAYZ_1_29)';
const FF_CALL = re('\\bFindFile\\s*\\(');
const FF_PREFIXED = re('\\$(profile|mission|saves)', 'I');
const MINUS_ONE = '-\\s*1';
const FLAG_ARG = '(?:\\w+\\s*\\.\\s*)*(\\w+)\\s*(\\(.*\\))?';
const FUNC_HEAD = re('\\b(\\w+)\\s*\\(([^;{}()]*)\\)\\s*\\{');
const BLOCK_WORDS = new Set(['if', 'while', 'for', 'foreach', 'switch', 'catch', 'return']);
const SCRIPT_PATH_MSG = 'CfgMods script path with backslashes: 1.30 compiles none of these scripts, silently, and other ' +
  'loaded code uses what they declare, so the module fails to compile';
const SKIP_LOST_MSG = 'CfgMods script path with backslashes: 1.30 compiles none of these scripts, silently, so what they do is ' +
  'lost (nothing else uses them, so it still compiles)';
const SKIP_EMPTY_MSG = 'CfgMods script path with backslashes points at a folder with no scripts: 1.30 skips it, and nothing is lost';
const SKIP_STUB_MSG = 'CfgMods script path with backslashes: 1.30 skips these scripts, but they are only empty classes, so those ' +
  "objects use their config parent's script and nothing is lost";
const OTHER_PATH_INFO = "CfgMods script path with backslashes into another mod's folder: 1.30 skips the entry, but this PBO's " +
  "scripts have no #ifdef, so they don't depend on that mod (it loads its own scripts)";
const TOP_DECL = re('^\\s*(?:enum\\s+(\\w+)|typedef\\s+[\\w<>, ]+?\\s+(\\w+)\\s*;)', 'M');
const EMPTY_ONLY = '(?:\\s*class\\s+\\w+\\s*(?::|extends)\\s*\\w+\\s*\\{\\s*\\}\\s*;?)*\\s*';
const IFDEF = re('^\\s*#\\s*ifn?def\\b', 'M');
const CORE_DIR = re('(^|/)1_core/', 'I');
const CORE_GATE = re('^[ \\t]*#[ \\t]*ifn?def[ \\t]+DAYZ_1_\\d+\\b', 'M');
const CORE_GATE_MSG = 'version gate (#ifdef/#ifndef DAYZ_1_xx) in a 1_Core script: the version defines are not set yet ' +
  'when the Core module compiles (measured on 1.29), so it always takes the "not defined" branch';
const WB_MSG = 'uses a class 1.30 declares only for Workbench (#ifdef WORKBENCH): outside an #ifdef WORKBENCH block ' +
  'the module does not compile ("Can\'t find variable")';
const WB_GAME = { ...V130, WORKBENCH: false };
const STRING = re('"(?:[^"\\\\\\n]|\\\\.)*"');
const CROSS_CALL = re('\\.\\s*Cross\\s*\\(');
const CROSS_MSG = 'calls vector.Cross(), which 1.30.164078 added and 1.30.164200 removed again: the module does not ' +
  'compile (write the cross product out)';
const WORKBENCH_DIR = re('(?:^|/)workbench/', 'I');
const MODULE_DIR = re('(?:^|/)([1-5])_(?:core|gamelib|game|world|mission)/', 'I');
const VAR_DECL = re('\\b([A-Za-z_]\\w*)(?:\\s*<[^<>;{}]*>)?\\s+([A-Za-z_]\\w*)\\s*(?=[=;,)\\[])');
const NOT_TYPES = new Set(['return', 'new', 'delete', 'class', 'extends', 'modded', 'typedef', 'case', 'else', 'out', 'inout',
  'ref', 'autoptr', 'notnull', 'const', 'static', 'private', 'protected', 'override', 'proto', 'native',
  'goto', 'throw', 'enum', 'sealed', 'event', 'external', 'volatile', 'reference']);
const NAME_CLASH_MSG = "variable named like another mod's class: with both mods loaded the module does not compile " +
  '("Variable name \'...\' already used as type name")';
const NAME_CLASH_RISK = "variable named like another mod's class: fails to compile with both loaded if that class is " +
  'visible from this module (module of one of them unknown)';
const moduleRank = (rel) => {
  const m = search(MODULE_DIR, rel);
  return m ? Number(m[1]) : null;
};

// Whether s uses name where only a type can stand (a variable of that name doesn't count).
function typeUse(s, n) {
  return search(re('(?<![\\w.])' + n + '\\s+[A-Za-z_]\\w*\\s*[;=,)(\\[]' +
    '|\\b(?:new|extends|ref|autoptr|class)\\s+' + n + '\\b' +
    '|[:<,]\\s*' + n + '\\s*[>,{]' +
    '|(?<![\\w.])' + n + '\\s*\\.\\s*Cast(?:To)?\\s*\\('), s) !== null;
}
const OTHER_PATH_MSG = "CfgMods script path with backslashes into another mod's folder: 1.30 skips the entry, so code that " +
  "needs that mod's scripts (often its #define for optional support) can compile out";

function debugSpans(src) {
  const spans = [];
  for (const m of finditer(DEBUG_SPAWN, src)) {
    let depth = 1;
    let i = m.index + m[0].length;
    while (i < src.length && depth) {
      if (src[i] === '{') depth += 1;
      else if (src[i] === '}') depth -= 1;
      i += 1;
    }
    spans.push([m.index, i]);
  }
  return spans;
}

// Top-level arguments of the call whose '(' is at src[i], or null if it never closes.
function callArgs(src, i) {
  const args = [];
  let depth = 0;
  let start = i + 1;
  let j = i;
  while (j < src.length) {
    const c = src[j];
    if (c === '"') {
      j += 1;
      while (j < src.length && src[j] !== '"') j += src[j] === '\\' ? 2 : 1;
    } else if ('([{'.includes(c)) depth += 1;
    else if (')]}'.includes(c)) {
      depth -= 1;
      if (depth === 0) {
        args.push(src.slice(start, j));
        return args;
      }
    } else if (c === ',' && depth === 1) {
      args.push(src.slice(start, j));
      start = j + 1;
    }
    j += 1;
  }
  return null;
}

const CALL_KW = new Set(['return', 'new', 'else', 'case', 'delete']);
const isWord = (c) => /[A-Za-z0-9_]/.test(c);

const PRIM = new Set(['int', 'float', 'bool', 'string', 'vector']);
const NOT_TYPE = new Set([...CALL_KW, 'out', 'inout', 'ref', 'const', 'notnull', 'autoptr', 'owned', 'static', 'auto',
  'private', 'protected', 'override', 'proto', 'native', 'typename']);

// Type of a call argument when it is obvious: a literal, or a variable declared earlier in src. '' if not.
function argType(src, pos, a) {
  a = pyStrip(a);
  if (a === '""') return 'string';
  if (fullmatch('-?[0-9]+', a)) return 'int';
  if (fullmatch('-?(?:[0-9]+\\.[0-9]*|\\.[0-9]+)f?', a)) return 'float';
  if (a === 'true' || a === 'false') return 'bool';
  if (fullmatch('[A-Za-z_][A-Za-z0-9_]*', a)) {
    let last = '';
    for (const m of finditer(re('\\b([A-Za-z_][A-Za-z0-9_]*)\\s+' + a + '\\s*[;=,)]'), src.slice(0, pos))) {
      if (!NOT_TYPE.has(m[1])) last = m[1].toLowerCase();
    }
    return last;
  }
  return '';
}

// Argument types (see argType) of the calls to name() in stripped src, as arrays, without repeats.
// A type word before the name makes it a definition.
function callTypes(src, name) {
  const out = new Map();
  for (const m of finditer(re('\\b' + name + '\\s*\\('), src)) {
    let k = m.index - 1;
    while (k >= 0 && ' \t\n'.includes(src[k])) k -= 1;
    if (k >= 0 && (isWord(src[k]) || '>]'.includes(src[k]))) {
      let w = k;
      while (w >= 0 && isWord(src[w])) w -= 1;
      if (!CALL_KW.has(src.slice(w + 1, k + 1))) continue;
    }
    const a = callArgs(src, m.index + m[0].length - 1);
    if (a === null) continue;
    const types = a.length === 1 && !pyStrip(a[0]) ? [] : a.map((x) => argType(src, m.index, x));
    out.set(JSON.stringify(types), types);
  }
  return [...out.values()];
}

// Whether an argument of type t (or unknown, '') can go into a parameter of normalised type p.
function typeFits(t, p) {
  if (p) p = p.split(' ').pop();
  if (!t || !p || t === p || (t === 'int' && p === 'float')) return true;
  return !PRIM.has(t) && !PRIM.has(p); // two classes: inheritance isn't checked
}

const sigFits = (types, params, req) =>
  req <= types.length && types.length <= params.length && types.every((t, i) => typeFits(t, params[i]));

function methodBodies(src, name) {
  const out = [];
  for (const m of finditer(re('\\b' + name + '\\s*\\([^;{}]*\\)\\s*\\{'), src)) {
    let depth = 1;
    let i = m.index + m[0].length;
    while (i < src.length && depth) {
      if (src[i] === '{') depth += 1;
      else if (src[i] === '}') depth -= 1;
      i += 1;
    }
    out.push(src.slice(m.index + m[0].length, i));
  }
  return out;
}

// [name, parameters, body start] of the function whose body holds src[pos], or null.
function enclosingFunction(src, heads, pos) {
  for (let k = heads.length - 1; k >= 0; k--) {
    const h = heads[k];
    const hend = h.index + h[0].length;
    if (hend > pos) continue;
    if (!BLOCK_WORDS.has(h[1]) && sameBlock(src, hend, pos)) return [h[1], h[2].split(',').map(pyStrip), hend];
  }
  return null;
}

// A FindFile flags argument that is -1: the literal, a const or static the mod sets to -1, a
// method of the mod that returns -1, or a variable or parameter of the calling function that the
// function sets to -1 or that its callers pass -1 into.
function flagsMinusOne(a, modsrc, src, heads, pos, memo) {
  if (a.startsWith('FindFileFlags')) return false;
  if (fullmatch(MINUS_ONE, a)) return true;
  const m = fullmatch(FLAG_ARG, a, 'S');
  if (!m) return false;
  const name = m[1];
  if (m[2] !== undefined) {
    const key = 'ret\0' + name;
    if (!memo.has(key)) memo.set(key, methodBodies(modsrc, name).some((b) => search(re('\\breturn\\s*-\\s*1\\s*;'), b)));
    return memo.get(key);
  }
  const dkey = 'decl\0' + name;
  if (!memo.has(dkey)) memo.set(dkey, !!search(re('\\b(?:const|static)\\b[^;{}=()]*\\b' + name + '\\s*=\\s*-\\s*1\\s*;'), modsrc));
  if (memo.get(dkey)) return true;
  if (a.includes('.')) return false;
  const fn = enclosingFunction(src, heads, pos);
  if (!fn) return false;
  const [fname, params, start] = fn;
  if (search(re('\\b' + name + '\\s*=\\s*-\\s*1\\b'), src.slice(start, pos))) return true;
  const idx = params.findIndex((x) => search(re('\\b' + name + '\\s*(?:=.*)?$'), x));
  if (idx < 0) return false;
  const key = 'pass\0' + fname + '\0' + idx;
  if (!memo.has(key)) {
    let found = false;
    for (const c of finditer(re('\\b' + fname + '\\s*\\('), modsrc)) {
      const got = callArgs(modsrc, c.index + c[0].length - 1);
      if (got && got.length > idx && fullmatch(MINUS_ONE, pyStrip(got[idx]))) {
        found = true;
        break;
      }
    }
    memo.set(key, found);
  }
  return memo.get(key);
}

// [offset, prefixed path, flags -1] for each FindFile call in src.
function findfileHits(src, modsrc, memo) {
  const out = [];
  let heads = null;
  for (const m of finditer(FF_CALL, src)) {
    const open = m.index + m[0].length - 1;
    const args = callArgs(src, open);
    const end = src.indexOf(';', open + 1);
    const prefixed = !!search(FF_PREFIXED, src.slice(open + 1, end >= 0 ? end : src.length));
    let fixed = false;
    if (args && args.length >= 4) {
      if (heads === null) heads = [...finditer(FUNC_HEAD, src)];
      fixed = flagsMinusOne(pyStrip(args[3]), modsrc, src, heads, m.index, memo);
    }
    out.push([m.index, prefixed, fixed]);
  }
  return out;
}

// src[b] is in the block that holds src[a] (or deeper): the braces between never close it.
function sameBlock(src, a, b) {
  let depth = 0;
  for (let i = a; i < b; i++) {
    if (src[i] === '{') depth += 1;
    else if (src[i] === '}') {
      depth -= 1;
      if (depth < 0) return false;
    }
  }
  return true;
}

// An unfixed call after a -1 call in the same function: the retry of the version-proof fix.
function isFallback(src, hits, k) {
  return hits.slice(0, k).some(([at, , fixed]) => fixed && at < hits[k][0] && sameBlock(src, at, hits[k][0]));
}

// A -1 call followed by another call in the same function (1.29 gets its answer there).
function hasRetry(src, hits, k) {
  return hits.slice(k + 1).some(([at, , fixed]) => !fixed && sameBlock(src, hits[k][0], at));
}

function ownsPath(pbos, path) {
  const norm = (s) => s.replace(/\\/g, '/').replace(/^\/+|\/+$/g, '').toLowerCase();
  const p = norm(path);
  return pbos.some((pb) => {
    const pre = norm(pb.prefix || pb.name.slice(0, -4));
    return pre && (p === pre || p.startsWith(pre + '/'));
  });
}

export const CHECK_COUNTS = { patterns: PATTERNS.length + RAW_PATTERNS.length };

export function makeScanner(vanilla) {
  const A = toIndex(vanilla['129']);
  const B = toIndex(vanilla['130']);
  const ALL130 = names(B);
  const ALL129 = names(A);

  // types 1.30 declares only under #ifdef WORKBENCH (left out of '130'): their own check
  const WB_ONLY = new Set(vanilla.workbench130 || []);
  const REMOVED_CLASSES = new Set([...A.keys()].filter((c) => !B.has(c) && !WB_ONLY.has(c)));
  const NEW_CLASSES = new Set([...B.keys()].filter((c) => !A.has(c)));
  const NEW_METHODS = new Map();
  for (const [cn, c] of B) for (const m of c.methods.keys()) if (!ALL129.has(m) && !NEW_METHODS.has(m)) NEW_METHODS.set(m, cn + '.' + m + '()');

  const CHILDREN = new Map();
  for (const [cn, c] of B) {
    if (c.base) {
      if (!CHILDREN.has(c.base)) CHILDREN.set(c.base, []);
      CHILDREN.get(c.base).push(cn);
    }
  }
  const descendants = (cn) => {
    const out = [];
    const todo = [cn];
    const seen = new Set();
    while (todo.length) {
      const x = todo.pop();
      for (const ch of CHILDREN.get(x) || []) {
        if (!seen.has(ch)) {
          seen.add(ch);
          out.push(ch);
          todo.push(ch);
        }
      }
    }
    return out;
  };
  const addedIn130 = (cn, m) => B.has(cn) && B.get(cn).methods.has(m) && !(A.has(cn) && A.get(cn).methods.has(m));
  const LOWER130 = new Map([...B.keys()].map((cn) => [cn.toLowerCase(), cn]));
  const isSubtype = (sub, sup) => sub === sup || (LOWER130.has(sub) && chain(B, LOWER130.get(sub)).some((x) => x.toLowerCase() === sup));
  // Vanilla's new cn.m() is a valid override of the mod's m(): same parameters, and its return
  // type is the mod's or a subclass of it (Code Lock's ItemBase GetCodeLock() vs 1.30's
  // DigitalCodeLock Fence.GetCodeLock() compiles, measured 2026-10-08).
  const overridesCleanly = (cn, m, ovs) => B.get(cn).methods.get(m).every((v) => ovs.some((o) => sig(o) === sig(v) && isSubtype(v.ret, o.ret)));

  const REMOVED_MEMBERS = new Map();
  for (const [cn, c] of A) {
    if (!B.has(cn)) continue;
    for (const m of c.methods.keys()) {
      if (findMethod(B, cn, m)[0] === null && !ALL130.has(m) && !REMOVED_MEMBERS.has(m)) REMOVED_MEMBERS.set(m, cn + '.' + m + '()');
    }
    for (const f of c.fields) {
      if (!hasField(B, cn, f) && !ALL130.has(f) && !REMOVED_MEMBERS.has(f)) REMOVED_MEMBERS.set(f, cn + '.' + f);
    }
  }

  const isPublic = (s) => (s.access || 'public') === 'public';
  const PUBLIC130 = new Set();
  for (const c of B.values()) for (const [m, ss] of c.methods) if (ss.some(isPublic)) PUBLIC130.add(m);
  const NOW_PROTECTED = new Map();
  for (const [cn, c] of A) {
    for (const [m, ss] of c.methods) {
      const s30 = B.has(cn) ? B.get(cn).methods.get(m) : undefined;
      if (s30 && s30.length && !PUBLIC130.has(m) && ss.some(isPublic) && !NOW_PROTECTED.has(m)) NOW_PROTECTED.set(m, cn + '.' + m + '()');
    }
  }
  const OBSOLETE = new Set(vanilla.obsolete130);
  const OBS_DEFS = vanilla.obsoleteDefs130 || {};
  // argument types vanilla still calls each obsolete name with ('' = unknown), calls that fit a current overload left out
  const OBS_CALLS = new Map(Object.entries(vanilla.obsoleteCalls130 || {}));
  // methods an obsolete method's message says to use instead ("1.30: use Transport.NeedElectricitySourceDevice")
  const OBS_USE = vanilla.obsoleteUse130 || {};
  const LIVE_SIGS = new Map();
  const LIVE_CLASS = new Map();
  for (const cn of [...B.keys()].sort()) {
    for (const [m, ss] of B.get(cn).methods) {
      if (!OBSOLETE.has(m)) continue;
      if (!LIVE_SIGS.has(m)) LIVE_SIGS.set(m, []);
      const live = ss.filter((s) => !s.obsolete).map((s) => s.params);
      LIVE_SIGS.get(m).push(...live);
      if (live.length && !LIVE_CLASS.has(m)) LIVE_CLASS.set(m, cn);
    }
  }
  const OBS_NOTED = new Set(['OnCEUpdate', 'CreateFrontLight', 'CreateRearLight', 'GetNoiseReduction', 'GetNoiseReductionByWeather']);
  const obsFits = (d, call) => sigFits(call, d.params, d.req);
  const obsCalled = (key, params) => {
    const all = OBS_DEFS[key] || [];
    const same = all.filter((d) => JSON.stringify(d.params) === JSON.stringify(params));
    const count = all.filter((d) => d.n === params.length);
    const ds = same.length ? same : count.length ? count : all;
    const calls = OBS_CALLS.get(key.split('.')[1]) || [];
    return !ds.length || ds.some((d) => calls.some((c) => obsFits(d, c)));
  };

  function load(text) {
    const out = { raw: text };
    for (const [tag, defs] of [['130', V130], ['129', V129]]) {
      const src = preprocess(nocomment(text), defs);
      let cls;
      try {
        cls = parse(src);
      } catch {
        cls = [];
      }
      out[tag] = [src, cls];
    }
    return out;
  }

  function ownClasses(parsed) {
    const out = new Map();
    for (const p of parsed) for (const tag of ['130', '129']) for (const c of p.load[tag][1]) if (!c.modded && !out.has(c.name)) out.set(c.name, c);
    return out;
  }

  function vanillaBase(c, modclasses, ix) {
    if (c.modded) return c.name;
    let b = c.base;
    const seen = new Set();
    while (b && modclasses.has(b) && !ix.has(b) && !seen.has(b)) {
      seen.add(b);
      b = modclasses.get(b).base;
    }
    return b && ix.has(b) ? b : null;
  }

  const anyOverride = (ovs) => ovs.some((o) => o.override);

  const LOWER_B = new Map([...B.keys()].map((c) => [c.toLowerCase(), c]));
  // Vanilla 1.30 class of the receiver in a "x.t(" / "Class.t(" / "Getter().t(" match, or null.
  function receiverClass(body, m, modclasses) {
    const [, dot, name, call] = m;
    if (dot !== undefined && call === undefined) return null; // a.b.t(): field type unknown
    if (call !== undefined) {
      const rets = new Set();
      for (const c of B.values()) for (const s of c.methods.get(name) || []) if (s.ret) rets.add(s.ret.split(/\s+/).pop());
      return rets.size === 1 ? LOWER_B.get([...rets][0]) || null : null;
    }
    if (B.has(name)) return name;
    let typ = null;
    for (const d of finditer(re('\\b(\\w+)\\s+' + name + '\\s*[=;,)]'), body)) {
      if (!['return', 'new', 'delete', 'out', 'inout', 'ref', 'autoptr'].includes(d[1])) {
        typ = d[1];
        break;
      }
    }
    if (B.has(typ)) return typ;
    return modclasses.has(typ) ? vanillaBase(modclasses.get(typ), modclasses, B) : null;
  }

  // Vanilla classes that define t for every t() call, or empty if any call's receiver is unknown.
  function callClasses(body, t, modclasses) {
    const out = new Set();
    let n = 0;
    for (const m of finditer(re('(\\.\\s*)?\\b(\\w+)\\s*(\\((?:[^()]|\\([^()]*\\))*\\))?\\s*\\.\\s*' + t + '\\s*\\('), body)) {
      n++;
      const vc = receiverClass(body, m, modclasses);
      const cls = vc ? findMethod(B, vc, t)[0] : null;
      if (!cls) return [];
      out.add(cls);
    }
    if (n !== findall(re('\\b' + t + '\\s*\\('), body).length) return [];
    return [...out];
  }

  // [["Class.t", declared type]] for every x.t() call whose x has a declared type; empty if any call can't be resolved.
  function receivers(body, t, modclasses) {
    const out = new Map();
    for (const m of finditer(re('(\\.\\s*)?\\b(\\w+)\\s*\\.\\s*' + t + '\\s*\\('), body)) {
      if (m[1] !== undefined) return [];
      let typ = null;
      for (const d of finditer(re('\\b(\\w+)\\s+' + m[2] + '\\s*[=;,)]'), body)) {
        if (!['return', 'new', 'delete', 'out', 'inout', 'ref', 'autoptr'].includes(d[1])) {
          typ = d[1];
          break;
        }
      }
      const vc = B.has(typ) ? typ : modclasses.has(typ) ? vanillaBase(modclasses.get(typ), modclasses, B) : null;
      const cls = vc ? findMethod(B, vc, t)[0] : null;
      if (!cls) return [];
      out.set(cls + '.' + t + '\0' + typ, [cls + '.' + t, typ]);
    }
    return [...out.values()];
  }

  function scanFiles(files, G) {
    const res = Object.fromEntries(LEVELS.map((l) => [l, {}]));
    const add = (level, msg, where) => {
      if (!res[level][msg]) res[level][msg] = [];
      if (res[level][msg].length < 100000) res[level][msg].push(where);
    };
    const parsed = files.map((f) => ({ rel: f.rel, load: load(f.text) }));
    const modclasses = ownClasses(parsed);
    const mod30 = parsed.map((p) => p.load['130'][0]).join('\n');
    const mod29 = parsed.map((p) => p.load['129'][0]).join('\n');
    const all29 = mod29.includes('FindFileFlags.ALL');
    const memo30 = new Map();
    const memo29 = new Map();
    // methods and fields the mod declares in any of its files (overrides excluded)
    const modOwn = new Set();
    const modOverrides = new Set(); // a call to one of these may reach the mod's own body
    for (const p of parsed) {
      for (const tag of ['130', '129']) {
        for (const c of p.load[tag][1]) {
          for (const [mn, ovs] of c.methods) {
            if (!anyOverride(ovs)) modOwn.add(mn);
            else modOverrides.add(mn);
          }
          for (const f of c.fields) modOwn.add(f);
        }
      }
    }
    for (const p of parsed) {
      const rel = p.rel;
      const [src30, cls] = p.load['130'];
      const [src29, cls29] = p.load['129'];
      for (const [level, msg, rx] of RAW_PATTERNS) for (const m of finditer(rx, p.load.raw)) add(level, msg, rel + ':' + (countChar(p.load.raw, '\n', 0, m.index) + 1));
      if (search(CORE_DIR, rel)) for (const m of finditer(CORE_GATE, p.load.raw)) add('RISK', CORE_GATE_MSG, rel + ':' + (countChar(p.load.raw, '\n', 0, m.index) + 1));
      if (findall(IDENT, p.load.raw).some((t) => WB_ONLY.has(t)) && moduleRank(rel) && !search(WORKBENCH_DIR, rel)) {
        const seen = new Set();
        preprocess(nocomment(p.load.raw), WB_GAME).split('\n').forEach((line, i) => {
          for (const t of findall(IDENT, line.replace(STRING, '""'))) {
            if (WB_ONLY.has(t) && !seen.has(t) && !modclasses.has(t) && !modOwn.has(t)) {
              seen.add(t);
              add('BREAK', WB_MSG, rel + ':' + (i + 1) + ' (' + t + ')');
            }
          }
        });
      }
      if (!modOwn.has('Cross')) {
        for (const m of finditer(CROSS_CALL, src30)) {
          const args = callArgs(src30, m.index + m[0].length - 1);
          if (args !== null && args.filter((a) => pyStrip(a)).length === 1) add('BREAK', CROSS_MSG, rel + ':' + (countChar(src30, '\n', 0, m.index) + 1));
        }
      }
      const spans = debugSpans(src30);
      for (const [level, msg, rx] of PATTERNS) {
        for (const m of finditer(rx, src30)) {
          if (SKIP_IN_DEBUG_SPAWN.has(msg) && spans.some(([a, b]) => a <= m.index && m.index < b)) continue;
          add(level, msg, rel + ':' + (countChar(src30, '\n', 0, m.index) + 1));
        }
      }
      const hits = findfileHits(src30, mod30, memo30);
      for (const [k, [at, prefixed, fixed]] of hits.entries()) {
        const where = rel + ':' + (countChar(src30, '\n', 0, at) + 1);
        if (fixed) {
          add('INFO', FF_FIXED_MSG, where);
          continue;
        }
        if (isFallback(src30, hits, k)) continue;
        if (prefixed) add('RISK', FF_PROFILE_MSG, where);
        add('RISK', FF_MSG, where);
      }
      if (!all29) {
        const hits29 = findfileHits(src29, mod29, memo29);
        for (const [k, [at, , fixed]] of hits29.entries()) {
          if (fixed && !hasRetry(src29, hits29, k)) add('RISK_129', FF_129_MSG, rel + ':' + (countChar(src29, '\n', 0, at) + 1));
        }
      }

      // ---- 1.30: what a 1.30 server compiles from this file
      for (const c of cls) {
        const name = c.name;
        if (c.modded) {
          if (REMOVED_CLASSES.has(name)) add('BREAK', 'modded class of class removed in 1.30: ' + name, rel);
        } else if (REMOVED_CLASSES.has(c.base)) add('BREAK', 'class extends class removed in 1.30: ' + c.base, rel + ' (' + name + ')');
        const vbase = vanillaBase(c, modclasses, A);
        if (vbase && B.has(vbase)) {
          // new-in-1.30 vanilla method with the same name as one this mod adds (no override)
          for (const [mn, ovs] of c.methods) {
            if (anyOverride(ovs) || mn === name || mn === vbase || mn.startsWith('~')) continue;
            const anc = chain(B, vbase).filter((x) => addedIn130(x, mn));
            const desc = c.modded ? descendants(vbase).filter((x) => addedIn130(x, mn) && !overridesCleanly(x, mn, ovs)) : [];
            if (anc.length) add('BREAK', `adds ${name}.${mn}(), but 1.30 vanilla now defines ${mn}() in ${anc[0]} (name clash)`, rel);
            else if (desc.length) add('BREAK', `adds ${mn}() to every ${name}, but 1.30 vanilla now defines ${mn}() in subclass ${desc.slice(0, 3).join(', ')} (name clash)`, rel);
          }
        }
        if (!vbase || !A.has(vbase)) continue;
        for (const [mn, ovs] of c.methods) {
          for (const ov of ovs) {
            if (!ov.override) continue;
            const [vc, ms29] = findMethod(A, vbase, mn);
            if (!vc) continue;
            const s = sig(ov);
            if (!sigs(ms29).has(s)) continue; // mod didn't match 1.29 either; skip
            const [vc30, ms30] = findMethod(B, B.has(vbase) ? vbase : vc, mn);
            if (!vc30) add('BREAK', 'overrides ' + vc + '.' + mn + '() which no longer exists in 1.30', rel);
            else if (!sigs(ms30).has(s)) {
              add('BREAK', 'override signature changed: ' + vc30 + '.' + mn + '(' + ov.params.join(', ') + ') is now ' + ms30.map(paramList).join(' | '), rel);
            } else {
              const r29 = new Set(ms29.filter((m) => sig(m) === s).map((m) => m.ret));
              const r30 = new Set(ms30.filter((m) => sig(m) === s).map((m) => m.ret));
              if (r29.size && r30.size && ![...r29].some((r) => r30.has(r))) {
                add('BREAK', 'override return type changed: ' + vc30 + '.' + mn + ' ' + [...r29].sort().join('/') + ' -> ' + [...r30].sort().join('/'), rel);
              }
              if (!OBS_NOTED.has(mn) && ms30.some((m) => m.obsolete && sig(m) === s)) {
                const live30 = new Set(ms30.filter((m) => !m.obsolete).map(sig));
                const also = ovs.filter((o) => o.override && live30.has(sig(o)));
                const repl = (OBS_USE[mn] || []).filter((u) => u !== mn && (c.methods.get(u) || []).some((o) => o.override));
                const what = 'overrides ' + vc30 + '.' + mn + '(' + ov.params.join(', ') + '), marked [Obsolete] in 1.30';
                if (also.length) add('INFO', what + '; the same class also overrides the current (' + also[0].params.join(', ') + ') version, so nothing is lost', rel);
                else if (repl.length) add('INFO', what + '; the same class also overrides ' + repl[0] + '(), its 1.30 replacement, so nothing is lost', rel);
                else if (obsCalled(vc30 + '.' + mn, ov.params)) add('INFO', what, rel);
                else add('RISK', what + ' and never called by 1.30 vanilla: the override does not run', rel);
              }
            }
          }
        }
      }
      const body = strip(src30);
      const own = new Set([...modclasses.keys(), ...modOwn]);
      for (const c of cls) {
        for (const m of c.methods.keys()) own.add(m);
        for (const f of c.fields) own.add(f);
      }
      const toks = new Set(findall(IDENT, body));
      for (const t of toks) {
        if (REMOVED_MEMBERS.has(t)) {
          if (!(GENERIC.has(t) && !search(GENERIC.get(t), body)) && !own.has(t)) add('RISK', 'uses ' + REMOVED_MEMBERS.get(t) + ', removed in 1.30', rel);
        }
        if (REMOVED_CLASSES.has(t)) {
          if (!(GENERIC.has(t) && !search(GENERIC.get(t), body)) && !own.has(t)) add('RISK', 'uses class ' + t + ', removed in 1.30', rel);
        }
        if (OBSOLETE.has(t) && !own.has(t)) {
          const live = LIVE_SIGS.get(t) || [];
          let calls = callTypes(body, t);
          const mine = Object.entries(OBS_DEFS).filter(([k]) => k.split('.')[1] === t).flatMap(([, v]) => v);
          // calls that only fit a current overload don't count
          if (mine.length) calls = calls.filter((c) => mine.some((d) => obsFits(d, c)));
          const ar = calls.filter((c) => !live.some((p) => sigFits(c, p, p.length)));
          const ds = mine.filter((d) => ar.some((c) => obsFits(d, c)));
          if (calls.length && !ar.length) {
            const reach = receivers(body, t, modclasses);
            if (reach.length && reach.every(([k]) => k in OBS_DEFS) && !reach.every(([k]) => OBS_DEFS[k].every((d) => d.stub))) {
              const [k, typ] = reach.sort((x, y) => (x[0] + '\0' + x[1] < y[0] + '\0' + y[1] ? -1 : 1))[0];
              add('INFO', 'calls ' + k + '() on a ' + typ + ': [Obsolete] in 1.30 but still there, so it works (compile warning)', rel);
            } else if (!(reach.length && !reach.some(([k]) => k in OBS_DEFS))) {
              const obs = Object.keys(OBS_DEFS).filter((k) => k.split('.')[1] === t).sort();
              add('INFO', 'calls ' + t + '(): ' + obs.join(', ') + '() is [Obsolete] in 1.30 but ' + LIVE_CLASS.get(t) + '.' + t + '() is not; check which one this call reaches', rel);
            }
          } else if (calls.length && ds.length && ds.every((d) => d.stub) && !modOverrides.has(t)) {
            add('RISK', 'calls ' + t + '(), which 1.30 left as a placeholder (empty, or returns a fixed value): it compiles but does nothing', rel);
          } else if (calls.length) add('INFO', 'calls ' + t + '() marked [Obsolete] in 1.30', rel);
        }
        if (NOW_PROTECTED.has(t) && !own.has(t)) {
          for (const m of finditer(re('(\\w+)\\s*\\.\\s*' + t + '\\s*\\('), body)) {
            if (m[1] !== 'super' && m[1] !== 'this') {
              add('RISK', 'calls ' + NOW_PROTECTED.get(t) + ' from outside the class; 1.30 made it protected (unverified whether that compiles)', rel);
              break;
            }
          }
        }
      }

      // ---- 1.29: does what a 1.29 server compiles from this file use anything 1.29 lacks?
      const own29 = new Set(modclasses.keys());
      for (const c of cls29) {
        for (const m of c.methods.keys()) own29.add(m);
        for (const f of c.fields) own29.add(f);
      }
      for (const c of cls29) {
        const name = c.name;
        if (c.modded && NEW_CLASSES.has(name) && !G.classes.has(name)) add('BREAK_129', 'modded class ' + name + ', which only exists from 1.30', rel);
        else if (!c.modded && NEW_CLASSES.has(c.base) && !G.classes.has(c.base)) add('BREAK_129', 'class extends ' + c.base + ', which only exists from 1.30', rel + ' (' + name + ')');
        const vbase = vanillaBase(c, modclasses, B) || vanillaBase(c, modclasses, A);
        if (!vbase) continue;
        // nearest class 1.29 has: a class new in 1.30 still inherits 1.29 methods from its old ancestors
        const base29 = chain(B, vbase).find((x) => A.has(x)) ?? (A.has(vbase) ? vbase : null);
        const added = new Set(); // methods mods add (not override) to this class's vanilla chain or the mod's own bases
        for (const x of chain(A, vbase).concat(chain(B, vbase))) for (const m of G.moddedAdds.get(x) || []) added.add(m);
        let b = c.base;
        const seen = new Set();
        while (b && modclasses.has(b) && !seen.has(b)) {
          seen.add(b);
          for (const [m, o] of modclasses.get(b).methods) if (!anyOverride(o)) added.add(m);
          b = modclasses.get(b).base;
        }
        for (const [mn, ovs] of c.methods) {
          for (const ov of ovs) {
            if (!ov.override || added.has(mn)) continue;
            const [vc, ms29] = base29 ? findMethod(A, base29, mn) : [null, null];
            const [vc30, ms30] = findMethod(B, vbase, mn);
            const s = sig(ov);
            if (!vc && vc30 && sigs(ms30).has(s)) add('BREAK_129', 'overrides ' + vc30 + '.' + mn + '(), which only exists from 1.30', rel);
            else if (vc && vc30 && !sigs(ms29).has(s) && sigs(ms30).has(s)) {
              add('BREAK_129', 'override uses the 1.30 signature of ' + vc30 + '.' + mn + '(' + ov.params.join(', ') + '); 1.29 has ' + ms29.map(paramList).join(' | '), rel);
            }
          }
        }
      }
      const body29 = strip(src29);
      const toks29 = new Set(findall(IDENT, body29));
      // methods only, called as name(...): new field names (ammoType, orientation, OFF) are ordinary words
      for (const t of toks29) {
        if (NEW_METHODS.has(t) && !own29.has(t) && !G.names.has(t) && search(re('\\b' + t + '\\s*\\('), body29)) {
          const on = callClasses(body29, t, modclasses);
          if (on.length) add('BREAK_129', 'calls ' + on.sort()[0] + '.' + t + '(), which 1.29 does not have: does not compile on 1.29', rel);
          else add('RISK_129', 'calls ' + NEW_METHODS.get(t) + ', which only exists from 1.30', rel);
        }
        if (NEW_CLASSES.has(t) && !own29.has(t) && !G.classes.has(t)) add('RISK_129', 'uses class ' + t + ', which only exists from 1.30', rel);
      }
    }
    return res;
  }

  function scan(mods, progress) {
    // Names any scanned mod declares: another mod may mod or call them, so they don't count as "new in 1.30".
    const G = { classes: new Set(), methods: new Set(), names: new Set(), moddedAdds: new Map() };
    for (const m of mods) {
      for (const f of m.files) {
        let cls;
        try {
          cls = parse(f.text);
        } catch {
          continue;
        }
        for (const c of cls) {
          if (!c.modded) G.classes.add(c.name);
          for (const [mn, ovs] of c.methods) {
            if (!anyOverride(ovs)) {
              G.methods.add(mn);
              if (c.modded) {
                if (!G.moddedAdds.has(c.name)) G.moddedAdds.set(c.name, new Set());
                G.moddedAdds.get(c.name).add(mn);
              }
            }
          }
          for (const f2 of c.fields) G.names.add(f2);
        }
      }
    }
    for (const x of G.classes) G.names.add(x);
    for (const x of G.methods) G.names.add(x);

    // Script folders 1.30 skips (backslash paths): graded by what they hold and whether other code needs it.
    const decls = new Map(); // rel -> [type names, Map(modded class -> members it adds)]
    const texts = new Map();
    const fileDecls = (f) => {
      if (!decls.has(f.rel)) {
        const types = new Set();
        const members = new Map();
        let cls;
        try {
          cls = parse(f.text);
        } catch {
          cls = [];
        }
        for (const c of cls) {
          if (!c.modded) {
            types.add(c.name);
            continue;
          }
          if (!members.has(c.name)) members.set(c.name, new Set());
          for (const [mn, ovs] of c.methods) if (mn !== c.name && !mn.startsWith('~') && !anyOverride(ovs)) members.get(c.name).add(mn);
          for (const f2 of c.fields) members.get(c.name).add(f2);
        }
        const s = strip(f.text);
        for (const m of finditer(TOP_DECL, s)) types.add(m[1] !== undefined ? m[1] : m[2]);
        decls.set(f.rel, [types, members]);
        texts.set(f.rel, s);
      }
      return decls.get(f.rel);
    };
    const norm = (s) => s.replace(/\\/g, '/').replace(/^\/+|\/+$/g, '').toLowerCase();
    const folderFiles = (m, path) => {
      const p = norm(path);
      for (const pb of m.pbos) {
        const pre = norm(pb.prefix || pb.name.slice(0, -4));
        if (pre && (p === pre || p.startsWith(pre + '/'))) {
          const sub = p.slice(pre.length).replace(/^\/+|\/+$/g, '');
          return m.files.filter((f) => f.pbo.toLowerCase() === pb.name.toLowerCase() && (!sub || norm(f.name).startsWith(sub + '/')));
        }
      }
      return [];
    };
    const isScriptPath = (sp) => sp.module && sp.module.toLowerCase().endsWith('scriptmodule');
    const skipped = new Set();
    for (const m of mods) for (const sp of m.scriptPaths) if (isScriptPath(sp) && ownsPath(m.pbos, sp.path)) for (const f of folderFiles(m, sp.path)) skipped.add(f.rel);
    const skippedFolder = (m, path) => {
      const fs = folderFiles(m, path);
      if (!fs.length) return ['INFO', SKIP_EMPTY_MSG, ''];
      const mine = new Set(fs.map((f) => f.rel));
      const types = new Set();
      const members = new Map();
      for (const f of fs) {
        const [t, mm] = fileDecls(f);
        for (const x of t) types.add(x);
        for (const [k, v] of mm) {
          if (!members.has(k)) members.set(k, new Set());
          for (const x of v) members.get(k).add(x);
        }
      }
      const others = mods.flatMap((m2) => m2.files).filter((f) => !mine.has(f.rel) && !skipped.has(f.rel));
      for (const f of others) for (const x of fileDecls(f)[0]) types.delete(x);
      for (const x of ALL130) types.delete(x);
      // a member a modded class adds counts only when used through the class name (ParticleList.x)
      const uses = [...members].filter(([, v]) => v.size).map(([k, v]) => re('\\b' + k + '\\s*\\.\\s*(' + [...v].sort().join('|') + ')\\b'));
      for (const f of others) {
        const s = texts.get(f.rel);
        const toks = new Set(findall(IDENT, s));
        let used = [...types].filter((t) => toks.has(t) && typeUse(s, t));
        if (!used.length) used = uses.map((u) => search(u, s)).filter((x) => x).map((x) => x[1]);
        if (used.length) return ['BREAK', SCRIPT_PATH_MSG, ' (' + f.rel + ' uses ' + used.sort()[0] + ')'];
      }
      if (fs.every((f) => fullmatch(EMPTY_ONLY, strip(f.text)))) return ['INFO', SKIP_STUB_MSG, ''];
      return ['RISK', SKIP_LOST_MSG, ''];
    };

    // Variables named like a class another scanned mod declares ("Variable name '...' already used as type name").
    const typeOwners = new Map(); // type name -> [[mod id, module rank]]
    for (const m of mods) {
      for (const f of m.files) {
        for (const t of fileDecls(f)[0]) {
          if (!typeOwners.has(t)) typeOwners.set(t, []);
          typeOwners.get(t).push([m.id, moduleRank(f.rel)]);
        }
      }
    }
    const modName = new Map(mods.map((m) => [m.id, m.mod]));
    const nameClashes = (m) => {
      const mine = new Set([...typeOwners].filter(([, o]) => o.some(([id]) => id === m.id)).map(([t]) => t));
      const out = [];
      for (const f of m.files) {
        if (search(WORKBENCH_DIR, f.rel)) continue; // Workbench editor plugins are not compiled by the game
        fileDecls(f);
        const rank = moduleRank(f.rel);
        const seen = new Set();
        for (const d of finditer(VAR_DECL, texts.get(f.rel))) {
          const [, typ, v] = d;
          if (NOT_TYPES.has(typ) || seen.has(v) || mine.has(v) || B.has(v) || !typeOwners.has(v)) continue;
          const others = typeOwners.get(v).filter(([id]) => id !== m.id);
          const known = others.filter(([, r]) => r !== null && rank !== null);
          const hit = known.filter(([, r]) => r <= rank).map(([id]) => id);
          const where = f.rel + ' (' + v + ', a class in ' + modName.get((hit.length ? hit : others.map(([id]) => id))[0]) + ')';
          if (hit.length) out.push(['BREAK', where]);
          else if (known.length < others.length) out.push(['RISK', where]);
          else continue;
          seen.add(v);
        }
      }
      return out;
    };

    const report = {};
    mods.forEach((m, k) => {
      if (progress) progress(k, mods.length, m.mod);
      const r = m.files.length ? scanFiles(m.files, G) : Object.fromEntries(LEVELS.map((l) => [l, {}]));
      for (const sp of m.scriptPaths) {
        if (isScriptPath(sp)) {
          const where = sp.pbo + ': ' + sp.module + ' = ' + sp.path;
          let level, msg, detail = '';
          if (ownsPath(m.pbos, sp.path)) [level, msg, detail] = skippedFolder(m, sp.path);
          else if (m.files.some((f) => f.pbo === sp.pbo && search(IFDEF, f.text))) [level, msg] = ['RISK', OTHER_PATH_MSG];
          else [level, msg] = ['INFO', OTHER_PATH_INFO];
          if (!r[level][msg]) r[level][msg] = [];
          r[level][msg].push(where + detail);
        }
      }
      for (const [level, where] of nameClashes(m)) {
        const msg = level === 'BREAK' ? NAME_CLASH_MSG : NAME_CLASH_RISK;
        if (!r[level][msg]) r[level][msg] = [];
        r[level][msg].push(where);
      }
      r.unscanned_pbos = m.pbos.filter((p) => p.unreadable).map((p) => p.name);
      r.packed_pbos = m.pbos.filter((p) => p.compressed).map((p) => p.name);
      r.mod = m.mod;
      r.kind = m.kind;
      r.files = m.files.length;
      report[m.id] = r;
    });
    return report;
  }

  return {
    scan,
    stats: { removedClasses: REMOVED_CLASSES.size, removedMembers: REMOVED_MEMBERS.size, obsolete: OBSOLETE.size,
      newClasses: NEW_CLASSES.size, newMethods: NEW_METHODS.size, nowProtected: NOW_PROTECTED.size },
    versions: vanilla.versions || {},
  };
}
