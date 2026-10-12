// Port of python/scan130.py.
import { re, search, finditer, findall, countChar } from './pyre.js';
import { parse, strip, preprocess, nocomment, V129, V130 } from './enfparse.js';

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
  ['BREAK', 'modded class GameConstants (fails to compile on 1.30 Exp, DZEXP-93)', re('modded\\s+class\\s+GameConstants\\b')],
  ['RISK', 'FindFile on $profile/$mission/$saves lists the game folder on 1.30 (DZEXP-134)', re('FindFile\\s*\\([^;]*\\$(profile|mission|saves)', 'I')],
  ['RISK', 'FindFile used (folder listing broken for prefixed/absolute paths on 1.30)', re('\\bFindFile\\s*\\(')],
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
  ['BREAK', '#include "$profile:..." silently does nothing on 1.30 (DZEXP-85)', re('#include\\s+"\\$profile', 'I')],
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
const SCRIPT_PATH_MSG = 'CfgMods script path with backslashes: 1.30 compiles none of these scripts, silently';
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

  const REMOVED_CLASSES = new Set([...A.keys()].filter((c) => !B.has(c)));
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

  function scanFiles(files, G) {
    const res = Object.fromEntries(LEVELS.map((l) => [l, {}]));
    const add = (level, msg, where) => {
      if (!res[level][msg]) res[level][msg] = [];
      if (res[level][msg].length < 100000) res[level][msg].push(where);
    };
    const parsed = files.map((f) => ({ rel: f.rel, load: load(f.text) }));
    const modclasses = ownClasses(parsed);
    for (const p of parsed) {
      const rel = p.rel;
      const [src30, cls] = p.load['130'];
      const [src29, cls29] = p.load['129'];
      for (const [level, msg, rx] of RAW_PATTERNS) for (const m of finditer(rx, p.load.raw)) add(level, msg, rel + ':' + (countChar(p.load.raw, '\n', 0, m.index) + 1));
      const spans = debugSpans(src30);
      for (const [level, msg, rx] of PATTERNS) {
        for (const m of finditer(rx, src30)) {
          if (SKIP_IN_DEBUG_SPAWN.has(msg) && spans.some(([a, b]) => a <= m.index && m.index < b)) continue;
          add(level, msg, rel + ':' + (countChar(src30, '\n', 0, m.index) + 1));
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
            const desc = c.modded ? descendants(vbase).filter((x) => addedIn130(x, mn)) : [];
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
              if (ms30.some((m) => m.obsolete && sig(m) === s)) add('INFO', 'overrides ' + vc30 + '.' + mn + '(), marked [Obsolete] in 1.30', rel);
            }
          }
        }
      }
      const body = strip(src30);
      const own = new Set(modclasses.keys());
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
        if (OBSOLETE.has(t) && !own.has(t) && search(re('\\b' + t + '\\s*\\('), body)) add('INFO', 'calls ' + t + '() marked [Obsolete] in 1.30', rel);
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
          add('RISK_129', 'calls ' + NEW_METHODS.get(t) + ', which only exists from 1.30', rel);
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

    const report = {};
    mods.forEach((m, k) => {
      if (progress) progress(k, mods.length, m.mod);
      const r = m.files.length ? scanFiles(m.files, G) : Object.fromEntries(LEVELS.map((l) => [l, {}]));
      for (const sp of m.scriptPaths) {
        if (sp.module && sp.module.toLowerCase().endsWith('scriptmodule')) {
          const [level, msg] = ownsPath(m.pbos, sp.path) ? ['BREAK', SCRIPT_PATH_MSG] : ['RISK', OTHER_PATH_MSG];
          if (!r[level][msg]) r[level][msg] = [];
          r[level][msg].push(sp.pbo + ': ' + sp.module + ' = ' + sp.path);
        }
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
