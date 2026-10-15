// Port of python/enfparse.py.
import { re, search, finditer, findall, fullmatch, strip as pstrip, lstrip, splitWs, countChar } from './pyre.js?v=202610151008';

const MODS = new Set(['override', 'static', 'proto', 'native', 'private', 'protected', 'event', 'external', 'volatile',
  'owned', 'ref', 'reference', 'notnull', 'const', 'autoptr', 'sealed', 'modded', 'extern']);

// Remove comments, blank out string/char literals, drop preprocessor lines.
export function strip(src) {
  const out = [];
  let i = 0;
  const n = src.length;
  while (i < n) {
    const c = src[i];
    if (c === '/' && i + 1 < n && src[i + 1] === '/') {
      const j = src.indexOf('\n', i);
      i = j < 0 ? n : j;
      continue;
    }
    if (c === '/' && i + 1 < n && src[i + 1] === '*') {
      const j = src.indexOf('*/', i + 2);
      i = j < 0 ? n : j + 2;
      out.push(' ');
      continue;
    }
    if (c === '"' || c === "'") {
      let j = i + 1;
      while (j < n && src[j] !== c) j += src[j] === '\\' ? 2 : 1;
      out.push(c + c);
      i = j + 1;
      continue;
    }
    out.push(c);
    i += 1;
  }
  return out.join('').split('\n').filter((l) => !lstrip(l).startsWith('#')).join('\n');
}

// Remove comments but keep string literals, directives and the line count.
export function nocomment(src) {
  const out = [];
  let i = 0;
  const n = src.length;
  while (i < n) {
    const c = src[i];
    if (c === '/' && i + 1 < n && src[i + 1] === '/') {
      const j = src.indexOf('\n', i);
      i = j < 0 ? n : j;
      continue;
    }
    if (c === '/' && i + 1 < n && src[i + 1] === '*') {
      let j = src.indexOf('*/', i + 2);
      j = j < 0 ? n : j + 2;
      const nl = countChar(src, '\n', i, j);
      out.push(nl ? '\n'.repeat(nl) : ' ');
      i = j;
      continue;
    }
    if (c === '"' || c === "'") {
      let j = i + 1;
      while (j < n && src[j] !== c && src[j] !== '\n') j += src[j] === '\\' ? 2 : 1;
      out.push(src.slice(i, j + 1));
      i = j + 1;
      continue;
    }
    out.push(c);
    i += 1;
  }
  return out.join('');
}

const DIRECTIVE = re('^\\s*#\\s*(ifdef|ifndef|if|elif|else|endif)\\b\\s*(.*)$');

function cond(kind, arg, defines) {
  arg = pstrip(arg.split('//')[0]);
  if (kind === 'ifdef' || kind === 'ifndef') {
    const v = Object.prototype.hasOwnProperty.call(defines, arg) ? defines[arg] : null;
    return v === null || kind === 'ifdef' ? v : !v;
  }
  const m = fullmatch('(!?)\\s*(?:defined\\s*\\(?\\s*)?(\\w+)\\s*\\)?', arg);
  if (!m || !Object.prototype.hasOwnProperty.call(defines, m[2])) return null;
  return defines[m[2]] !== Boolean(m[1]);
}

// Unknown defines keep both branches; line count is kept.
export function preprocess(src, defines) {
  const out = [];
  const stack = []; // [enclosing active, cond (true/false/null), a branch was taken]
  for (const line of src.split('\n')) {
    const m = search(DIRECTIVE, line);
    const active = stack.every((f) => f[0] && f[1] !== false);
    if (!m) {
      out.push(active ? line : '');
      continue;
    }
    const kind = m[1];
    const arg = m[2];
    if (kind === 'ifdef' || kind === 'ifndef' || kind === 'if') {
      const c = cond(kind, arg, defines);
      stack.push([active, c, c === true]);
    } else if (stack.length && kind === 'elif') {
      const f = stack[stack.length - 1];
      const c = cond('if', arg, defines);
      f[1] = f[2] ? false : c;
      f[2] = f[2] || c === true;
    } else if (stack.length && kind === 'else') {
      const f = stack[stack.length - 1];
      f[1] = f[1] === null ? null : !f[2];
    } else if (stack.length && kind === 'endif') {
      stack.pop();
    }
    out.push('');
  }
  return out.join('\n');
}

export const V129 = { DAYZ_1_29: true, DAYZ_1_30: false };
export const V130 = { DAYZ_1_29: false, DAYZ_1_30: true };

export function splitTop(s) {
  const parts = [];
  let d = 0;
  let cur = '';
  for (const ch of s) {
    if ('<(['.includes(ch)) d += 1;
    else if ('>)]'.includes(ch)) d -= 1;
    if (ch === ',' && d === 0) {
      parts.push(cur);
      cur = '';
    } else cur += ch;
  }
  if (pstrip(cur)) parts.push(cur);
  return parts;
}

const WS_RUN = re('\\s+');
const IDENT_ONLY = re('^\\w+$');
const DROP = new Set(['const', 'notnull', 'owned', 'ref', 'autoptr']);

function normParam(p) {
  p = pstrip(p.split('=')[0]);
  p = p.replace(WS_RUN, ' ');
  let toks = splitWs(p.split('<').join(' < ').split('>').join(' > ').split('[').join(' [ ').split(']').join(' ] ').split(',').join(' , '));
  if (!toks.length) return '';
  // drop the parameter name: last identifier, unless it closes a template
  const last = toks[toks.length - 1];
  if (toks.length > 1 && search(IDENT_ONLY, last) && toks[toks.length - 2] !== '<' && toks[toks.length - 2] !== ',') {
    toks = toks.slice(0, -1);
  }
  toks = toks.filter((t) => !DROP.has(t));
  return pstrip(toks.join(' ').split(' < ').join('<').split(' > ').join('>').split(' , ').join(',')).toLowerCase();
}

const HDR = re('(?:^|[\\s;}])((?:(?:modded|sealed)\\s+)*)class\\s+(\\w+)\\s*(?:<[^>{]*>)?\\s*(?:(?:extends|:)\\s*(\\w+)(?:<[^>{]*>)?)?\\s*$');
const METH = re('([\\w<>,\\s\\[\\]]*?)\\b(\\w+)\\s*\\(([^()]*(?:\\([^()]*\\)[^()]*)*)\\)\\s*$', 'S');
const OBS = re('\\[\\s*Obsolete');
const KW = new Set(['if', 'while', 'for', 'switch', 'foreach', 'return', 'else']);
const FIELD = re('\\b(\\w+)\\b(?:\\s*\\[[^\\]]*\\])?\\s*$');

function addMethod(cur, text) {
  const mm = search(METH, text);
  if (!mm || KW.has(mm[2])) return false;
  const head = text.slice(0, mm.indices[2][0]);
  const pre = splitWs(mm[1]);
  const ret = pre.filter((t) => !MODS.has(t) && t !== ']' && t !== '[');
  let list = cur.methods.get(mm[2]);
  if (!list) cur.methods.set(mm[2], (list = []));
  list.push({
    ret: ret.join(' ').toLowerCase(),
    params: splitTop(mm[3]).filter((p) => pstrip(p)).map(normParam),
    override: pre.includes('override'),
    static: pre.includes('static'),
    obsolete: Boolean(search(OBS, head)),
    access: pre.includes('private') ? 'private' : pre.includes('protected') ? 'protected' : 'public',
  });
  return true;
}

export function parse(src, defines = null) {
  const s = strip(defines ? preprocess(src, defines) : src);
  const n = s.length;
  let i = 0;
  let depth = 0;
  let buf = '';
  const classes = [];
  const stack = [];
  while (i < n) {
    const ch = s[i];
    if (ch === '{') {
      const cur = stack.length ? stack[stack.length - 1] : null;
      const m = !cur || depth === cur._d ? search(HDR, buf) : null;
      if (m) {
        const c = { name: m[2], base: m[3] === undefined ? null : m[3], modded: m[1].includes('modded'),
          methods: new Map(), fields: new Set(), _d: depth + 1 };
        classes.push(c);
        stack.push(c);
        depth += 1;
        buf = '';
        i += 1;
        continue;
      }
      if (cur && depth === cur._d) {
        addMethod(cur, pstrip(buf));
        let d = 1;
        let j = i + 1;
        while (j < n && d) {
          if (s[j] === '{') d += 1;
          else if (s[j] === '}') d -= 1;
          j += 1;
        }
        i = j;
        buf = '';
        continue;
      }
      depth += 1;
      buf = '';
      i += 1;
      continue;
    }
    if (ch === '}') {
      if (stack.length && depth === stack[stack.length - 1]._d) stack.pop();
      depth -= 1;
      buf = '';
      i += 1;
      continue;
    }
    if (ch === ';') {
      const cur = stack.length ? stack[stack.length - 1] : null;
      if (cur && depth === cur._d) {
        const st = pstrip(buf);
        if (st.split('=')[0].includes('(') && addMethod(cur, st)) {
        } else if (st && !st.startsWith('typedef') && !st.startsWith('enum')) {
          const left = st.split('=')[0];
          for (const part of splitTop(left)) {
            const ids = findall(FIELD, pstrip(part));
            if (ids.length) cur.fields.add(ids[ids.length - 1]);
          }
        }
      }
      buf = '';
      i += 1;
      continue;
    }
    buf += ch;
    i += 1;
  }
  for (const c of classes) delete c._d;
  return classes;
}
