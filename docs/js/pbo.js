// reader: { size, read(offset, length) -> Promise<Uint8Array> }
import { re, finditer, findall, decodeUtf8 } from './pyre.js?v=202610151236';

const VERS = 0x56657273; // 'Vers' header extension
const CPRS = 0x43707273; // 'Cprs' packed entry

class NeedMore extends Error {}
class Malformed extends Error {}

function latin1(bytes, a, b) {
  let s = '';
  for (let i = a; i < b; i++) s += String.fromCharCode(bytes[i]);
  return s;
}

// strict: a short read is an error (deps.py); otherwise it ends the table (extract.py)
function parseHeader(buf, fileSize, strict) {
  let i = 0;
  const atEnd = () => buf.length >= fileSize;
  const cstr = () => {
    let j = i;
    while (j < buf.length && buf[j] !== 0) j++;
    if (j >= buf.length) {
      if (!atEnd()) throw new NeedMore();
      if (strict) throw new Malformed('no string terminator in header');
      const s = latin1(buf, i, j);
      i = j;
      return s;
    }
    const s = latin1(buf, i, j);
    i = j + 1;
    return s;
  };
  const u32 = (o) => (buf[o] | (buf[o + 1] << 8) | (buf[o + 2] << 16) | (buf[o + 3] << 24)) >>> 0;
  const props = {};
  const entries = [];
  let first = true;
  for (;;) {
    const name = cstr();
    if (i + 20 > buf.length) {
      if (!atEnd()) throw new NeedMore();
      if (strict) throw new Malformed('header truncated');
      break;
    }
    const mime = u32(i);
    const orig = u32(i + 4);
    const size = u32(i + 16);
    i += 20;
    if (first && !name && mime === VERS) {
      for (;;) {
        const k = cstr();
        if (!k) break;
        props[k] = cstr();
      }
      first = false;
      continue;
    }
    first = false;
    if (!name) break;
    entries.push({ name: name.split('\\').join('/'), mime, orig, size });
  }
  let off = i;
  for (const e of entries) {
    e.offset = off;
    off += e.size;
  }
  return { props, entries };
}

export async function readHeader(reader, strict) {
  let len = Math.min(reader.size, 1 << 20);
  for (;;) {
    const buf = await reader.read(0, len);
    try {
      return parseHeader(buf, reader.size, strict);
    } catch (e) {
      if (!(e instanceof NeedMore)) throw e;
      len = Math.min(reader.size, len * 4);
    }
  }
}

// BI LZSS
export function lzss(data, outlen) {
  const out = new Uint8Array(outlen);
  let o = 0;
  let i = 0;
  const n = data.length;
  while (o < outlen && i < n) {
    const flags = data[i];
    i += 1;
    for (let b = 0; b < 8; b++) {
      if (o >= outlen || i >= n) break;
      if (flags & (1 << b)) {
        out[o++] = data[i];
        i += 1;
      } else {
        if (i + 1 >= n) throw new Malformed('LZSS data truncated');
        const lo = data[i];
        const hi = data[i + 1];
        i += 2;
        const rpos = o - (lo | ((hi & 0xf0) << 4));
        const rlen = (hi & 0x0f) + 3;
        for (let k = 0; k < rlen; k++) {
          if (o >= outlen) break;
          const p = rpos + k;
          out[o++] = p >= 0 ? out[p] : 0x20;
        }
      }
    }
  }
  return out.subarray(0, o);
}

export function isPacked(e) {
  return e.mime === CPRS || (e.orig && e.orig !== e.size);
}

export async function extractScripts(reader) {
  const { props, entries } = await readHeader(reader, false);
  const note = { prefix: props.prefix || '', files: [], compressed: 0, unreadable: 0 };
  for (const e of entries) {
    const low = e.name.toLowerCase();
    if (!(low.endsWith('.c') || low.endsWith('config.cpp'))) continue;
    let data = await reader.read(e.offset, Math.max(0, Math.min(e.size, reader.size - e.offset)));
    if (isPacked(e)) {
      try {
        data = lzss(data, e.orig);
      } catch {
        note.unreadable += 1;
        continue;
      }
      note.compressed += 1;
      if (data.length !== e.orig) {
        note.unreadable += 1;
        continue;
      }
    }
    if (e.name.split('/').includes('..') || !e.name.split('/').some((s) => s)) {
      note.unreadable += 1;
      continue;
    }
    note.files.push({ name: e.name, bytes: data });
  }
  return note;
}

async function configEntries(reader) {
  const { entries } = await readHeader(reader, true);
  const out = [];
  for (const e of entries) {
    const base = e.name.slice(e.name.lastIndexOf('/') + 1).toLowerCase();
    if (base !== 'config.bin' && base !== 'config.cpp') continue;
    let blob = await reader.read(e.offset, Math.max(0, Math.min(e.size, reader.size - e.offset)));
    if (isPacked(e)) blob = lzss(blob, e.orig);
    out.push({ name: e.name, bytes: blob });
  }
  return out;
}

// ---- rapified config ----
function byte(b, i) {
  if (i >= b.length) throw new Malformed('config.bin truncated');
  return b[i];
}

function cstrBuf(b, i) {
  let j = i;
  while (j < b.length && b[j] !== 0) j++;
  if (j >= b.length) throw new Malformed('config.bin string not terminated');
  return [latin1(b, i, j), j + 1];
}

function cint(b, i) {
  let v = 0;
  let s = 0;
  for (;;) {
    const c = byte(b, i);
    i += 1;
    v += (c & 0x7f) * 2 ** s;
    s += 7;
    if (!(c & 0x80)) return [v, i];
  }
}

function rapArray(b, i) {
  let n;
  [n, i] = cint(b, i);
  const out = [];
  for (let k = 0; k < n; k++) {
    const t = byte(b, i);
    i += 1;
    if (t === 0) {
      let s;
      [s, i] = cstrBuf(b, i);
      out.push(s);
    } else if (t === 1 || t === 2) {
      i += 4;
      out.push(null);
    } else if (t === 3) {
      let sub;
      [sub, i] = rapArray(b, i);
      out.push(sub);
    } else if (t === 6) {
      i += 8;
      out.push(null);
    } else throw new Malformed('array elem type ' + t);
  }
  return [out, i];
}

// Map name -> ['class', offset] | ['value', v] | ['array', list]
function rapClass(b, off) {
  let i;
  [, i] = cstrBuf(b, off); // inherited
  let n;
  [n, i] = cint(b, i);
  const out = new Map();
  for (let k = 0; k < n; k++) {
    const t = byte(b, i);
    i += 1;
    let name;
    if (t === 0) {
      [name, i] = cstrBuf(b, i);
      if (i + 4 > b.length) throw new Malformed('config.bin truncated');
      const o = (b[i] | (b[i + 1] << 8) | (b[i + 2] << 16) | (b[i + 3] << 24)) >>> 0;
      i += 4;
      out.set(name, ['class', o]);
    } else if (t === 1) {
      const st = byte(b, i);
      i += 1;
      [name, i] = cstrBuf(b, i);
      let v = null;
      if (st === 0 || st === 4) [v, i] = cstrBuf(b, i);
      else if (st === 6) i += 8;
      else i += 4;
      out.set(name, ['value', v]);
    } else if (t === 2) {
      [name, i] = cstrBuf(b, i);
      let arr;
      [arr, i] = rapArray(b, i);
      out.set(name, ['array', arr]);
    } else if (t === 3 || t === 4) {
      [name, i] = cstrBuf(b, i);
    } else if (t === 5) {
      i += 4;
      [name, i] = cstrBuf(b, i);
      let arr;
      [arr, i] = rapArray(b, i);
      out.set(name, ['array', arr]);
    } else throw new Malformed('entry type ' + t);
  }
  return out;
}

function findKey(map, lower) {
  for (const k of map.keys()) if (k.toLowerCase() === lower) return k;
  return null;
}

// CfgMods > <mod> > defs > <module> > files[] : [mod, module, path]
function pathsFromBin(b) {
  const out = [];
  const root = rapClass(b, 16);
  const key = findKey(root, 'cfgmods');
  if (!key) return out;
  for (const [mn, [k, o]] of rapClass(b, root.get(key)[1])) {
    if (k !== 'class') continue;
    const d = rapClass(b, o);
    const dk = findKey(d, 'defs');
    if (!dk) continue;
    for (const [dn, [k2, o2]] of rapClass(b, d.get(dk)[1])) {
      if (k2 !== 'class') continue;
      for (const [fk, [k3, v]] of rapClass(b, o2)) {
        if (fk.toLowerCase() === 'files' && k3 === 'array') {
          for (const x of v) if (typeof x === 'string') out.push([mn, dn, x]);
        }
      }
    }
  }
  return out;
}

const LINE_COMMENT = re('//[^\\n]*');
const BLOCK_COMMENT = re('/\\*.*?\\*/', 'S');
const MODULE = re('class\\s+(\\w+ScriptModule)\\s*\\{[^{}]*?files\\[\\]\\s*=\\s*\\{([^}]*)\\}', 'SI');
const QUOTED = re('"([^"]*)"');

function pathsFromCpp(t) {
  const out = [];
  const s = t.replace(LINE_COMMENT, '').replace(BLOCK_COMMENT, '');
  for (const m of finditer(MODULE, s)) for (const x of findall(QUOTED, m[2])) out.push(['?', m[1], x]);
  return out;
}

function cmpTuple(a, b) {
  for (let i = 0; i < a.length; i++) {
    if (a[i] < b[i]) return -1;
    if (a[i] > b[i]) return 1;
  }
  return 0;
}

export async function backslashPaths(reader) {
  let paths = [];
  try {
    for (const { bytes } of await configEntries(reader)) {
      const isBin = bytes[0] === 0 && bytes[1] === 0x72 && bytes[2] === 0x61 && bytes[3] === 0x50;
      paths = paths.concat(isBin ? pathsFromBin(bytes) : pathsFromCpp(decodeUtf8(bytes)));
    }
  } catch (e) {
    return { error: String(e && e.message ? e.message : e) };
  }
  const seen = new Map();
  for (const [, d, x] of paths) if (x.includes('\\')) seen.set(d + '\0' + x, [d, x]);
  return { paths: [...seen.values()].sort(cmpTuple) };
}
