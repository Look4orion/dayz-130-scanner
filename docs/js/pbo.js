// reader: { size, read(offset, length) -> Promise<Uint8Array> }

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
