// Usage: node tools/parity.mjs <vanilla.json> <mods.tsv> <mods root> <out.json>
import fs from 'node:fs';
import path from 'node:path';
import { makeScanner } from '../docs/js/scan.js';
import { loadMod } from '../docs/js/load.js';
import { re, stripChars } from '../docs/js/pyre.js';

const [vanillaPath, tsv, root, outPath] = process.argv.slice(2);

function fileReader(p) {
  const fd = fs.openSync(p, 'r');
  const size = fs.fstatSync(fd).size;
  return {
    size,
    async read(off, len) {
      len = Math.max(0, Math.min(len, size - off));
      const buf = Buffer.alloc(len);
      if (len) fs.readSync(fd, buf, 0, len, off);
      return new Uint8Array(buf.buffer, buf.byteOffset, len);
    },
  };
}

const BAD = re('[^\\w.-]');
const sanitise = (s) => stripChars(s.replace(BAD, '_'), ' .') || '_';

const vanilla = JSON.parse(fs.readFileSync(vanillaPath, 'utf8'));
const scanner = makeScanner(vanilla);
const mods = [];
for (const line of fs.readFileSync(tsv, 'utf8').split('\n')) {
  if (!line.trim()) continue;
  const [n, kind, folder] = line.replace(/\r$/, '').split('\t').map((x) => x.trim());
  const dir = path.join(root, folder);
  const addons = fs.existsSync(dir) ? fs.readdirSync(dir).find((d) => d.toLowerCase() === 'addons') : null;
  const pbos = addons
    ? fs.readdirSync(path.join(dir, addons)).filter((f) => f.toLowerCase().endsWith('.pbo')).map((f) => ({ name: f, reader: fileReader(path.join(dir, addons, f)) }))
    : [];
  // same numbering as extract.py
  const used = new Set();
  const rel = (pbo, name) => {
    const parts = name.split('/').filter((s) => s).map(sanitise);
    const base = parts[parts.length - 1];
    let key = [n, pbo, ...parts].join('/').toLowerCase();
    for (let k = 2; used.has(key); k++) {
      const dot = base.lastIndexOf('.');
      parts[parts.length - 1] = dot > 0 ? base.slice(0, dot) + '~' + k + base.slice(dot) : base + '~' + k;
      key = [n, pbo, ...parts].join('/').toLowerCase();
    }
    used.add(key);
    return [n, pbo, ...parts].join('/');
  };
  mods.push(await loadMod({ id: n, mod: folder, kind, pbos }, rel));
}
const t0 = Date.now();
const report = scanner.scan(mods);
fs.writeFileSync(outPath, JSON.stringify(report, null, 1));
console.log('scanned', mods.length, 'mods in', ((Date.now() - t0) / 1000).toFixed(1), 's', JSON.stringify(scanner.stats));
