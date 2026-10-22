import { makeScanner } from './scan.js?v=202610220525';
import { loadMod } from './load.js?v=202610220525';

let scannerPromise = null;

function getScanner() {
  if (!scannerPromise) {
    scannerPromise = fetch(new URL('../vanilla.json?v=202610220525', import.meta.url))
      .then((r) => {
        if (!r.ok) throw new Error('could not load vanilla.json (' + r.status + ')');
        return r.json();
      })
      .then(makeScanner);
  }
  return scannerPromise;
}

function fileReader(file) {
  return {
    size: file.size,
    async read(off, len) {
      return new Uint8Array(await file.slice(off, off + len).arrayBuffer());
    },
  };
}

self.onmessage = async (ev) => {
  const { groups } = ev.data;
  try {
    const scanner = await getScanner();
    const mods = [];
    for (let k = 0; k < groups.length; k++) {
      const g = groups[k];
      self.postMessage({ type: 'progress', phase: 'Reading', done: k, total: groups.length, mod: g.mod });
      mods.push(await loadMod({ id: g.id, mod: g.mod, kind: 'mod', pbos: g.pbos.map((p) => ({ name: p.name, reader: fileReader(p.file) })) }));
    }
    const report = scanner.scan(mods, (done, total, mod) => self.postMessage({ type: 'progress', phase: 'Scanning', done, total, mod }));
    const errors = {};
    for (const m of mods) {
      const bad = m.pbos.filter((p) => p.error);
      if (bad.length) errors[m.id] = bad.map((p) => p.name + ': ' + p.error);
    }
    self.postMessage({ type: 'done', report, errors, versions: scanner.versions });
  } catch (e) {
    self.postMessage({ type: 'error', message: String(e && e.message ? e.message : e) });
  }
};
