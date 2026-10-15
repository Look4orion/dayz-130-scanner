import { extractScripts, backslashPaths } from './pbo.js?v=202610151114';
import { decodeText } from './pyre.js?v=202610151114';

export async function loadMod(mod, rel = (pbo, name) => pbo + '/' + name) {
  const out = { id: mod.id, mod: mod.mod, kind: mod.kind, files: [], scriptPaths: [], pbos: [] };
  const pbos = [...mod.pbos].sort((a, b) => (a.name < b.name ? -1 : a.name > b.name ? 1 : 0));
  for (const p of pbos) {
    let note;
    try {
      note = await extractScripts(p.reader);
    } catch (e) {
      out.pbos.push({ name: p.name, unreadable: 1, compressed: 0, error: String(e && e.message ? e.message : e) });
      continue;
    }
    out.pbos.push({ name: p.name, prefix: note.prefix, unreadable: note.unreadable, compressed: note.compressed });
    for (const f of note.files) {
      if (f.name.toLowerCase().endsWith('.c')) out.files.push({ rel: rel(p.name, f.name), pbo: p.name, name: f.name, text: decodeText(f.bytes) });
    }
    const bp = await backslashPaths(p.reader);
    for (const [module, path] of bp.paths || []) out.scriptPaths.push({ pbo: p.name, module, path });
  }
  return out;
}
