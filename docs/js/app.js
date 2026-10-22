const LEVELS = [
  ['BREAK', 'Breaks on 1.30', 'break'],
  ['RISK', 'Check by hand (1.30)', 'risk'],
  ['INFO', 'Good to know (1.30)', 'info'],
  ['BREAK_129', "Won't compile on 1.29", 'break'],
  ['RISK_129', 'Check by hand (1.29)', 'risk'],
];
const SHOW_LOCATIONS = 8;

const $ = (id) => document.getElementById(id);
const drop = $('drop');
const status = $('status');
const results = $('results');
let lastReport = null;

function el(tag, attrs = {}, ...kids) {
  const e = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') e.className = v;
    else if (k.startsWith('on')) e.addEventListener(k.slice(2), v);
    else e.setAttribute(k, v);
  }
  for (const k of kids) if (k !== null && k !== undefined) e.append(k);
  return e;
}

// ---- collecting files ----
// Only the files a scan reads are opened; anything that can't be read is skipped and counted.
const wanted = (name) => {
  const low = name.toLowerCase();
  return low.endsWith('.pbo') || low === 'meta.cpp' || low === 'mod.cpp';
};

// A folder link (the DayZ Launcher's !Workshop folders are junctions) can make a read never answer.
const timed = (p) => Promise.race([p, new Promise((_, rej) => setTimeout(() => rej(new Error('timed out')), 5000))]);

async function entriesFromDrop(items) {
  const out = [];
  let seen = 0;
  let skipped = 0;
  const walk = async (entry, path) => {
    seen += 1;
    if (seen % 200 === 0) status.textContent = `Collecting files... ${seen} looked at, ${out.length} to scan`;
    try {
      if (entry.isFile) {
        if (!wanted(entry.name)) return;
        const file = await timed(new Promise((res, rej) => entry.file(res, rej)));
        out.push({ path: path + entry.name, file });
      } else if (entry.isDirectory) {
        const reader = entry.createReader();
        for (;;) {
          const batch = await timed(new Promise((res, rej) => reader.readEntries(res, rej)));
          if (!batch.length) break;
          for (const e of batch) await walk(e, path + entry.name + '/');
        }
      }
    } catch {
      skipped += 1;
    }
  };
  const roots = [];
  for (const it of items) {
    const entry = it.webkitGetAsEntry ? it.webkitGetAsEntry() : null;
    if (entry) roots.push(entry);
  }
  for (const r of roots) await walk(r, '');
  return { files: out, skipped };
}

const metaName = /^\s*name\s*=\s*"([^"]*)"/m;

async function groupMods(files) {
  const groups = new Map();
  const metas = new Map();
  for (const { path, file } of files) {
    const parts = path.split('/').filter(Boolean);
    const low = parts.map((p) => p.toLowerCase());
    const name = low[low.length - 1];
    if (name === 'meta.cpp' || name === 'mod.cpp') {
      metas.set(parts.slice(0, -1).join('/') + '|' + name, file);
      continue;
    }
    if (!name.endsWith('.pbo')) continue;
    const ai = low.lastIndexOf('addons');
    let key;
    let mod;
    if (ai > 0 && ai === parts.length - 2) {
      key = parts.slice(0, ai).join('/');
      mod = parts[ai - 1];
    } else if (parts.length > 1) {
      key = parts.slice(0, -1).join('/');
      mod = parts[parts.length - 2];
    } else {
      key = 'loose:' + parts[0];
      mod = parts[0];
    }
    if (!groups.has(key)) groups.set(key, { id: String(groups.size + 1), key, mod, pbos: [] });
    groups.get(key).pbos.push({ name: parts[parts.length - 1], file });
  }
  // Workshop folders are numbers; use the name from meta.cpp / mod.cpp
  for (const g of groups.values()) {
    for (const which of ['meta.cpp', 'mod.cpp']) {
      const f = metas.get(g.key + '|' + which);
      if (!f) continue;
      const m = metaName.exec(await f.text());
      if (m && m[1].trim()) {
        if (m[1].trim() !== g.mod) g.mod = m[1].trim() + ' (' + g.mod + ')';
        break;
      }
    }
  }
  return [...groups.values()];
}

// ---- scanning ----
let worker = null;

function run(groups) {
  if (!groups.length) {
    status.textContent = 'No .pbo files found. Drop a mod folder (the one with an Addons folder inside), or the .pbo files themselves.';
    return;
  }
  results.replaceChildren();
  status.textContent = 'Starting...';
  drop.classList.add('busy');
  if (worker) worker.terminate();
  worker = new Worker(new URL('./worker.js?v=202610220104', import.meta.url), { type: 'module' });
  worker.onmessage = (ev) => {
    const d = ev.data;
    if (d.type === 'progress') {
      status.textContent = `${d.phase} ${d.done + 1} of ${d.total}: ${d.mod}`;
    } else if (d.type === 'done') {
      drop.classList.remove('busy');
      const n = groups.length;
      status.textContent = `Scanned ${n} mod${n === 1 ? '' : 's'} against DayZ ${d.versions.previous} and ${d.versions.stable}.`;
      lastReport = { groups, report: d.report, errors: d.errors };
      render(lastReport);
      tally({ p: 'scan', t: 'Scan', e: 'true' });
    } else if (d.type === 'error') {
      drop.classList.remove('busy');
      status.textContent = 'Scan failed: ' + d.message;
    }
  };
  worker.onerror = (e) => {
    drop.classList.remove('busy');
    status.textContent = 'Scan failed: ' + (e.message || 'worker error');
  };
  worker.postMessage({ groups: groups.map((g) => ({ id: g.id, mod: g.mod, pbos: g.pbos })) });
}

// ---- report ----
const count = (r, lv) => Object.keys(r[lv]).length;

function severity(r) {
  return [count(r, 'BREAK') + count(r, 'BREAK_129'), count(r, 'RISK') + count(r, 'RISK_129'), count(r, 'INFO')];
}

function verdict(r) {
  const [b, k] = severity(r);
  if (count(r, 'BREAK')) return ['break', 'Breaks on 1.30'];
  if (count(r, 'BREAK_129')) return ['break', "Won't compile on 1.29"];
  if (k) return ['risk', 'Check by hand'];
  if (!r.files) return ['none', 'No scripts'];
  return ['ok', 'No known breakers'];
}

function sortedMods(rep) {
  return rep.groups
    .map((g) => ({ g, r: rep.report[g.id] }))
    .sort((a, b) => {
      const sa = severity(a.r);
      const sb = severity(b.r);
      for (let i = 0; i < 3; i++) if (sa[i] !== sb[i]) return sb[i] - sa[i];
      return a.g.mod.localeCompare(b.g.mod);
    });
}

function render(rep) {
  const hideInfo = $('hide-info').checked;
  const list = el('div', { class: 'mods' });
  for (const { g, r } of sortedMods(rep)) {
    const [cls, label] = verdict(r);
    const counts = el('span', { class: 'counts' });
    for (const [lv, , c] of LEVELS) {
      const n = count(r, lv);
      if (n && !(hideInfo && lv === 'INFO')) counts.append(el('span', { class: 'pill ' + c, title: LEVELS.find((x) => x[0] === lv)[1] }, `${n} ${lv.replace('_129', ' 1.29').toLowerCase()}`));
    }
    const body = el('div', { class: 'detail' });
    for (const [lv, title, c] of LEVELS) {
      if (hideInfo && lv === 'INFO') continue;
      const msgs = Object.keys(r[lv]);
      if (!msgs.length) continue;
      body.append(el('h4', { class: c }, title));
      for (const msg of msgs) {
        const locs = r[lv][msg];
        const ul = el('ul', { class: 'locs' });
        locs.slice(0, SHOW_LOCATIONS).forEach((l) => ul.append(el('li', {}, l)));
        const item = el('div', { class: 'hit' }, el('div', { class: 'msg' }, msg), ul);
        if (locs.length > SHOW_LOCATIONS) {
          const more = el('button', { class: 'more', type: 'button' }, `${locs.length - SHOW_LOCATIONS} more`);
          more.addEventListener('click', () => {
            locs.slice(SHOW_LOCATIONS).forEach((l) => ul.append(el('li', {}, l)));
            more.remove();
          });
          item.append(more);
        }
        body.append(item);
      }
    }
    const notes = [];
    if (r.unscanned_pbos.length) notes.push('Some entries could not be read in: ' + r.unscanned_pbos.join(', ') + '. Those files were not checked.');
    for (const e of rep.errors[g.id] || []) notes.push('Could not read ' + e);
    if (!r.files) notes.push('No script files: there is nothing for 1.30 script changes to break.');
    for (const n of notes) body.append(el('p', { class: 'note' }, n));
    if (!body.childNodes.length) body.append(el('p', { class: 'note' }, `${r.files} script files checked; no known 1.30 breakers found.`));
    const pbos = g.pbos.length;
    const det = el('details', { class: 'mod ' + cls },
      el('summary', {},
        el('span', { class: 'verdict ' + cls }, label),
        el('span', { class: 'name' }, g.mod),
        el('span', { class: 'meta' }, `${pbos} PBO${pbos === 1 ? '' : 's'}, ${r.files} script${r.files === 1 ? '' : 's'}`),
        counts),
      body);
    if (cls === 'break' && rep.groups.length <= 3) det.open = true;
    list.append(det);
  }
  const bar = el('div', { class: 'bar' },
    el('button', { type: 'button', onclick: () => copyText(rep) }, 'Copy report'),
    el('button', { type: 'button', onclick: () => downloadText(rep) }, 'Download .txt'),
    el('span', { id: 'copied', class: 'copied' }));
  results.replaceChildren(bar, list);
}

function asText(rep) {
  const hideInfo = $('hide-info').checked;
  const lines = [];
  for (const { g, r } of sortedMods(rep)) {
    const [, label] = verdict(r);
    lines.push(`**${g.mod}**: ${label} (${r.files} scripts)`);
    for (const [lv, title] of LEVELS) {
      if (hideInfo && lv === 'INFO') continue;
      for (const msg of Object.keys(r[lv])) {
        const locs = r[lv][msg];
        lines.push(`- ${title}: ${msg}`);
        locs.slice(0, 5).forEach((l) => lines.push(`  - ${l}`));
        if (locs.length > 5) lines.push(`  - ...and ${locs.length - 5} more`);
      }
    }
    lines.push('');
  }
  lines.push('Static scan only: a clean result means no known 1.30 breaker was found, not that the mod works.');
  return lines.join('\n');
}

async function copyText(rep) {
  try {
    await navigator.clipboard.writeText(asText(rep));
    $('copied').textContent = 'Copied';
  } catch {
    $('copied').textContent = 'Copy failed; use Download';
  }
}

function downloadText(rep) {
  const url = URL.createObjectURL(new Blob([asText(rep)], { type: 'text/plain' }));
  const a = el('a', { href: url, download: 'dayz-130-scan.txt' });
  document.body.append(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

// ---- GoatCounter: page views and scans only ----
const COUNTER = 'https://rook1969.goatcounter.com/count';
function tally(params) {
  if (!location.hostname.endsWith('github.io')) return;
  const q = new URLSearchParams({ ...params, rnd: Math.random().toString(36).slice(2) });
  new Image().src = COUNTER + '?' + q.toString();
}
tally({ p: location.pathname, t: document.title, r: document.referrer });

// ---- wiring ----
drop.addEventListener('dragover', (e) => {
  e.preventDefault();
  drop.classList.add('over');
});
drop.addEventListener('dragleave', () => drop.classList.remove('over'));
drop.addEventListener('drop', async (e) => {
  e.preventDefault();
  drop.classList.remove('over');
  status.textContent = 'Collecting files...';
  try {
    const { files, skipped } = await entriesFromDrop([...e.dataTransfer.items]);
    const groups = await groupMods(files);
    if (!groups.length && skipped) {
      status.textContent = "The browser couldn't open that folder. Mod folders under DayZ\\!Workshop are links, which browsers don't follow: drop the mod's addons folder, or the mod's real folder in steamapps\\workshop\\content\\221100.";
      return;
    }
    run(groups);
    if (skipped) status.textContent += ` (${skipped} file${skipped === 1 ? '' : 's'} or folder${skipped === 1 ? '' : 's'} couldn't be read and were skipped)`;
  } catch (err) {
    status.textContent = 'Could not read what was dropped: ' + (err && err.message ? err.message : err) + '. Try "Choose folder" instead.';
  }
});
$('pick-folder').addEventListener('change', async (e) => {
  const files = [...e.target.files].map((f) => ({ path: f.webkitRelativePath || f.name, file: f }));
  e.target.value = '';
  run(await groupMods(files));
});
$('pick-files').addEventListener('change', async (e) => {
  const files = [...e.target.files].map((f) => ({ path: f.name, file: f }));
  e.target.value = '';
  run(await groupMods(files));
});
$('hide-info').addEventListener('change', () => {
  if (lastReport) render(lastReport);
});
