// Python re / str behaviour in JS, so results match the Python scanner exactly.

// Python's whitespace
const WS = '\\t\\n\\x0b\\x0c\\r\\x1c-\\x20\\x85\\xa0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000';
const WORD = '\\p{L}\\p{N}_';
const WS_SET = new RegExp('[' + WS + ']', 'u');

function translate(pattern, multiline, dotall) {
  let out = '';
  let inClass = false;
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i];
    if (c === '\\') {
      const n = pattern[++i];
      if (inClass) {
        if (n === 's') out += WS;
        else if (n === 'w') out += WORD;
        else if (n === 'd') out += '\\p{Nd}';
        else out += '\\' + n;
      } else if (n === 's') out += '[' + WS + ']';
      else if (n === 'S') out += '[^' + WS + ']';
      else if (n === 'w') out += '[' + WORD + ']';
      else if (n === 'W') out += '[^' + WORD + ']';
      else if (n === 'd') out += '\\p{Nd}';
      else if (n === 'b') out += '(?:(?<=[' + WORD + '])(?![' + WORD + '])|(?<![' + WORD + '])(?=[' + WORD + ']))';
      else out += '\\' + n;
      continue;
    }
    if (inClass) {
      if (c === ']') inClass = false;
      out += c;
      continue;
    }
    if (c === '[') {
      inClass = true;
      out += c;
      if (pattern[i + 1] === '^') out += pattern[++i];
      continue;
    }
    if (c === '.') out += dotall ? '[\\s\\S]' : '[^\\n]';
    else if (c === '^') out += multiline ? '(?:^|(?<=\\n))' : '^';
    else if (c === '$') out += multiline ? '(?=\\n|(?![\\s\\S]))' : '(?=\\n?(?![\\s\\S]))';
    else out += c;
  }
  return out;
}

const cache = new Map();

// flags: 'I', 'M', 'S'
export function re(pattern, flags = '') {
  const key = flags + '\0' + pattern;
  let r = cache.get(key);
  if (!r) {
    const js = translate(pattern, flags.includes('M'), flags.includes('S'));
    r = new RegExp(js, 'gud' + (flags.includes('I') ? 'i' : ''));
    cache.set(key, r);
  }
  return r;
}

// re.search
export function search(rx, s, pos = 0) {
  rx.lastIndex = pos;
  return rx.exec(s);
}

// re.finditer
export function* finditer(rx, s) {
  rx.lastIndex = 0;
  let m;
  while ((m = rx.exec(s)) !== null) {
    yield m;
    if (m[0] === '') rx.lastIndex = m.index + (s.codePointAt(m.index) > 0xffff ? 2 : 1);
  }
}

// re.findall (one group at most)
export function findall(rx, s) {
  const out = [];
  for (const m of finditer(rx, s)) out.push(m.length > 1 ? m[1] : m[0]);
  return out;
}

// re.fullmatch
export function fullmatch(pattern, s, flags = '') {
  return search(re('^(?:' + pattern + ')(?![\\s\\S])', flags), s);
}

export function isSpace(ch) {
  return WS_SET.test(ch);
}

export function lstrip(s) {
  let i = 0;
  while (i < s.length && isSpace(s[i])) i++;
  return s.slice(i);
}

export function rstrip(s) {
  let j = s.length;
  while (j > 0 && isSpace(s[j - 1])) j--;
  return s.slice(0, j);
}

export function strip(s) {
  return rstrip(lstrip(s));
}

// str.strip(chars)
export function stripChars(s, chars) {
  let i = 0;
  let j = s.length;
  while (i < j && chars.includes(s[i])) i++;
  while (j > i && chars.includes(s[j - 1])) j--;
  return s.slice(i, j);
}

// str.split()
export function splitWs(s) {
  const out = [];
  let cur = '';
  for (const ch of s) {
    if (isSpace(ch)) {
      if (cur) out.push(cur);
      cur = '';
    } else cur += ch;
  }
  if (cur) out.push(cur);
  return out;
}

export function countChar(s, ch, start = 0, end = s.length) {
  let n = 0;
  for (let i = start; i < end; i++) if (s[i] === ch) n++;
  return n;
}

// like Python text mode: BOM kept, newlines normalised
const decoder = new TextDecoder('utf-8', { ignoreBOM: true });
export function decodeText(bytes) {
  return decoder.decode(bytes).replace(/\r\n/g, '\n').replace(/\r/g, '\n');
}

export function decodeUtf8(bytes) {
  return decoder.decode(bytes);
}
