"""Rough Enforce Script structure parser: classes, bases, methods (with signatures), fields."""
import re

MODS = {'override', 'static', 'proto', 'native', 'private', 'protected', 'event', 'external', 'volatile',
        'owned', 'ref', 'reference', 'notnull', 'const', 'autoptr', 'sealed', 'modded', 'extern'}


def strip(src):
    """Remove comments, blank out string/char literals, drop preprocessor lines."""
    out = []
    i = 0
    n = len(src)
    while i < n:
        c = src[i]
        if c == '/' and i + 1 < n and src[i + 1] == '/':
            j = src.find('\n', i)
            i = n if j < 0 else j
            continue
        if c == '/' and i + 1 < n and src[i + 1] == '*':
            j = src.find('*/', i + 2)
            i = n if j < 0 else j + 2
            out.append(' ')
            continue
        if c == '"' or c == "'":
            j = i + 1
            while j < n and src[j] != c:
                j += 2 if src[j] == '\\' else 1
            out.append(c + c)
            i = j + 1
            continue
        out.append(c)
        i += 1
    lines = ''.join(out).split('\n')
    return '\n'.join(l for l in lines if not l.lstrip().startswith('#'))


def nocomment(src):
    """Remove comments but keep string literals, directives and the line count (for pattern hits with line numbers)."""
    out = []
    i = 0
    n = len(src)
    while i < n:
        c = src[i]
        if c == '/' and i + 1 < n and src[i + 1] == '/':
            j = src.find('\n', i)
            i = n if j < 0 else j
            continue
        if c == '/' and i + 1 < n and src[i + 1] == '*':
            j = src.find('*/', i + 2)
            j = n if j < 0 else j + 2
            out.append('\n' * src.count('\n', i, j) or ' ')
            i = j
            continue
        if c == '"' or c == "'":
            j = i + 1
            while j < n and src[j] != c and src[j] != '\n':
                j += 2 if src[j] == '\\' else 1
            out.append(src[i:j + 1])
            i = j + 1
            continue
        out.append(c)
        i += 1
    return ''.join(out)


DIRECTIVE = re.compile(r'^\s*#\s*(ifdef|ifndef|if|elif|else|endif)\b\s*(.*)$')


def _cond(kind, arg, defines):
    """True/False when the condition only names symbols in `defines`, None when unknown."""
    arg = arg.split('//')[0].strip()
    if kind in ('ifdef', 'ifndef'):
        v = defines.get(arg)
        return v if v is None or kind == 'ifdef' else not v
    m = re.fullmatch(r'(!?)\s*(?:defined\s*\(?\s*)?(\w+)\s*\)?', arg)
    if not m or m.group(2) not in defines:
        return None
    return defines[m.group(2)] != bool(m.group(1))


def preprocess(src, defines):
    """Blank the lines a server with `defines` ({name: bool}) would not compile, and every directive line.
    Symbols missing from `defines` (mod defines, SERVER, ...) keep both branches. Line count is kept."""
    out = []
    stack = []  # [enclosing active, cond (True/False/None), a branch was taken]
    for line in src.split('\n'):
        m = DIRECTIVE.match(line)
        active = all(f[0] and f[1] is not False for f in stack)
        if not m:
            out.append(line if active else '')
            continue
        kind, arg = m.group(1), m.group(2)
        if kind in ('ifdef', 'ifndef', 'if'):
            c = _cond(kind, arg, defines)
            stack.append([active, c, c is True])
        elif stack and kind == 'elif':
            f = stack[-1]
            c = _cond('if', arg, defines)
            f[1] = False if f[2] else c
            f[2] = f[2] or c is True
        elif stack and kind == 'else':
            f = stack[-1]
            f[1] = None if f[1] is None else not f[2]
        elif stack and kind == 'endif':
            stack.pop()
        out.append('')
    return '\n'.join(out)


V129 = {'DAYZ_1_29': True, 'DAYZ_1_30': False}
V130 = {'DAYZ_1_29': False, 'DAYZ_1_30': True}


def split_top(s):
    parts = []
    d = 0
    cur = ''
    for ch in s:
        if ch in '<([':
            d += 1
        elif ch in '>)]':
            d -= 1
        if ch == ',' and d == 0:
            parts.append(cur)
            cur = ''
        else:
            cur += ch
    if cur.strip():
        parts.append(cur)
    return parts


def norm_param(p):
    p = p.split('=')[0].strip()
    p = re.sub(r'\s+', ' ', p)
    toks = p.replace('<', ' < ').replace('>', ' > ').replace('[', ' [ ').replace(']', ' ] ').replace(',', ' , ').split()
    if not toks:
        return ''
    # drop the parameter name: last identifier, unless it closes a template
    if len(toks) > 1 and re.match(r'^\w+$', toks[-1]) and toks[-2] not in ('<', ','):
        toks = toks[:-1]
    toks = [t for t in toks if t not in ('const', 'notnull', 'owned', 'ref', 'autoptr')]
    return ' '.join(toks).replace(' < ', '<').replace(' > ', '>').replace(' , ', ',').strip().lower()


HDR = re.compile(r'(?:^|[\s;}])((?:(?:modded|sealed)\s+)*)class\s+(\w+)\s*(?:<[^>{]*>)?\s*(?:(?:extends|:)\s*(\w+)(?:<[^>{]*>)?)?\s*$')
METH = re.compile(r'([\w<>,\s\[\]]*?)\b(\w+)\s*\(([^()]*(?:\([^()]*\)[^()]*)*)\)\s*$', re.S)
KW = {'if', 'while', 'for', 'switch', 'foreach', 'return', 'else'}


def _method(cur, text):
    mm = METH.search(text)
    if not mm or mm.group(2) in KW:
        return False
    head = text[:mm.start(2)]
    obsolete = bool(re.search(r'\[\s*Obsolete', head))
    pre = mm.group(1).split()
    ret = [t for t in pre if t not in MODS and t not in (']', '[')]
    cur['methods'].setdefault(mm.group(2), []).append({
        'ret': ' '.join(ret).lower(),
        'params': tuple(norm_param(p) for p in split_top(mm.group(3)) if p.strip()),
        'override': 'override' in pre,
        'static': 'static' in pre,
        'obsolete': obsolete,
        'access': 'private' if 'private' in pre else 'protected' if 'protected' in pre else 'public',
    })
    return True


def parse(src, defines=None):
    """`defines` ({name: bool}, e.g. V130) drops the #ifdef branches that version would not compile."""
    s = strip(preprocess(src, defines) if defines else src)
    n = len(s)
    i = 0
    depth = 0
    buf = ''
    classes = []
    stack = []
    while i < n:
        ch = s[i]
        if ch == '{':
            cur = stack[-1] if stack else None
            m = HDR.search(buf) if (not cur or depth == cur['_d']) else None
            if m:
                c = {'name': m.group(2), 'base': m.group(3), 'modded': 'modded' in m.group(1),
                     'methods': {}, 'fields': set(), '_d': depth + 1}
                classes.append(c)
                stack.append(c)
                depth += 1
                buf = ''
                i += 1
                continue
            if cur and depth == cur['_d']:
                _method(cur, buf.strip())
                d = 1
                j = i + 1
                while j < n and d:
                    if s[j] == '{':
                        d += 1
                    elif s[j] == '}':
                        d -= 1
                    j += 1
                i = j
                buf = ''
                continue
            depth += 1
            buf = ''
            i += 1
            continue
        if ch == '}':
            if stack and depth == stack[-1]['_d']:
                stack.pop()
            depth -= 1
            buf = ''
            i += 1
            continue
        if ch == ';':
            cur = stack[-1] if stack else None
            if cur and depth == cur['_d']:
                st = buf.strip()
                if '(' in st.split('=')[0] and _method(cur, st):
                    pass
                elif st and not st.startswith(('typedef', 'enum')):
                    left = st.split('=')[0]
                    for part in split_top(left):
                        ids = re.findall(r'\b(\w+)\b(?:\s*\[[^\]]*\])?\s*$', part.strip())
                        if ids:
                            cur['fields'].add(ids[-1])
            buf = ''
            i += 1
            continue
        buf += ch
        i += 1
    for c in classes:
        del c['_d']
    return classes
