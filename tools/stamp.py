"""Put a version on every file the page loads, so a browser never mixes cached files from two releases.
Usage: python -I tools/stamp.py [version]   (default: the current UTC time). Run it before each push of docs/."""
import sys, os, re, glob, datetime

ver = sys.argv[1] if len(sys.argv) > 1 else datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%d%H%M')
docs = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'docs')
REF = re.compile(r'''(['"])((?:\.\.?/|js/)[\w./-]+\.(?:js|json|css)|style\.css)(?:\?v=[^'"]*)?\1''')
for f in [os.path.join(docs, 'index.html')] + glob.glob(os.path.join(docs, 'js', '*.js')):
    src = open(f, encoding='utf-8', newline='').read()
    out = REF.sub(lambda m: m.group(1) + m.group(2) + '?v=' + ver + m.group(1), src)
    if out != src:
        open(f, 'w', encoding='utf-8', newline='').write(out)
        print('stamped', os.path.relpath(f, docs), ver)
