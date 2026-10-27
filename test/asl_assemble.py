#!/usr/bin/env python3
"""asl_assemble.py <statements.txt> <out.txt> [workdir]: assemble each statement with asl (-cpu st7)
and print "<hex bytes>\t<statement>" or "ERR\t<statement>\t<message>". A statement line may be
"<hex address>\t<statement>" to assemble at that address (default $1000)."""
import re, subprocess, sys, os, tempfile

stm = []
addrs = []
for l in open(sys.argv[1]):
    l = l.rstrip('\n')
    if not l.strip():
        continue
    if '\t' in l:
        a, l = l.split('\t', 1)
        addrs.append(int(a, 16))
    else:
        addrs.append(0x1000)
    stm.append(l)
out = open(sys.argv[2], 'w')
wd = os.path.abspath(sys.argv[3]) if len(sys.argv) > 3 else tempfile.mkdtemp()
os.makedirs(wd, exist_ok=True)
CHUNK = 500
for c in range(0, len(stm), CHUNK):
    part = stm[c:c + CHUNK]
    src = os.path.join(wd, 'c.asm')
    with open(src, 'w') as f:
        f.write('\tcpu st7\n')
        for i, s in enumerate(part):
            f.write('\torg $%x\n\t' % addrs[c + i] + s + '\n')
    if os.path.exists(os.path.join(wd, 'c.lst')):
        os.remove(os.path.join(wd, 'c.lst'))
    subprocess.run(['asl', '-L', '-q', '-cpu', 'st7', src], cwd=wd, capture_output=True)
    lst = open(os.path.join(wd, 'c.lst')).read().split('\n')
    # map source line number -> bytes / error
    res = {}
    err = {}
    pending = None
    for l in lst:
        m = re.match(r'^\s*(\d+)/\s*[0-9A-F]+ :\s+((?:[0-9A-F]{2} )+)\s*(.*)$', l)
        m2 = re.match(r'^\s*(\d+)/\s*[0-9A-F]+ :\s+(\S.*)$', l)
        e = re.match(r'^> > > \S+\((\d+)\):\d+: (error.*)$', l)
        if e:
            err[int(e.group(1))] = e.group(2)
            continue
        if m:
            res[int(m.group(1))] = m.group(2).split()
        elif m2:
            pass
    for i, s in enumerate(part):
        ln = 2 + 2 * i + 1 + 0  # cpu line=1, org=2+2i, stmt=3+2i
        b = res.get(ln)
        if b is not None and ln - 0 not in err:
            out.write(''.join(b).lower() + '\t' + s + '\n')
        else:
            out.write('ERR\t' + s + '\t' + err.get(ln, err.get(ln - 1, 'no output')) + '\n')
out.close()
