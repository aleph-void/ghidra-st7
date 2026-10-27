#!/usr/bin/env python3
"""ucsim_dis.py <cases.txt> <out.txt>: disassemble each hex case (<= 5 bytes) with the uCsim ST7
simulator (UCSIM_ST7 environment variable, run as a black box). Output "<hex> <len> <text>"
(text "BAD" when ucsim prints UNKNOWN/INVALID)."""
import os, re, subprocess, sys, tempfile

U = os.environ.get('UCSIM_ST7', os.path.expanduser(
    '~/.cache/ghidra-rare-scratch/tools/ucsim-src/ucsim/src/sims/st7.src/ucsim_st7'))
cases = [l.strip() for l in open(sys.argv[1]) if l.strip()]
out = open(sys.argv[2], 'w')
PER = 6000            # 8-byte slots from 0x1000 (stay below the 64K limit)
for c0 in range(0, len(cases), PER):
    part = cases[c0:c0 + PER]
    cmds = []
    for i, c in enumerate(part):
        a = 0x1000 + 8 * i
        bs = bytes.fromhex(c)[:5] + bytes(8 - min(5, len(c) // 2))
        cmds.append('set memory rom 0x%x %s' % (a, ' '.join('0x%02x' % x for x in bs)))
    for i, c in enumerate(part):
        a = 0x1000 + 8 * i
        cmds.append('dc 0x%x 0x%x' % (a, a))
    cmds.append('quit')
    cf = tempfile.NamedTemporaryFile('w', suffix='.cmd', delete=False, dir=os.environ.get('TMPDIR', '/tmp'))
    cf.write('\n'.join(cmds) + '\n'); cf.close()
    p = subprocess.run([U, '-b', '-q', '-C', cf.name], stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                       stderr=subprocess.STDOUT, text=True, timeout=900)
    os.unlink(cf.name)
    res = {}
    want = None
    for l in p.stdout.split('\n'):
        m = re.match(r'^(?:\d+> )*dc 0x([0-9a-f]+) ', l)
        if m:
            want = int(m.group(1), 16)
            continue
        m = re.match(r'^0x([0-9a-f]{4})\s+((?:[0-9a-f]{2} )+)\s*(.*?)\s*$', l)
        if m and want is not None and int(m.group(1), 16) == want:
            res[want] = (len(m.group(2).split()), m.group(3))
            want = None
    for i, c in enumerate(part):
        a = 0x1000 + 8 * i
        n, t = res.get(a, (0, 'MISSING'))
        if 'UNKNOWN' in t:
            n, t = 0, 'BAD'
        else:
            # relative branches: show the target as if the case sat at 0x1000 (what Ghidra's dump uses)
            m = re.match(r'^(jr\w+|callr)\s+0x([0-9a-f]+)$', t) or re.match(r'^(.*,)0x([0-9a-f]+)$', t) \
                if re.match(r'^(jr\w+|callr|bjtf|btjt|btjf)', t) else None
            if m:
                t = '%s%s0x%04x' % (m.group(1), '' if m.group(1).endswith(',') else ' ',
                                    (int(m.group(2), 16) - a + 0x1000) & 0xffff)
        out.write('%s %d %s\n' % (c, n, t))
out.close()
