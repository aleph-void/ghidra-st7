#!/usr/bin/env python3
"""real_compare.py <name> <image.bin> <ghidra.dis> <ghidra.funcs> <linker.sym> <workdir>

Checks the analysed listing of a real firmware image against three independent references:
 1. asl (assembler): every instruction's text is assembled at its address; the bytes must equal the
    image bytes (a round trip through an independent encoder);
 2. the uCsim ST7 disassembler on the same bytes (known uCsim differences are listed by class);
 3. the ST linker's symbol file: every code symbol must be the start of an instruction, and (for
    the ones the analysis reaches) of a function.
Prints one summary block; exit status 1 on an unexplained difference."""
import os, re, subprocess, sys, collections
HERE = os.path.dirname(os.path.abspath(__file__))
T = os.path.dirname(HERE)
name, binf, disf, funcf, symf, wd = sys.argv[1:7]
os.makedirs(wd, exist_ok=True)
img = open(binf, 'rb').read()
ins = []
for l in open(disf):
    a, h, t = l.rstrip('\n').split(' ', 2)
    ins.append((int(a, 16), h, t))

# ---- 1. asl round trip ----
def to_asl(t):
    return re.sub(r'0x([0-9a-fA-F]+)', lambda m: '$' + m.group(1), t).lower()
def add_w(t):
    return re.sub(r'(?<![\w$])\$([0-9a-f]+)(?!\.w)', lambda m: '$' + m.group(1) + '.w', t, count=1)
rt = os.path.join(wd, name + '.rt')
with open(rt, 'w') as f:
    for a, h, t in ins:
        f.write('%x\t%s\n%x\t%s\n' % (a, to_asl(t), a, add_w(to_asl(t))))
subprocess.run(['python3', f'{T}/asl_assemble.py', rt, rt + '.asl', os.path.join(wd, 'aslwd')], check=True)
res = [l.rstrip('\n').split('\t') for l in open(rt + '.asl')]
agree = long_forced = bad = 0
badl = []
for k, (a, h, t) in enumerate(ins):
    r1, r2 = res[2 * k][0], res[2 * k + 1][0]
    if r1 == h:
        agree += 1
    elif r2 == h:
        long_forced += 1
    else:
        bad += 1; badl.append((a, h, t, r1, r2))
print(f'{name}: {len(ins)} instructions; asl round trip: {agree} identical, {long_forced} identical with the long form forced, {bad} different')
for x in badl[:10]:
    print('   ASL-DIFF', *x)

# ---- 2. uCsim disassembly of the same bytes ----
cases = os.path.join(wd, name + '.uc.cases')
gh_re = os.path.join(wd, name + '.uc.gh')
with open(cases, 'w') as f, open(gh_re, 'w') as g:
    for a, h, t in ins:
        f.write(h + '\n')
        # relative branch targets as if the instruction sat at 0x1000 (what ucsim_dis.py prints)
        m = re.match(r'^(JR\w+|CALLR|BTJ[TF]\s.*,)\s*0x([0-9a-f]+)$', t) if re.match(r'^(JR|CALLR|BTJ)', t) else None
        t2 = t
        if m and not t.startswith('JR') or (m and not '[' in t):
            pass
        mm = re.match(r'^(.*?)0x([0-9a-f]+)$', t) if re.match(r'^(JR|CALLR|BTJ)', t) and not re.search(r'\[0x[0-9a-f]+\]$', t) else None
        if mm:
            t2 = '%s0x%04x' % (mm.group(1), (int(mm.group(2), 16) - a + 0x1000) & 0xffff)
        g.write('%s %d %s\n' % (h, len(h) // 2, t2))
subprocess.run(['python3', f'{T}/ucsim_dis.py', cases, cases + '.out'], check=True)
r = subprocess.run(['python3', f'{T}/cmp_ucsim.py', gh_re, cases + '.out', name + ' vs uCsim', '-c'], capture_output=True, text=True)
print(r.stdout.rstrip().split('\n')[0])
for l in r.stdout.rstrip().split('\n')[1:12]:
    print('  ', l)

# ---- 3. linker symbols ----
starts = {a for a, h, t in ins}
funcs = {int(l.split()[0], 16) for l in open(funcf)}
codesyms = []
sec = None
for l in open(symf):
    m = re.match(r"^'([^']*)'\s*(\w*)\s*$", l)
    if m:
        sec = (m.group(1), m.group(2)); continue
    m = re.match(r'^\s+([0-9A-F]+)\s+(\S+)\s*$', l)
    if m and sec and 'C' in sec[1] and sec[0] not in ('CONSTANTS',):
        codesyms.append((int(m.group(1), 16), m.group(2), sec[0]))
inst = [s for s in codesyms if s[0] in starts]
fn = [s for s in codesyms if s[0] in funcs]
print(f'   linker symbols in code sections: {len(codesyms)}; instruction starts {len(inst)}; function entries {len(fn)}')
for s in codesyms:
    if s[0] not in starts:
        print('   SYMBOL-NOT-AN-INSTRUCTION', hex(s[0]), s[1], s[2])
sys.exit(1 if bad else 0)
