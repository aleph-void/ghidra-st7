#!/usr/bin/env python3
"""rand_diff.py <workdir> <language-id> [n=60000] [seed=1]
Random-word differential against asl (an assembler, so the check is a round trip):
 1. random 4-byte strings (about a third start with a pre-byte; some start with two) are decoded
    by Ghidra;
 2. every string Ghidra accepts is turned back into assembly text and assembled by asl; the bytes
    must equal the decoded bytes of the input;
 3. every string Ghidra rejects must not be an instruction asl can produce: the set of
    (pre-byte, opcode) pairs asl produces is taken from the exhaustive form list.
Prints counts per class; exit status 1 if anything is unexplained."""
import os, random, re, subprocess, sys
HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import asm_forms

wd = os.path.abspath(sys.argv[1]); lang = sys.argv[2]
n = int(sys.argv[3]) if len(sys.argv) > 3 else 60000
seed = int(sys.argv[4]) if len(sys.argv) > 4 else 1
os.makedirs(wd, exist_ok=True)
tag = lang.split(':')[0]

def run(*a):
    subprocess.run(a, check=True)

# 1. cases
rnd = random.Random(seed)
cases = []
for i in range(n):
    b = bytearray(rnd.getrandbits(8) for _ in range(5))
    r = rnd.random()
    if r < 0.30:
        b[0] = rnd.choice([0x90, 0x91, 0x92])
    elif r < 0.34:
        b[0] = rnd.choice([0x90, 0x91, 0x92]); b[1] = rnd.choice([0x90, 0x91, 0x92])
    cases.append(bytes(b))
with open(f'{wd}/{tag}.cases', 'w') as f:
    for c in cases:
        f.write(c.hex() + '\n')
run(f'{HERE}/dis.sh', lang, f'{wd}/{tag}.cases', f'{wd}/{tag}.gh')

# 2. valid (prefix, opcode) set from asl over the exhaustive forms
forms = f'{wd}/forms.txt'
open(forms, 'w').write('\n'.join(asm_forms.statements()) + '\n')
run('python3', f'{HERE}/asl_assemble.py', forms, f'{wd}/forms.asl', f'{wd}/aslwd')
valid = {}
for l in open(f'{wd}/forms.asl'):
    h = l.split('\t')[0]
    if h == 'ERR':
        continue
    b = bytes.fromhex(h)
    key = (b[0], b[1]) if b[0] in (0x90, 0x91, 0x92) else (0, b[0])
    valid[key] = len(b)

# 3. round trip of everything Ghidra accepts
def to_asl(t):
    t = re.sub(r'0x([0-9a-fA-F]+)', lambda m: '$' + m.group(1), t)
    return t.lower()

def add_w(t):
    # force the long form on the first numeric operand (asl otherwise picks the short form)
    return re.sub(r'(?<![\w$])\$([0-9a-f]+)(?!\.w)', lambda m: '$' + m.group(1) + '.w', t, count=1)

rows = []
for line in open(f'{wd}/{tag}.gh'):
    h, ln, txt = line.rstrip('\n').split(' ', 2)
    rows.append((bytes.fromhex(h), int(ln), txt))
stm = []
for b, ln, txt in rows:
    if ln:
        stm.append(to_asl(txt))
        stm.append(add_w(to_asl(txt)))
open(f'{wd}/{tag}.rt', 'w').write('\n'.join(stm) + '\n')
run('python3', f'{HERE}/asl_assemble.py', f'{wd}/{tag}.rt', f'{wd}/{tag}.rt.asl', f'{wd}/aslwd')
res = [l.rstrip('\n').split('\t') for l in open(f'{wd}/{tag}.rt.asl')]
cnt = dict(agree=0, agree_long_forced=0, both_invalid=0, ghidra_only=0, asl_rejects=0, mismatch=0)
bad = []
k = 0
for b, ln, txt in rows:
    if not ln:
        key = (b[0], b[1]) if b[0] in (0x90, 0x91, 0x92) else (0, b[0])
        if key in valid:
            cnt['ghidra_only'] += 1  # actually asl-only: Ghidra rejects an instruction asl produces
            bad.append(('ghidra-rejects-valid', b.hex(), txt))
        else:
            cnt['both_invalid'] += 1
        continue
    a1, a2 = res[k], res[k + 1]; k += 2
    want = b[:ln].hex()
    if a1[0] == want:
        cnt['agree'] += 1
    elif a2[0] == want:
        cnt['agree_long_forced'] += 1
    elif a1[0] == 'ERR' and a2[0] == 'ERR':
        cnt['asl_rejects'] += 1
        bad.append(('asl-rejects', b[:ln].hex(), txt))
    else:
        cnt['mismatch'] += 1
        bad.append(('mismatch', b[:ln].hex(), txt + '  asl=' + a1[0] + '/' + a2[0]))
print(tag, n, 'cases', cnt)
for x in bad[:40]:
    print('  ', *x)
sys.exit(1 if bad else 0)
