#!/usr/bin/env python3
"""sem_diff.py <workdir> [n=20000] [seed=1] [lang=ST7] : semantics differential, one instruction at a
time, against the uCsim ST7 simulator (run as a black box).

For each random case (instruction from the asl-assembled form list with random operand bytes, random
A/X/Y/flags/SP, a 64 KB deterministic memory pattern) both the simulator and Ghidra's emulator execute
one instruction; A, X, Y, flags (H I N Z C), SP, PC and every modified memory byte are compared.
Prints counts per difference class (by mnemonic and register); exit status 1 if there are
differences not listed in the explained set (sem_known.txt)."""
import os, random, re, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import asm_forms

wd = os.path.abspath(sys.argv[1]); os.makedirs(wd, exist_ok=True)
n = int(sys.argv[2]) if len(sys.argv) > 2 else 20000
seed = int(sys.argv[3]) if len(sys.argv) > 3 else 1
lang = sys.argv[4] if len(sys.argv) > 4 else 'ST7'
U = os.environ.get('UCSIM_ST7', os.path.expanduser(
    '~/.cache/ghidra-rare-scratch/tools/ucsim-src/ucsim/src/sims/st7.src/ucsim_st7'))
PAT = os.path.join(wd, 'pat.hex')

pat = bytes(((a * 37 + 11) ^ ((a >> 8) * 13)) & 0xff for a in range(65536))
open(os.path.join(wd, 'pat.bin'), 'wb').write(pat)
def rec(addr, data):
    b = [len(data), addr >> 8, addr & 255, 0] + list(data)
    return ':' + ''.join('%02X' % x for x in b) + '%02X' % ((-sum(b)) & 255)
with open(PAT, 'w') as f:
    for a in range(0, 65536, 32):
        f.write(rec(a, pat[a:a + 32]) + '\n')
    f.write(':00000001FF\n')

# instruction pool: asl-assembled forms (all valid prefix/opcode combinations), random operands
forms = os.path.join(wd, 'forms.txt')
open(forms, 'w').write('\n'.join(asm_forms.statements()) + '\n')
subprocess.run(['python3', f'{HERE}/asl_assemble.py', forms, f'{wd}/forms.asl', f'{wd}/aslwd'], check=True)
pool = []
for l in open(f'{wd}/forms.asl'):
    p = l.rstrip('\n').split('\t')
    if p[0] != 'ERR':
        pool.append((bytes.fromhex(p[0]), p[1]))
# opcodes ucsim cannot be compared on: it lacks the I1/I0 pair (ST72), the 92 BD/ED call forms, X/Y
# as 16-bit registers (cp x,#imm and the 91 Y forms), STM8-style swap x
rnd = random.Random(seed)
cases = []
for i in range(n):
    code, text = rnd.choice(pool)
    code = bytearray(code)
    # randomise operand bytes (keep prefix/opcode)
    k = 2 if code[0] in (0x90, 0x91, 0x92) else 1
    for j in range(k, len(code)):
        code[j] = rnd.getrandbits(8)
    a, x, y = rnd.getrandbits(8), rnd.getrandbits(8), rnd.getrandbits(8)
    cc = rnd.getrandbits(5)
    sp = rnd.randrange(0x01C8, 0x01F0)
    cases.append((bytes(code), text, a, x, y, cc, sp))
with open(f'{wd}/cases.txt', 'w') as f:
    for c in cases:
        f.write('%s 0x%02x 0x%02x 0x%02x 0x%02x 0x%04x\n' % (c[0].hex(), *c[2:]))

if '-r' in sys.argv and os.path.exists(f'{wd}/{lang}.sem.pkl'):
    import pickle
    cases, ghl, res = pickle.load(open(f'{wd}/{lang}.sem.pkl', 'rb'))
else:
    # ---- Ghidra side ----
    env = dict(os.environ)
    gh = f'{wd}/{lang}.ghidra'
    proj = tempfile.mkdtemp(dir=env.get('TMPDIR', '/tmp'), prefix='st7-sd.')
    open(f'{proj}/pat.bin', 'wb').write(pat)
    gi = env['GHIDRA_INSTALL_DIR']
    lid = {'ST7': 'ST7:BE:16:default', 'ST72': 'ST72:BE:16:default'}[lang]
    r = subprocess.run([f'{gi}/support/analyzeHeadless', proj, 'p', '-import', f'{proj}/pat.bin', '-loader', 'BinaryLoader',
                        '-loader-baseAddr', '0', '-processor', lid, '-noanalysis', '-scriptPath', HERE,
                        '-postScript', 'EmuDiff.java', f'{wd}/cases.txt', gh, '-deleteProject'],
                       capture_output=True, text=True)
    if not os.path.exists(gh):
        print(r.stdout[-3000:], r.stderr[-2000:]); sys.exit(2)
    ghl = [l.rstrip('\n') for l in open(gh)]
    assert len(ghl) == len(cases), (len(ghl), len(cases))

    # ---- ucsim side: one process per chunk of cases, memory reloaded for each case ----
    def run_chunk(chunk):
        cmds = ['step 1']
        for idx, (code, text, a, x, y, cc, sp) in chunk:
            cmds.append('file "%s"' % PAT)
            cmds.append('set memory rom 0x1000 ' + ' '.join('0x%02x' % b for b in code))
            cmds += ['expression A=%d' % a, 'expression X=%d' % x, 'expression Y=%d' % y,
                     'expression CC=%d' % cc, 'expression SP=%d' % sp, 'expression PC=4096', 'step 1',
                     'echo @@@ %d' % idx, 'expression A', 'expression X', 'expression Y', 'expression CC',
                     'expression SP', 'expression PC', 'check "%s"' % PAT, 'echo @@@END']
        cf = os.path.join(proj, 'c%d.cmd' % chunk[0][0])
        open(cf, 'w').write('\n'.join(cmds) + '\n')
        p = subprocess.run([U, '-b', '-q', PAT], input='exec "%s"\nquit\n' % cf, capture_output=True,
                           text=True, timeout=1800)
        return p.stdout + p.stderr

    res = {}
    CH = 400
    chunks = [list(enumerate(cases))[i:i + CH] for i in range(0, len(cases), CH)]
    from concurrent.futures import ThreadPoolExecutor
    if os.path.exists(U):
        with ThreadPoolExecutor(max_workers=6) as ex:
            outs = list(ex.map(run_chunk, chunks))
    else:
        print('uCsim not found (UCSIM_ST7): comparing only with the manual model')
        outs = []
    for out in outs:
        cur = None
        vals = []
        diffs = []
        for l in out.split('\n'):
            l = re.sub(r'^(?:\d+> )+', '', l)
            m = re.match(r'^@@@ (\d+)$', l)
            if m:
                cur = int(m.group(1)); vals = []; diffs = []; continue
            if cur is None:
                continue
            if l.startswith('@@@END'):
                if len(vals) >= 6:
                    res[cur] = (vals[:6], diffs)
                cur = None; continue
            if re.match(r'^-?\d+$', l):
                vals.append(int(l)); continue
            m = re.match(r'^Diff at ([0-9a-f]+), FILE=([0-9a-f]+) MEM=([0-9a-f]+)', l)
            if m:
                diffs.append((int(m.group(1), 16), int(m.group(3), 16)))
    import shutil; shutil.rmtree(proj, ignore_errors=True)


# ---- known uCsim deviations (each confirmed against the manual; see GHIDRA-RARE.md) ----
st72 = lang == 'ST72'
def explain(code, text, gt, ut, gm, um):
    """gt/ut = (A, X, Y, CC5, SP, PC); returns the name of the known uCsim deviation that accounts
    for the difference, or None."""
    mn = text.split()[0]
    ops = text.split(None, 1)[1] if len(text.split()) > 1 else ''
    pre = code[0] if code[0] in (0x90, 0x91, 0x92) else 0
    ga, gx, gy, gcc, gsp, gpc = gt
    ua, ux, uy, ucc, usp, upc = ut
    if st72 and mn in ('jrm', 'jrnm'):
        return 'jrm/jrnm on the two-bit-priority variant: uCsim has no I1 bit'
    if mn == 'jp':
        return 'jp: uCsim reads the target address from memory'
    if mn == 'trap':
        return 'trap: not implemented in uCsim'
    if mn == 'rsp':
        return 'rsp: SP reset value is device dependent (uCsim 0x017F)'
    if mn == 'mul' and (ga, gx, gy, gsp, gpc) == (ua, ux, uy, usp, upc) and gm == um:
        return 'mul: uCsim leaves H and C unchanged (manual: both cleared)'
    if mn == 'push' and ops == 'cc':
        return 'push cc: uCsim pushes only the five flag bits (manual: bits 7-5 read as 1)'
    if mn in ('btjt', 'btjf', 'bset', 'bres') and pre == 0x92:
        return mn + ': uCsim ignores the pointer of the 92 (indirect) forms'
    if mn in ('btjt', 'btjf') and (ga, gx, gy, gsp, gpc) == (ua, ux, uy, usp, upc) and gm == um \
            and (gcc ^ ucc) == 1 and (gcc & 0x1e) == (ucc & 0x1e):
        return 'btjt/btjf: uCsim does not copy the tested bit into C'
    if pre == 0x91 and mn in ('ld', 'cp', 'call'):
        return '91 (Y indirect) forms: uCsim mis-decodes length or operand'
    if mn in ('ld', 'cp') and ('y' in ops.replace('a,', '').lower() or ops.lower().startswith('x,#')):
        return 'ld/cp with X/Y operand: uCsim uses 16-bit X/Y semantics (STM8 heritage)'
    if mn == 'ld' and (ga, gx, gy, gpc) == (ua, ux, uy, upc) and gm == um:
        if ops.lower().startswith('s,') and (gsp & 0xff) == (usp & 0xff):
            return 'ld S,r: uCsim clears the SP high byte (manual: fixed by the device)'
        if gsp == usp and (gcc ^ ucc) & ~0x06 == 0:
            return 'ld: uCsim does not update N and Z'
    if mn == 'neg' and (gcc ^ ucc) & 1 and gcc & 2 and (ga, gx, gy, gsp, gpc) == (ua, ux, uy, usp, upc) and gm == um:
        return 'neg of 0: uCsim sets C (manual: cleared when the result is zero)'
    if mn in ('rlc', 'rrc', 'sll', 'sla', 'sra', 'swap', 'tnz', 'neg') and \
            (ga, gx, gy, gsp, gpc) == (ua, ux, uy, usp, upc) and gm == um and (gcc ^ ucc) & ~0x04 == 0:
        return mn + ': uCsim does not update N'
    if mn in ('rlc', 'rrc', 'sll', 'sla', 'sra', 'swap', 'tnz', 'neg', 'bcp') and pre == 0x90:
        return 'Y forms: uCsim mixes X and Y (16-bit registers)'
    if upc & 0xffff == gpc and (ga, gx, gy, gcc, gsp) == (ua, ux, uy, ucc, usp) and gm == um:
        return 'PC is not wrapped to 16 bits in uCsim'
    return None

# ---- compare ----
import collections
import st7model
st72 = lang == 'ST72'
cnt = collections.Counter(); classes = collections.defaultdict(list)
rule_cnt = collections.Counter(); mcnt = collections.Counter(); mclasses = collections.defaultdict(list)
def flags_cc(f):
    return f['H'] << 4 | (f['I0'] if st72 else f['I']) << 3 | f['N'] << 2 | f['Z'] << 1 | f['C']
for i, (code, text, a, x, y, cc, sp) in enumerate(cases):
    g = ghl[i].split(' ')
    mn = text.split()[0]
    if g[0] != 'OK':
        cnt['ghidra-error'] += 1; classes['ghidra-error ' + mn].append((i, text, ghl[i])); continue
    ga, gx, gy, gcc, gsp, gpc = [int(v, 16) for v in g[1:7]]
    gm = {int(t.split('=')[0], 16): int(t.split('=')[1], 16) for t in g[7:]}
    # --- Ghidra against the manual model ---
    st = dict(A=a, X=x, Y=y, SP=sp, H=cc >> 4 & 1, N=cc >> 2 & 1, Z=cc >> 1 & 1, C=cc & 1, I=cc >> 3 & 1,
              I0=cc >> 3 & 1, I1=1)
    mo = st7model.execute(code, st, pat, st72)
    mbad = []
    if (ga, gx, gy) != (mo['A'], mo['X'], mo['Y']): mbad.append('regs')
    if gcc != flags_cc(mo['f']): mbad.append('flags')
    if gsp != mo['SP']: mbad.append('SP')
    if gpc != mo['PC']: mbad.append('PC')
    if gm != mo['mem']: mbad.append('MEM')
    if mbad:
        mcnt['differ'] += 1; mclasses[mn + ' ' + ','.join(mbad)].append((i, text, ghl[i], mo))
    else:
        mcnt['agree'] += 1
    # --- Ghidra against ucsim ---
    if i not in res:
        cnt['ucsim-missing'] += 1; continue
    (ua, ux, uy, ucc, usp, upc), ud = res[i]
    um = {ad: v for ad, v in ud if not (0x1000 <= ad < 0x1000 + len(code))}
    bad = []
    if ga != (ua & 0xff): bad.append('A')
    if gx != (ux & 0xff): bad.append('X')
    if gy != (uy & 0xff): bad.append('Y')
    if gcc != (ucc & 0x1f):
        d = gcc ^ (ucc & 0x1f)
        bad.append('flags:' + ''.join(n for b, n in ((16, 'H'), (8, 'I'), (4, 'N'), (2, 'Z'), (1, 'C')) if d & b))
    if gsp != usp: bad.append('SP')
    if gpc != upc: bad.append('PC')
    if gm != um: bad.append('MEM')
    if bad:
        why = explain(code, text, (ga, gx, gy, gcc, gsp, gpc), (ua & 0xff, ux & 0xff, uy & 0xff, ucc & 0x1f, usp, upc), gm, um)
        if why:
            cnt['explained'] += 1; rule_cnt[why] += 1
        else:
            cnt['unexplained'] += 1
            classes[mn + ' ' + ','.join(bad)].append((i, text, ghl[i], res[i]))
    else:
        cnt['agree'] += 1
print(lang, n, 'cases; Ghidra vs manual model:', dict(mcnt), '; Ghidra vs uCsim:', dict(cnt))
for k, v in sorted(mclasses.items(), key=lambda kv: -len(kv[1])):
    print('  MODEL %5d %s   e.g. %s' % (len(v), k, v[0][1]))
for k, v in sorted(rule_cnt.items(), key=lambda kv: -kv[1]):
    print('  uCsim deviation %6d  %s' % (v, k))
if True:
    for k, v in sorted(classes.items(), key=lambda kv: -len(kv[1])):
        print('  ucsim %5d %s   e.g. %s' % (len(v), k, v[0][1]))
import pickle; pickle.dump((cases, ghl, res), open(f'{wd}/{lang}.sem.pkl', 'wb'))
sys.exit(1 if mcnt['differ'] or cnt['unexplained'] else 0)
