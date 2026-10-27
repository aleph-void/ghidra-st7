#!/usr/bin/env python3
"""A small independent model of the ST7 core written from the ST7 Family Programming Manual
(PM0002): operation, flag and stack-order tables.  Used as the third opinion in sem_diff.py (next to
Ghidra's emulator and the uCsim simulator): Ghidra's p-code must agree with it on every random
single-instruction case.

State: dict with A X Y SP PC, flags H I N Z C (and I0/I1 for the two-bit-priority variant), and
mem (dict addr->value overriding the base image).  `execute` runs exactly one instruction."""

class Mem:
    def __init__(self, image):
        self.image = image
        self.w = {}
    def r(self, a):
        a &= 0xffff
        return self.w.get(a, self.image[a])
    def r16(self, a):
        return self.r(a) << 8 | self.r(a + 1)
    def wr(self, a, v):
        self.w[a & 0xffff] = v & 0xff

def execute(code, st, image, st72=False):
    m = Mem(image)
    A, X, Y, SP = st['A'], st['X'], st['Y'], st['SP']
    f = dict(H=st['H'], N=st['N'], Z=st['Z'], C=st['C'])
    if st72:
        f['I0'] = st['I0']; f['I1'] = st['I1']
    else:
        f['I'] = st['I']
    pc = 0x1000
    pos = 0
    pre = 0
    if code[0] in (0x90, 0x91, 0x92):
        pre = code[0]; pos = 1
    op = code[pos]; pos += 1
    n, l = op >> 4, op & 15
    def i8():
        nonlocal pos
        v = code[pos]; pos += 1; return v
    def i16():
        nonlocal pos
        v = code[pos] << 8 | code[pos + 1]; pos += 2; return v
    nxt_len = None
    regs = dict(A=A, X=X, Y=Y)
    idx = 'Y' if pre in (0x90, 0x91) else 'X'     # index register in indexed forms
    reg = 'Y' if pre in (0x90, 0x91) else 'X'     # X-family data register (ld X,.. / cp X,..)
    def nz(v):
        f['Z'] = int(v & 0xff == 0); f['N'] = (v >> 7) & 1
    def cc_image():
        if st72:
            return 0xC0 | f['I1'] << 5 | f['H'] << 4 | f['I0'] << 3 | f['N'] << 2 | f['Z'] << 1 | f['C']
        return 0xE0 | f['H'] << 4 | f['I'] << 3 | f['N'] << 2 | f['Z'] << 1 | f['C']
    def set_cc(v):
        f['C'] = v & 1; f['Z'] = v >> 1 & 1; f['N'] = v >> 2 & 1; f['H'] = v >> 4 & 1
        if st72:
            f['I0'] = v >> 3 & 1; f['I1'] = v >> 5 & 1
        else:
            f['I'] = v >> 3 & 1
    def push(v):
        nonlocal SP
        m.wr(SP, v); SP = (SP - 1) & 0xffff
    def pop():
        nonlocal SP
        SP = (SP + 1) & 0xffff; return m.r(SP)
    def ea_mem(nn):
        """effective address of the memory operand for high nibble nn in B..F"""
        if pre in (0, 0x90):
            ix = regs['Y'] if pre else regs['X']
            return {0xB: lambda: i8(), 0xC: lambda: i16(), 0xD: lambda: (i16() + ix) & 0xffff,
                    0xE: lambda: (i8() + ix) & 0xffff, 0xF: lambda: ix}[nn]()
        ix = regs['Y'] if pre == 0x91 else regs['X']
        if nn == 0xB: return m.r(i8())
        if nn == 0xC: return m.r16(i8())
        if nn == 0xE: return (m.r(i8()) + ix) & 0xffff
        if nn == 0xD: return (m.r16(i8()) + ix) & 0xffff
        raise ValueError('no such mode')
    def sub_flags(a, b, c=0):
        r = a - b - c
        f['C'] = int(a < b + c)
        nz(r); return r & 0xff
    def rmw_ea(nn):
        """operand location of the single-operand group: ('reg',name) or ('mem',addr)"""
        if nn == 4: return ('reg', 'A')
        if nn == 5: return ('reg', 'Y' if pre == 0x90 else 'X')
        ix = regs['Y'] if pre in (0x90, 0x91) else regs['X']
        if pre in (0, 0x90):
            return ('mem', {3: lambda: i8(), 6: lambda: (i8() + ix) & 0xffff, 7: lambda: ix}[nn]())
        if nn == 3: return ('mem', m.r(i8()))
        if nn == 6: return ('mem', (m.r(i8()) + ix) & 0xffff)
        raise ValueError
    def rd(loc):
        return regs[loc[1]] if loc[0] == 'reg' else m.r(loc[1])
    def wrl(loc, v):
        v &= 0xff
        if loc[0] == 'reg': regs[loc[1]] = v
        else: m.wr(loc[1], v)

    jump = None
    if n in (0xA, 0xB, 0xC, 0xD, 0xE, 0xF) and not (n == 0xA and l in (0xC, 0xD, 0x7, 0xF)) \
            and not (l == 0xD and n == 0xA):
        # A-family
        if n == 0xA:
            val = i8(); loc = None
        else:
            if l == 0xC or l == 0xD:
                ea = ea_mem(n)
                if l == 0xC:
                    jump = ea
                else:
                    ret = (0x1000 + pos) & 0xffff
                    push(ret & 0xff); push(ret >> 8)
                    jump = ea
                val = None
            else:
                ea = ea_mem(n); val = m.r(ea); loc = ea
        if val is not None or l in (0x7, 0xF):
            if l == 0x0: regs['A'] = sub_flags(regs['A'], val)
            elif l == 0x1: sub_flags(regs['A'], val)
            elif l == 0x2: regs['A'] = sub_flags(regs['A'], val, f['C'])
            elif l == 0x3:
                sub_flags(regs[reg], val)
            elif l == 0x4: regs['A'] &= val; nz(regs['A'])
            elif l == 0x5: nz(regs['A'] & val)
            elif l == 0x6: regs['A'] = val; nz(val)
            elif l == 0x7: m.wr(loc, regs['A']); nz(regs['A'])
            elif l == 0x8: regs['A'] ^= val; nz(regs['A'])
            elif l == 0x9:
                a = regs['A']; c = f['C']; r = a + val + c
                f['H'] = int((a & 15) + (val & 15) + c > 15); f['C'] = int(r > 255)
                regs['A'] = r & 255; nz(r)
            elif l == 0xA: regs['A'] |= val; nz(regs['A'])
            elif l == 0xB:
                a = regs['A']; r = a + val
                f['H'] = int((a & 15) + (val & 15) > 15); f['C'] = int(r > 255)
                regs['A'] = r & 255; nz(r)
            elif l == 0xE: regs[reg] = val; nz(val)
            elif l == 0xF: m.wr(loc, regs[reg]); nz(regs[reg])
            else:
                raise ValueError('bad A-family')
    elif n in (3, 4, 5, 6, 7):
        loc = rmw_ea(n)
        v = rd(loc)
        if l == 0x0:
            r = (0 - v) & 255; f['C'] = int(v != 0); nz(r); wrl(loc, r)
        elif l == 0x3:
            r = v ^ 255; f['C'] = 1; nz(r); wrl(loc, r)
        elif l == 0x4:
            f['C'] = v & 1; r = v >> 1; nz(r); wrl(loc, r)
        elif l == 0x6:
            r = (v >> 1) | (f['C'] << 7); f['C'] = v & 1; nz(r); wrl(loc, r)
        elif l == 0x7:
            r = (v >> 1) | (v & 0x80); f['C'] = v & 1; nz(r); wrl(loc, r)
        elif l == 0x8:
            f['C'] = v >> 7; r = (v << 1) & 255; nz(r); wrl(loc, r)
        elif l == 0x9:
            r = ((v << 1) | f['C']) & 255; f['C'] = v >> 7; nz(r); wrl(loc, r)
        elif l == 0xA:
            r = (v - 1) & 255; nz(r); wrl(loc, r)
        elif l == 0xC:
            r = (v + 1) & 255; nz(r); wrl(loc, r)
        elif l == 0xD:
            nz(v)
        elif l == 0xE:
            r = (v >> 4) | (v << 4) & 255; nz(r); wrl(loc, r)
        elif l == 0xF:
            wrl(loc, 0); f['N'] = 0; f['Z'] = 1
        elif l == 0x2 and n == 4:
            # 42 / 90 42: mul
            r = regs['Y' if pre == 0x90 else 'X'] * regs['A']
            regs['A'] = r & 255; regs['Y' if pre == 0x90 else 'X'] = r >> 8; f['H'] = 0; f['C'] = 0
        else:
            raise ValueError('bad rmw %02x' % op)
    elif n in (0, 1):
        # bit operations: 0x = btjt/btjf, 1x = bset/bres
        bit = (op & 15) >> 1
        p = i8()
        addr = m.r(p) if pre == 0x92 else p
        v = m.r(addr)
        if n == 1:
            m.wr(addr, v | (1 << bit) if l % 2 == 0 else v & ~(1 << bit))
        else:
            rel = i8(); rel = rel - 256 if rel > 127 else rel
            b = (v >> bit) & 1; f['C'] = b
            if (l % 2 == 0) == (b == 1):
                jump = (0x1000 + pos + rel) & 0xffff
    elif n == 2:
        cond = {0: 1, 1: 0, 2: not (f['C'] or f['Z']), 3: f['C'] or f['Z'], 4: not f['C'], 5: f['C'],
                6: not f['Z'], 7: f['Z'], 8: not f['H'], 9: f['H'], 0xA: not f['N'], 0xB: f['N'],
                0xC: (f['I0'] == 0 and f['I1'] == 0) if st72 else not f['I'],
                0xD: (f['I0'] == 1 and f['I1'] == 1) if st72 else f['I'],
                0xE: st.get('EXTI', 0) == 0, 0xF: st.get('EXTI', 0) == 1}[l]
        p = i8()
        rel = m.r(p) if pre == 0x92 else p
        rel = rel - 256 if rel > 127 else rel
        if cond:
            jump = (0x1000 + pos + rel) & 0xffff
    elif n == 0xA and l == 0xD:
        p = i8()
        rel = m.r(p) if pre == 0x92 else p
        rel = rel - 256 if rel > 127 else rel
        ret = (0x1000 + pos) & 0xffff
        push(ret & 0xff); push(ret >> 8)
        jump = (0x1000 + pos + rel) & 0xffff
    elif n == 8:
        if l == 0x0:   # iret
            set_cc(pop()); regs['A'] = pop(); regs['X'] = pop(); hi = pop(); lo = pop(); jump = hi << 8 | lo
        elif l == 0x1:
            hi = pop(); lo = pop(); jump = hi << 8 | lo
        elif l == 0x3:
            ret = (0x1000 + pos) & 0xffff
            push(ret & 0xff); push(ret >> 8); push(regs['X']); push(regs['A']); push(cc_image())
            if st72: f['I0'] = 1; f['I1'] = 1
            else: f['I'] = 1
            jump = m.r16(0xFFFC)
        elif l == 0x4: regs['A'] = pop()
        elif l == 0x5: regs['Y' if pre == 0x90 else 'X'] = pop()
        elif l == 0x6: set_cc(pop())
        elif l == 0x8: push(regs['A'])
        elif l == 0x9: push(regs['Y' if pre == 0x90 else 'X'])
        elif l == 0xA: push(cc_image())
        else:
            raise ValueError('halt/wfi')
    elif n == 9:
        if l == 0x3:
            if pre == 0x90: regs['Y'] = regs['X']; nz(regs['X'])
            else: regs['X'] = regs['Y']; nz(regs['Y'])
        elif l == 0x4:   # ld S,X / ld S,Y
            SP = (SP & 0xff00) | regs['Y' if pre == 0x90 else 'X']; nz(regs['Y' if pre == 0x90 else 'X'])
        elif l == 0x5: SP = (SP & 0xff00) | regs['A']; nz(regs['A'])
        elif l == 0x6: regs['Y' if pre == 0x90 else 'X'] = SP & 255; nz(SP & 255)
        elif l == 0x7:
            if pre == 0x90: regs['Y'] = regs['A']
            else: regs['X'] = regs['A']
            nz(regs['A'])
        elif l == 0x8: f['C'] = 0
        elif l == 0x9: f['C'] = 1
        elif l == 0xA:
            if st72: f['I0'] = 0; f['I1'] = 1
            else: f['I'] = 0
        elif l == 0xB:
            if st72: f['I0'] = 1; f['I1'] = 1
            else: f['I'] = 1
        elif l == 0xC: SP = (SP & 0xff00) | 0xff
        elif l == 0xD: pass
        elif l == 0xE: regs['A'] = SP & 255; nz(SP & 255)
        elif l == 0xF:
            if pre == 0x90: regs['A'] = regs['Y']; nz(regs['Y'])
            else: regs['A'] = regs['X']; nz(regs['X'])
        else:
            raise ValueError('bad 9x')
    else:
        raise ValueError('unmodelled %02x' % op)
    pc = jump if jump is not None else (0x1000 + pos) & 0xffff
    out = dict(A=regs['A'], X=regs['X'], Y=regs['Y'], SP=SP, PC=pc, f=f)
    out['mem'] = {a: v for a, v in m.w.items() if image[a] != v and not (0x1000 <= a < 0x1000 + len(code))}
    return out
