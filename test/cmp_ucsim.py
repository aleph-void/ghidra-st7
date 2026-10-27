#!/usr/bin/env python3
"""cmp_ucsim.py <ghidra-out> <ucsim-out> [label] [-v]: compare Ghidra's decode with the uCsim ST7
disassembler. Prints counts and difference classes (class = mnemonic pair or kind of difference)."""
import re, sys, collections

def norm(t):
    t = t.strip().lower()
    t = t.replace('$', '')
    t = re.sub(r'0x([0-9a-f]+)', lambda m: str(int(m.group(1), 16)), t)
    t = re.sub(r'\s+', ' ', t)
    m = re.match(r'([a-z]+)\s*(.*)', t)
    if not m:
        return (t, '')
    mn = {'bjtf': 'btjf', 'jruge': 'jrnc', 'jrult': 'jrc', 'sla': 'sll', 'jrt': 'jra'}.get(m.group(1), m.group(1))
    return (mn, m.group(2).replace(' ', ''))

def main():
    g = [l.rstrip('\n').split(' ', 2) for l in open(sys.argv[1])]
    u = [l.rstrip('\n').split(' ', 2) for l in open(sys.argv[2])]
    label = sys.argv[3] if len(sys.argv) > 3 and not sys.argv[3].startswith('-') else ''
    assert len(g) == len(u)
    classes = collections.Counter(); c = collections.Counter(); ex = collections.defaultdict(list)
    for a, b in zip(g, u):
        assert a[0] == b[0]
        ga, ub = a[2] == 'BAD', b[2] == 'BAD'
        if ga and ub:
            k = 'both-invalid'
        elif ga:
            k = 'ucsim-only'
        elif ub:
            k = 'ghidra-only'
        elif int(a[1]) != int(b[1]):
            k = 'length'
        else:
            gm, go = norm(a[2]); um, uo = norm(b[2])
            if gm == um and go == uo:
                k = 'agree'
            else:
                k = 'text-differs'
        if k in ('text-differs', 'length'):
            k = k + ': ' + re.sub(r'0x[0-9a-f]+', 'N', a[2]) + '  |  ' + re.sub(r'0x[0-9a-f]+|\$', 'N', b[2]) if False else k
        c[k] += 1
        cls = re.sub(r'0x[0-9a-f]+', 'N', a[2]) + '  |  ' + re.sub(r'\s+', ' ', re.sub(r'0x[0-9a-f]+', 'N', b[2]))
        classes[(k, cls)] += 1
        if len(ex[k]) < 8:
            ex[k].append((a[0], a[2], b[2]))
    print(label, dict(c))
    if '-c' in sys.argv:
        for (k, cls), n in sorted(classes.items(), key=lambda x: -x[1]):
            if k not in ('agree', 'both-invalid'):
                print('  %6d %-12s %s' % (n, k, cls))
    if '-v' in sys.argv or any(k not in ('agree', 'agree(alias)', 'both-invalid') for k in c):
        for k, v in ex.items():
            if k in ('agree', 'agree(alias)', 'both-invalid'):
                continue
            for x in v:
                print('  ', k, *x)

main()
