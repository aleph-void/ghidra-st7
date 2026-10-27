#!/usr/bin/env python3
"""cmp_asl.py <asl-output> <ghidra-output> [label]: compare asl's assembly of each statement with
Ghidra's decode of the assembled bytes. Exact = same text after number normalisation;
alias = same instruction under a documented alias (SLA=SLL, JRT=JRA, JRULT=JRC, JRUGE=JRNC)."""
import re, sys

ALIAS = {'sla': 'sll', 'jrt': 'jra', 'jrult': 'jrc', 'jruge': 'jrnc'}


def norm(t, alias=False):
    t = t.strip().lower()
    t = re.sub(r'\s+', ' ', t)
    t = re.sub(r'\$([0-9a-f]+)', lambda m: str(int(m.group(1), 16)), t)
    t = re.sub(r'0x([0-9a-f]+)', lambda m: str(int(m.group(1), 16)), t)
    t = re.sub(r'(?<![\w$])([0-9]+)h\b', lambda m: str(int(m.group(1), 16)), t)
    if alias:
        m = re.match(r'([a-z]+)(.*)', t)
        t = ALIAS.get(m.group(1), m.group(1)) + m.group(2)
    return t.replace(' ', '')


def main():
    asl = [l.rstrip('\n').split('\t') for l in open(sys.argv[1])]
    gh = [l.rstrip('\n').split(' ', 2) for l in open(sys.argv[2])]
    label = sys.argv[3] if len(sys.argv) > 3 else ''
    assert len(asl) == len(gh), (len(asl), len(gh))
    ex = al = bad = err = 0
    diffs = []
    for a, g in zip(asl, gh):
        if a[0] == 'ERR':
            err += 1
            continue
        assert a[0] == g[0], (a, g)
        gl, gt = int(g[1]), g[2]
        if gt == 'BAD' or gl != len(a[0]) // 2:
            bad += 1
            diffs.append((a[0], a[1], f'{gt} len={gl}'))
        elif norm(gt) == norm(a[1]):
            ex += 1
        elif norm(gt, True) == norm(a[1], True):
            al += 1
        else:
            bad += 1
            diffs.append((a[0], a[1], gt))
    print(f'{label}: {len(asl)} statements, asl-rejected {err}, exact {ex}, alias {al}, different {bad}')
    for d in diffs[:60]:
        print('  DIFF', *d)
    return 1 if bad else 0


sys.exit(main())
