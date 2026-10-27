#!/usr/bin/env python3
"""Enumerate ST7 assembly statements (AS syntax) covering every mnemonic and addressing form.
Used by asl-diff.sh: each statement is assembled with asl, decoded with Ghidra, compared."""
import itertools

MEM_A = ['#$55', '$10', '$1234', '(x)', '($10,x)', '($1234,x)', '(y)', '($10,y)', '($1234,y)',
         '[$10]', '[$12.w]', '([$10],x)', '([$12.w],x)', '([$10],y)', '([$12.w],y)']
MEM_X = ['#$55', '$10', '$1234', '(x)', '($10,x)', '($1234,x)', '[$10]', '[$12.w]', '([$10],x)', '([$12.w],x)']
MEM_Y = ['#$55', '$10', '$1234', '(y)', '($10,y)', '($1234,y)', '[$10]', '[$12.w]', '([$10],y)', '([$12.w],y)']
UNARY = ['a', 'x', 'y', '$10', '(x)', '($10,x)', '(y)', '($10,y)', '[$10]', '([$10],x)', '([$10],y)']
JMP = ['$10', '$1234', '(x)', '($10,x)', '($1234,x)', '(y)', '($10,y)', '($1234,y)', '[$10]', '[$12.w]',
       '([$10],x)', '([$12.w],x)', '([$10],y)', '([$12.w],y)']
BITS = ['$10', '[$10]']
JRCC = ['jra', 'jrt', 'jrf', 'jrc', 'jrnc', 'jreq', 'jrne', 'jrh', 'jrnh', 'jrm', 'jrnm', 'jrmi', 'jrpl',
        'jrugt', 'jrule', 'jrult', 'jruge', 'jrih', 'jril']


def statements():
    s = []
    for m in ['adc', 'add', 'and', 'bcp', 'cp', 'ld', 'or', 'sbc', 'sub', 'xor']:
        for o in MEM_A:
            s.append(f'{m} a,{o}')
    for o in MEM_A:
        if not o.startswith('#'):
            s.append(f'ld {o},a')
    for o in MEM_X:
        s.append(f'cp x,{o}')
        s.append(f'ld x,{o}')
        if not o.startswith('#'):
            s.append(f'ld {o},x')
    for o in MEM_Y:
        s.append(f'cp y,{o}')
        s.append(f'ld y,{o}')
        if not o.startswith('#'):
            s.append(f'ld {o},y')
    for r in ['x,a', 'a,x', 'y,a', 'a,y', 'y,x', 'x,y', 'a,s', 's,a', 'x,s', 's,x', 'y,s', 's,y']:
        s.append(f'ld {r}')
    for m in ['clr', 'cpl', 'dec', 'inc', 'neg', 'rlc', 'rrc', 'sla', 'sll', 'sra', 'srl', 'swap', 'tnz']:
        for o in UNARY:
            s.append(f'{m} {o}')
    for m in ['call', 'jp']:
        for o in JMP:
            s.append(f'{m} {o}')
    for m in ['callr'] + JRCC:
        s.append(f'{m} $1010')
        s.append(f'{m} [$10]')
    for m in ['bset', 'bres']:
        for o in BITS:
            for n in range(8):
                s.append(f'{m} {o},#{n}')
    for m in ['btjt', 'btjf']:
        for o in BITS:
            for n in range(8):
                s.append(f'{m} {o},#{n},$1030')
    for r in ['a', 'x', 'y', 'cc']:
        s.append(f'push {r}')
        s.append(f'pop {r}')
    s += ['mul x,a', 'mul y,a']
    s += ['nop', 'halt', 'wfi', 'iret', 'ret', 'rcf', 'scf', 'rim', 'sim', 'rsp', 'trap']
    return s


if __name__ == '__main__':
    for x in statements():
        print(x)
