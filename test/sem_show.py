#!/usr/bin/env python3
"""sem_show.py <pkl> <mnemonic-prefix> [count]: show cases of a semantics difference class in detail."""
import pickle, sys
cases, ghl, res = pickle.load(open(sys.argv[1], 'rb'))
want = sys.argv[2]; cnt = int(sys.argv[3]) if len(sys.argv) > 3 else 6
shown = 0
for i, c in enumerate(cases):
    code, text, a, x, y, cc, sp = c
    if not text.startswith(want) or i not in res: continue
    g = ghl[i].split(' ')
    if g[0] != 'OK': continue
    ga, gx, gy, gcc, gsp, gpc = [int(v, 16) for v in g[1:7]]
    gm = {int(t.split('=')[0], 16): int(t.split('=')[1], 16) for t in g[7:]}
    (ua, ux, uy, ucc, usp, upc), ud = res[i]
    um = {ad: v for ad, v in ud if not (0x1000 <= ad < 0x1000 + len(code))}
    if (ga, gx, gy, gcc & 31, gsp, gpc) == (ua & 255, ux & 255, uy & 255, ucc & 31, usp, upc) and gm == um: continue
    shown += 1
    print(f'{code.hex()} {text}  in: A={a:02x} X={x:02x} Y={y:02x} CC={cc:02x}({cc&16 and "H" or "-"}{cc&8 and "I" or "-"}{cc&4 and "N" or "-"}{cc&2 and "Z" or "-"}{cc&1 and "C" or "-"}) SP={sp:04x}')
    print(f'   ghidra A={ga:02x} X={gx:02x} Y={gy:02x} CC={gcc:02x} SP={gsp:04x} PC={gpc:04x} mem={ {hex(k):hex(v) for k,v in gm.items()} }')
    print(f'   ucsim  A={ua&255:02x} X={ux&255:02x} Y={uy&255:02x} CC={ucc:02x} SP={usp:04x} PC={upc:04x} mem={ {hex(k):hex(v) for k,v in um.items()} }')
    if shown >= cnt: break
