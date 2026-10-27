#!/usr/bin/env python3
"""s19tobin.py <in.s19> <out.bin>: Motorola S-record (S1/S2/S3) to a flat 64 KB image at address 0."""
import sys
img = bytearray(0x10000)
for l in open(sys.argv[1]):
    l = l.strip()
    if len(l) < 10 or l[0] != 'S' or l[1] not in '123':
        continue
    alen = {'1': 2, '2': 3, '3': 4}[l[1]]
    n = int(l[2:4], 16)
    a = int(l[4:4 + 2 * alen], 16)
    d = bytes.fromhex(l[4 + 2 * alen:4 + 2 * (n - 1)])
    img[a:a + len(d)] = d
open(sys.argv[2], 'wb').write(img)
