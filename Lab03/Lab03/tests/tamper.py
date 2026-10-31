#!/usr/bin/env python3
"""Flip a byte of a package; keep the input untouched."""
import argparse
from pathlib import Path
p=argparse.ArgumentParser();p.add_argument('input',type=Path);p.add_argument('output',type=Path);p.add_argument('offset',type=lambda s:int(s,0));p.add_argument('--xor',type=lambda s:int(s,0),default=1);a=p.parse_args()
if a.input.resolve()==a.output.resolve():p.error('use a different output path')
if a.output.exists():p.error('output already exists')
b=bytearray(a.input.read_bytes());i=a.offset if a.offset>=0 else len(b)+a.offset
if not 0<=i<len(b) or not 0<a.xor<=255:p.error('invalid offset/xor')
b[i]^=a.xor
with a.output.open('xb') as f:f.write(b)
print(f'Wrote modified copy; offset={i}, xor={a.xor:02x}')
