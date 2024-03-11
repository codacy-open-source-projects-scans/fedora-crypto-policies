#!/usr/bin/python3

import ctypes
import ctypes.util
import os
import shutil
import subprocess
import sys
from pathlib import Path

if shutil.which('nss-policy-check') is None:
    print('nss-policy-check not found, skipping check')
    sys.exit(0)


nss_path = ctypes.util.find_library('nss3')
nss_lib = ctypes.CDLL(nss_path)

nss_lax = os.getenv('NSS_LAX', '0') == '1'
nss_is_lax_by_default = True
try:
    if not nss_lib.NSS_VersionCheck(b'3.80'):
        # NSS older than 3.80 uses strict config checking.
        # 3.80 and newer ignores new keywords by default
        # and needs extra switches to be strict.
        nss_is_lax_by_default = False
except AttributeError:
    print('Cannot determine nss version with ctypes, assuming >=3.80')
options = (['-f', 'value', '-f', 'identifier']
           if nss_is_lax_by_default and not nss_lax else [])


print('Checking the NSS configuration')

for policy_path in Path('tests', 'outputs').glob('*-nss.txt'):
    policy = policy_path.name.removesuffix('-nss.txt')
    print(f'Checking policy {policy}')
    if policy not in {'EMPTY', 'GOST-ONLY'}:
        try:
            p = subprocess.run(['nss-policy-check',  # noqa: S607
                                *options, policy_path],
                               check=True,
                               encoding='utf-8',
                               stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT)
        except subprocess.CalledProcessError as e:
            print(f'Error in NSS policy for {policy}', file=sys.stderr)
            print(f'NSS policy for {policy}:', file=sys.stderr)
            print(policy_path.read_text(encoding='utf-8'), file=sys.stderr)
            print(f'nss-policy-check error {e.returncode}:', file=sys.stderr)
            print(e.stdout, file=sys.stderr)
            sys.exit(1)
