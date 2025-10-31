#!/usr/bin/python3

import re
import subprocess
import sys
from pathlib import Path

print('Checking the OpenSSL configuration')

for policy_path in Path('tests', 'outputs').glob('*-opensslcnf.txt'):
    policy = policy_path.name.removesuffix('-opensslcnf.txt')
    if policy in {'EMPTY', 'GOST-ONLY'}:
        continue
    print(f'Checking policy {policy}')

    ciphers, = re.findall(r'^CipherString = (.*)$',
                          policy_path.read_text(encoding='utf-8'),
                          re.MULTILINE)

    try:
        p = subprocess.run(['openssl', 'ciphers', ciphers],  # noqa: S607
                           check=True,
                           encoding='utf-8',
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        print(f'openssl ciphers error {e.returncode}:', file=sys.stderr)
        print(e.stdout, file=sys.stderr)
        print(f'ciphers: {ciphers}', file=sys.stderr)
        sys.exit(1)
