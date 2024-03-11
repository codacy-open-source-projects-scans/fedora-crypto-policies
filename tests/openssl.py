#!/usr/bin/python3

import subprocess
import sys
from pathlib import Path

print('Checking the OpenSSL configuration')

for policy_path in Path('tests', 'outputs').glob('*-openssl.txt'):
    policy = policy_path.name.removesuffix('-openssl.txt')
    if policy in {'EMPTY', 'GOST-ONLY'}:
        continue
    print(f'Checking policy {policy}')

    tmp = policy_path.read_text(encoding='utf-8').rstrip()

    try:
        p = subprocess.run(['openssl', 'ciphers', tmp],  # noqa: S607
                           check=True,
                           encoding='utf-8',
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        print(f'openssl ciphers error {e.returncode}:', file=sys.stderr)
        print(e.stdout, file=sys.stderr)
        print(f'ciphers: {tmp}', file=sys.stderr)
        sys.exit(1)
