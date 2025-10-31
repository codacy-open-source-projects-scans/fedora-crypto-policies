#!/usr/bin/python3

import os
import subprocess
import sys
from pathlib import Path

if os.getenv('OLD_GNUTLS') == '1':
    print('Not checking the GnuTLS configuration')
    sys.exit(0)

print('Checking the GnuTLS configuration')

for policy_path in Path('tests', 'outputs').glob('*-gnutls.txt'):
    policy = policy_path.name.removesuffix('-gnutls.txt')
    if policy == 'GOST-ONLY':
        continue
    print(f'Checking policy {policy}')

    p = subprocess.run(['gnutls-cli', '-l'],  # noqa: S607
                       env={**os.environ,
                            'GNUTLS_DEBUG_LEVEL': '3',
                            'GNUTLS_SYSTEM_PRIORITY_FILE': policy_path,
                            'GNUTLS_SYSTEM_PRIORITY_FAIL_ON_INVALID': '1'},
                       check=False,
                       encoding='utf-8',
                       stdout=subprocess.PIPE, stderr=subprocess.STDOUT)

    if p.returncode == 0 and policy == 'EMPTY':
        print(f'Error in gnutls empty policy {policy}', file=sys.stderr)
        print(p.stdout, file=sys.stderr)
        sys.exit(1)
    elif p.returncode != 0 and policy != 'EMPTY':
        print(f'Error in gnutls policy {policy}', file=sys.stderr)
        print(p.stdout, file=sys.stderr)
        sys.exit(1)
