#!/usr/bin/python3

import subprocess
import sys
from pathlib import Path

print('Checking the Java configuration')

subprocess.run(['javac', 'tests/java/CipherList.java'],  # noqa: S607
               check=True)

for policy_path in Path('tests', 'outputs').glob('*-java.txt'):
    policy = policy_path.name.removesuffix('-java.txt')

    print(f'Checking policy {policy}')

    # catch errors here, in this script,
    # since the -D option will ignore missing files.

    if not policy_path.exists():
        print(f'Policy file {policy_path} missing')
        sys.exit(1)

    try:
        p = subprocess.run(['java',  # noqa: S607
                            '-Djava.security.disableSystemPropertiesFile=true',
                            f'-Djava.security.properties={policy_path}',
                            '-cp', 'tests/java', 'CipherList', '-l'],
                           check=True,
                           encoding='utf-8',
                           stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    except subprocess.CalledProcessError as e:
        print(f'CipherList error {e.returncode}:', file=sys.stderr)
        print(e.stdout, file=sys.stderr)
        sys.exit(1)

    out = p.stdout.rstrip()
    lines = out.split('\n')
    line_count = out.count('\n')

    if policy in {'EMPTY', 'GOST-ONLY'}:
        if line_count >= 2:  # we allow SCSV  # noqa: PLR2004
            print('Empty policy has ciphersuites!', file=sys.stderr)
            print(p.stdout, file=sys.stderr)
            sys.exit(1)
    else:
        if 'TLS_EMPTY_RENEGOTIATION_INFO_SCSV' not in lines:
            print('Could not find TLS_EMPTY_RENEGOTIATION_INFO_SCSV '
                  f'in {policy}', file=sys.stderr)
            print(p.stdout, file=sys.stderr)
            sys.exit(1)

        if line_count <= 1:  # SCSV
            print(f'Policy {policy} has no ciphersuites!', file=sys.stderr)
            print(p.stdout, file=sys.stderr)
            sys.exit(1)
