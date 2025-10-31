#!/usr/bin/python3

import sys
from pathlib import Path

# krb5check can be found at:
#     https://github.com/frozencemetery/krb5check
# At a minimum, it verifies that:
#   - no unrecognized sections are specified
#   - no values are overriding each other
#   - libdefaults section is present
#   - permitted_enctypes is specified
#   - no unknown enctypes are specified
#   - no known-broken enctypes are specified
#   - if pkinit_dh_min_bits is specified, it is larger than default
#   - if pkinit_dh_min_bits is specified, it is reasonable

try:
    from krb5check.krb5_conf import ACCEPTED_ENCTYPES, check, parse
except ImportError:
    print('Skipping krb5 test; checker not found!')
    sys.exit(0)

print('Checking the Krb5 configuration')

for policy_path in Path('tests', 'outputs').glob('*-krb5.txt'):
    policy = policy_path.name.removesuffix('-krb5.txt')
    print(f'Checking policy {policy}')

    sections = parse(policy_path)
    check(sections, ACCEPTED_ENCTYPES)
