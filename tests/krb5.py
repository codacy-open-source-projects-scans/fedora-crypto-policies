#!/usr/bin/python3

import sys

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
    from krb5check.krb5_conf import parse, check, ACCEPTED_ENCTYPES
except ImportError:
    print("Skipping krb5 test; checker not found!")
    sys.exit(0)

print("Checking the Krb5 configuration")

# Don't verify EMPTY policy
for policy in ["LEGACY", "DEFAULT", "FUTURE", "FIPS"]:
    path = 'tests/outputs/' + policy + '-krb5.txt'

    sections = parse(path)
    check(sections, ACCEPTED_ENCTYPES)
