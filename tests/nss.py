#!/usr/bin/python3

import ctypes
import ctypes.util
import glob
import os
import shutil
import subprocess
import sys
import tempfile


if shutil.which('nss-policy-check') is None:
    print('nss-policy-check not found, skipping check', file=sys.stderr)
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
    print('Cannot determine nss version with ctypes, assuming >=3.80',
          file=sys.stderr)
options = (['-f', 'value', '-f', 'identifier']
           if nss_is_lax_by_default and not nss_lax else [])


print('Checking the NSS configuration')

for policy_path in glob.glob('tests/outputs/*-nss.txt'):
    policy = os.path.basename(policy_path)[:-len('-nss.txt')]
    print(f'Checking policy {policy}')
    if policy not in ('EMPTY', 'GOST-ONLY'):
        with open(policy_path, encoding='utf-8') as pf:
            config = pf.read()
        with tempfile.NamedTemporaryFile('w', delete=False) as tf:
            tf.write(config)

        with subprocess.Popen(['nss-policy-check'] + options + [tf.name],
                              stdout=subprocess.PIPE,
                              stderr=subprocess.STDOUT) as p:
            output, _ = p.communicate()
        if p.returncode:
            print(f'Error in NSS policy for {policy}')
            print(f'NSS policy for {policy}:', file=sys.stderr)
            with open(policy_path, encoding='utf-8') as policy_file:
                shutil.copyfileobj(policy_file, sys.stderr)
                sys.stderr.write('\n')
            print('nss-policy-check error:', file=sys.stderr)
            print(output.decode(), file=sys.stderr)
            os.unlink(tf.name)
            sys.exit(1)
        os.unlink(tf.name)
