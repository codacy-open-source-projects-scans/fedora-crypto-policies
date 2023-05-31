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


# Cannot validate with pre-3.59 NSS that doesn't know ECDSA/RSA-PSS/RSA-PKCS
# identifiers yet. Checking for 3.65 because Fedora keeps reverting the change.
# First one with unreverted is F34's 3.65 (but not F33's 3.65!)
old_nss = os.getenv('OLD_NSS', None)
try:
    nss = ctypes.CDLL(ctypes.util.find_library('nss3'))
    if not nss.NSS_VersionCheck(b'3.65'):
        print('Working around nss-policy-check verification '
              'due to nss being older than 3.65', file=sys.stderr)
        old_nss = True
except AttributeError:
    print('Cannot determine nss version with ctypes, hoping for >=3.59',
          file=sys.stderr)


print('Checking the NSS configuration')

for policy_path in glob.glob('tests/outputs/*-nss.txt'):
    policy = os.path.basename(policy_path)[:-len('-nss.txt')]
    print(f'Checking policy {policy}')
    if policy not in ('EMPTY', 'GOST-ONLY'):
        with open(policy_path, encoding='utf-8') as pf:
            config = pf.read()
        with tempfile.NamedTemporaryFile('w', delete=False) as tf:
            tf.write(config
                     if not old_nss else
                     config.replace(':ECDSA:', ':')
                           .replace(':RSA-PSS:', ':')
                           .replace(':RSA-PKCS:', ':')
                           .replace(':DSA:', ':'))

        with subprocess.Popen(['nss-policy-check', tf.name],
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
