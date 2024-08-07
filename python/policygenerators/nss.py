# SPDX-License-Identifier: LGPL-2.1-or-later

# Copyright (c) 2019 Red Hat, Inc.
# Copyright (c) 2019 Tomáš Mráz <tmraz@fedoraproject.org>

import ctypes
import ctypes.util
import os
from subprocess import CalledProcessError, call
from tempfile import mkstemp

from .configgenerator import ConfigGenerator

NSS_P11_KIT_PROXY = '''
library=p11-kit-proxy.so
name=p11-kit-proxy
'''


class NSSGenerator(ConfigGenerator):
    CONFIG_NAME = 'nss'
    SCOPES = {'tls', 'ssl', 'nss'}

    mac_map = {
        'AEAD': '',
        'HMAC-SHA1': 'HMAC-SHA1',
        'HMAC-MD5': 'HMAC-MD5',
        'HMAC-SHA2-256': 'HMAC-SHA256',
        'HMAC-SHA2-384': 'HMAC-SHA384',
        'HMAC-SHA2-512': 'HMAC-SHA512'
    }

    hash_map = {
        'SHA1': 'SHA1',
        'MD5': 'MD5',
        'SHA2-224': 'SHA224',
        'SHA2-256': 'SHA256',
        'SHA2-384': 'SHA384',
        'SHA2-512': 'SHA512',
        'SHA3-256': '',
        'SHA3-384': '',
        'SHA3-512': '',
        'SHAKE-128': '',
        'SHAKE-256': '',
        'GOSTR94': ''
    }

    curve_map = {
        'X25519': 'CURVE25519',
        'X448': '',
        'SECP256R1': 'SECP256R1',
        'SECP384R1': 'SECP384R1',
        'SECP521R1': 'SECP521R1',
        'X25519-KYBER768': 'XYBER768D00',
    }

    cipher_map = {
        'AES-256-CTR': '',
        'AES-128-CTR': '',
        'RC2-CBC': 'rc2',
        'RC4-128': 'rc4',
        'AES-256-GCM': 'aes256-gcm',
        'AES-128-GCM': 'aes128-gcm',
        'AES-256-CBC': 'aes256-cbc',
        'AES-128-CBC': 'aes128-cbc',
        'CAMELLIA-256-CBC': 'camellia256-cbc',
        'CAMELLIA-128-CBC': 'camellia128-cbc',
        'CAMELLIA-256-GCM': '',
        'CAMELLIA-128-GCM': '',
        'AES-256-CCM': '',
        'AES-128-CCM': '',
        'CHACHA20-POLY1305': 'chacha20-poly1305',
        '3DES-CBC': 'des-ede3-cbc'
    }

    key_exchange_map = {
        'PSK': '',
        'DHE-PSK': '',
        'ECDHE-PSK': '',
        'RSA-PSK': '',
        'RSA': 'RSA',
        'DHE-RSA': 'DHE-RSA',
        'DHE-DSS': 'DHE-DSS',
        'ECDHE': 'ECDHE-RSA:ECDHE-ECDSA',
        'ECDH': 'ECDH-RSA:ECDH-ECDSA',
        'DH': 'DH-RSA:DH-DSS'
    }

    protocol_map = {
        'SSL3.0': 'ssl3.0',
        'TLS1.0': 'tls1.0',
        'TLS1.1': 'tls1.1',
        'TLS1.2': 'tls1.2',
        'TLS1.3': 'tls1.3',
        'DTLS1.0': 'dtls1.0',
        'DTLS1.2': 'dtls1.2'
    }

    # Depends on a dict being ordered,
    # impl. detail in CPython 3.6, guaranteed starting from Python 3.7.
    sign_prefix_ordmap = {
        'RSA-PSS-': 'RSA-PSS',  # must come before RSA-
        'RSA-': 'RSA-PKCS',
        'ECDSA-': 'ECDSA',
        'DSA-': 'DSA',
    }

    @classmethod
    def generate_config(cls, policy):
        p = policy.enabled

        # including it unconditionally, because Fedora NSS depends on p11-kit
        cfg = NSS_P11_KIT_PROXY.lstrip() + '\n\n'

        cfg += 'library=\n'
        cfg += 'name=Policy\n'
        cfg += 'NSS=flags=policyOnly,moduleDB\n'
        cfg += 'config="disallow=ALL allow='

        s = ''
        for i in p['mac']:
            try:
                s = cls.append(s, cls.mac_map[i])
            except KeyError:
                pass

        for i in p['group']:
            try:
                s = cls.append(s, cls.curve_map[i])
            except KeyError:
                pass

        for i in p['cipher']:
            try:
                s = cls.append(s, cls.cipher_map[i])
            except KeyError:
                pass

        for i in p['hash']:
            try:
                s = cls.append(s, cls.hash_map[i])
            except KeyError:
                pass

        for i in p['key_exchange']:
            try:
                s = cls.append(s, cls.key_exchange_map[i])
            except KeyError:
                pass

        # option not in Fedora yet, default to True
        no_tls_require_ems = os.getenv('NSS_NO_TLS_REQUIRE_EMS', '1') == '1'
        if policy.enums['__ems'] == 'ENFORCE' and not no_tls_require_ems:
            s = cls.append(s, 'TLS-REQUIRE-EMS')

        enabled_sigalgs = set()
        for i in p['sign']:
            for prefix, sigalg in cls.sign_prefix_ordmap.items():
                if i.startswith(prefix):
                    if sigalg not in enabled_sigalgs:
                        enabled_sigalgs.add(sigalg)
                        s = cls.append(s, sigalg)
                    break  # limit to first match

        if policy.min_tls_version:
            minver = cls.protocol_map[policy.min_tls_version]
            s = cls.append(s, 'tls-version-min=' + minver)
        else:  # FIXME, preserving behaviour, but this is wrong
            s = cls.append(s, 'tls-version-min=0')

        if policy.min_dtls_version:
            minver = cls.protocol_map[policy.min_dtls_version]
            s = cls.append(s, 'dtls-version-min=' + minver)
        else:  # FIXME, preserving behaviour, but this is wrong
            s = cls.append(s, 'dtls-version-min=0')

        s = cls.append(s, 'DH-MIN=' + str(policy.integers['min_dh_size']))
        s = cls.append(s, 'DSA-MIN=' + str(policy.integers['min_dsa_size']))
        s = cls.append(s, 'RSA-MIN=' + str(policy.integers['min_rsa_size']))

        cfg += s + '"\n'

        return cfg

    @classmethod
    def test_config(cls, config):
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
            cls.eprint('Cannot determine nss version with ctypes, '
                       'assuming >=3.80')
        options = ('-f value -f identifier'
                   if nss_is_lax_by_default and not nss_lax else '')

        fd, path = mkstemp()

        ret = 255
        try:
            with os.fdopen(fd, 'w') as f:
                f.write(config)
            try:
                ret = call(f'/usr/bin/nss-policy-check {options} {path}'
                           '>/dev/null',
                           shell=True)
            except CalledProcessError:
                cls.eprint("/usr/bin/nss-policy-check: Execution failed")
        finally:
            os.unlink(path)

        if ret == 2:
            cls.eprint("There is a warning in NSS generated policy")
            cls.eprint(f'Policy:\n{config}')
            return False
        if ret:
            cls.eprint("There is an error in NSS generated policy")
            cls.eprint(f'Policy:\n{config}')
            return False
        return True
