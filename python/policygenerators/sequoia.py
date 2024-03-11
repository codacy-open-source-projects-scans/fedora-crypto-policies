# SPDX-License-Identifier: LGPL-2.1-or-later

# Copyright (c) 2022 Red Hat, Inc.
# Copyright (c) 2022 Alexander Sosedkin <asosedkin@redhat.com>

import os
import subprocess
from tempfile import mkstemp

try:
    import tomllib as toml
    toml_error = toml.TOMLDecodeError
except ModuleNotFoundError:
    import toml
    toml_error = toml.decoder.TomlDecodeError

from .configgenerator import ConfigGenerator


class SequoiaGenerator(ConfigGenerator):
    # Limitation: controls only
    # * `hash_algorithms`,
    # * `symmetric_algorithms` and
    # * partially, `asymmetric_algorithms`, deduced from `sign` and `group`

    CONFIG_NAME = 'sequoia'
    SCOPES = {'sequoia'}

    # sequoia display name to c-p name, taken from sequoia_openpgp/types/mod.rs
    hash_backwards_map = {
        'md5': 'MD5',
        'sha1': 'SHA1',
        'ripemd160': None,
        'sha224': 'SHA2-224',
        'sha256': 'SHA2-256',
        'sha384': 'SHA2-384',
        'sha512': 'SHA2-512',
    }

    symmetric_backwards_map = {
        'idea': 'IDEA-CFB',
        'tripledes': '3DES-CFB',
        'cast5': None,
        'blowfish': None,
        'aes128': 'AES-128-CFB',
        'aes192': 'AES-192-CFB',
        'aes256': 'AES-256-CFB',
        'twofish': None,
        'camellia128': 'CAMELLIA-128-CFB',
        'camellia192': 'CAMELLIA-192-CFB',
        'camellia256': 'CAMELLIA-256-CFB',
        # 'unencrypted': 'NULL',  # can't be set
    }

    asymmetric_always_disabled = (
        'elgamal1024',
        'elgamal2048',
        'elgamal3072',
        'elgamal4096',
        'brainpoolp256',
        'brainpoolp512',
        # 'unknown',  # can't be set
    )

    @classmethod
    def generate_config(cls, policy):
        p = policy.enabled

        cfg = '[hash_algorithms]\n'
        for seqoia_name, c_p_name in cls.hash_backwards_map.items():
            v = 'always' if c_p_name in p['hash'] else 'never'
            cfg += f'{seqoia_name}.collision_resistance = "{v}"\n'
            cfg += f'{seqoia_name}.second_preimage_resistance = "{v}"\n'
        cfg += 'default_disposition = "never"\n\n'

        cfg += '[symmetric_algorithms]\n'
        for seqoia_name, c_p_name in cls.symmetric_backwards_map.items():
            v = 'always' if c_p_name in p['cipher'] else 'never'
            cfg += f'{seqoia_name} = "{v}"\n'
        cfg += 'default_disposition = "never"\n\n'

        cfg += '[asymmetric_algorithms]\n'
        # ugly inference from other lists
        any_rsa = any(s.startswith('RSA-') for s in p['sign'])
        any_dsa = any(s.startswith('DSA-') for s in p['sign'])
        secp256 = 'SECP256R1' in p['group']
        secp384 = 'SECP384R1' in p['group']
        secp521 = 'SECP521R1' in p['group']
        min_rsa = policy.integers['min_rsa_size']
        for l in 1024, 2048, 3072, 4096:
            v = 'always' if l >= min_rsa and any_rsa else 'never'
            cfg += f'rsa{l} = "{v}"\n'
        min_dsa = policy.integers['min_dsa_size']
        for l in 1024, 2048, 3072, 4096:
            v = 'always' if l >= min_dsa and any_dsa else 'never'
            cfg += f'dsa{l} = "{v}"\n'
        cfg += f'nistp256 = "{"always" if secp256 else "never"}"\n'
        cfg += f'nistp384 = "{"always" if secp384 else "never"}"\n'
        cfg += f'nistp521 = "{"always" if secp521 else "never"}"\n'
        cv25519 = 'X25519' in p['group']
        cfg += f'cv25519 = "{"always" if cv25519 else "never"}"\n'
        for seq_name in cls.asymmetric_always_disabled:
            cfg += f'{seq_name} = "never"\n'
        cfg += 'default_disposition = "never"\n'

        return cfg

    @classmethod
    def test_config(cls, config):
        # check for TOML validity
        toml.loads(config)
        try:
            toml.loads(config)
        except toml_error as ex:
            cls.eprint('There is an error in generated sequoia policy')
            cls.eprint(f'Invalid TOML: {type(ex)} {ex}')
            cls.eprint(f'Policy:\n{config}')
            return False

        # check with sequoia-policy-config-check
        r = subprocess.getstatusoutput('sequoia-policy-config-check /dev/null')
        if r[0] != 0:
            cls.eprint('Working sequoia-policy-config not found, skipping...')
            return True

        fd, path = mkstemp()
        try:
            with os.fdopen(fd, 'w') as f:
                f.write(config)
            r = subprocess.getstatusoutput('sequoia-policy-config-check '
                                           f'{path}')
            if r == (0, ''):
                cls.eprint('sequoia-policy-config-check returns '
                           f'{r[0]}{" `" + r[1] + "`" if r[1] else ""}')
                return True
            cls.eprint('There is an error in generated sequoia policy')
            cls.eprint('sequoia-policy-config-check returns '
                       f'{r[0]}: `{r[1]}`')
            cls.eprint(f'Policy:\n{config}')
        finally:
            os.unlink(path)
        return False


class RPMSequoiaGenerator(SequoiaGenerator):
    CONFIG_NAME = 'rpm-sequoia'
    SCOPES = {'rpm', 'rpm-sequoia'}
