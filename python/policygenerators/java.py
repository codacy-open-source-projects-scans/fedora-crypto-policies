# SPDX-License-Identifier: LGPL-2.1-or-later

# Copyright (c) 2019 Red Hat, Inc.
# Copyright (c) 2019 Tomáš Mráz <tmraz@fedoraproject.org>

from .configgenerator import ConfigGenerator


class JavaGenerator(ConfigGenerator):
    CONFIG_NAME = 'java'
    SCOPES = {'tls', 'ssl', 'java-tls'}

    hash_not_map = {
        'MD2': 'MD2',
        'MD5': 'MD5',
        'SHA1': 'SHA1',
        'SHA2-224': 'SHA224',
        'SHA2-256': 'SHA256',
        'SHA2-384': 'SHA384',
        'SHA2-512': 'SHA512',
        'SHA3-256': 'SHA3_256',
        'SHA3-384': 'SHA3_384',
        'SHA3-512': 'SHA3_512',
        'SHAKE-128': '',
        'SHAKE-256': '',
        'GOSTR94': ''
    }

    cipher_not_map = {
        'AES-256-CTR': '',
        'AES-128-CTR': '',
        'CHACHA20-POLY1305': 'ChaCha20-Poly1305',
        'CAMELLIA-256-GCM': '',
        'CAMELLIA-128-GCM': '',
        'CAMELLIA-256-CBC': '',
        'CAMELLIA-128-CBC': '',
        'AES-256-CBC': 'AES_256_CBC',
        'AES-128-CBC': 'AES_128_CBC',
        'AES-256-GCM': 'AES_256_GCM',
        'AES-128-GCM': 'AES_128_GCM',
        'AES-256-CCM': 'AES_256_CCM',
        'AES-128-CCM': 'AES_128_CCM',
        'RC4-128': 'RC4_128',
        'RC4-40': 'RC4_40',
        'RC2-CBC': 'RC2',
        'DES-CBC': 'DES_CBC',
        'DES40-CBC': 'DES40_CBC',
        '3DES-CBC': '3DES_EDE_CBC',
        'SEED-CBC': '',
        'IDEA-CBC': '',
        'NULL': 'anon, NULL'
    }

    cipher_legacy_map = {
        'RC4-128': 'RC4_128',
        '3DES-CBC': '3DES_EDE_CBC',
    }

    key_exchange_not_map = {
        'EXPORT': ', '.join((  # noqa: FLY002
            'RSA_EXPORT',
            'DHE_DSS_EXPORT',
            'DHE_RSA_EXPORT',
            'DH_DSS_EXPORT',
            'DH_RSA_EXPORT',
        )),
        'DH': 'DH_RSA, DH_DSS',
        'ANON': 'DH_anon, ECDH_anon',
        'RSA': ', '.join((  # noqa: FLY002
            'TLS_RSA_WITH_AES_256_CBC_SHA256',
            'TLS_RSA_WITH_AES_256_CBC_SHA',
            'TLS_RSA_WITH_AES_128_CBC_SHA256',
            'TLS_RSA_WITH_AES_128_CBC_SHA',
            'TLS_RSA_WITH_AES_256_GCM_SHA384',
            'TLS_RSA_WITH_AES_128_GCM_SHA256',
        )),
        'DHE-RSA': 'DHE_RSA',
        'DHE-DSS': 'DHE_DSS',
        'ECDHE': 'ECDHE',
        'ECDH': 'ECDH',
        'PSK': '',
        'DHE-PSK': '',
        'ECDHE-PSK': '',
        'RSA-PSK': 'RSAPSK'
    }

    sign_not_map = {
        'RSA-MD5': 'MD5withRSA',
        'RSA-SHA1': 'SHA1withRSA',
        'DSA-SHA1': 'SHA1withDSA',
        'ECDSA-SHA1': 'SHA1withECDSA',
        'RSA-SHA2-224': 'SHA224withRSA',
        'DSA-SHA2-224': 'SHA224withDSA',
        'ECDSA-SHA2-224': 'SHA224withECDSA',
        'RSA-SHA2-256': 'SHA256withRSA',
        'DSA-SHA2-256': 'SHA256withDSA',
        'ECDSA-SHA2-256': 'SHA256withECDSA',
        'RSA-SHA2-384': 'SHA384withRSA',
        'DSA-SHA2-384': 'SHA384withDSA',
        'ECDSA-SHA2-384': 'SHA384withECDSA',
        'RSA-SHA2-512': 'SHA512withRSA',
        'DSA-SHA2-512': 'SHA512withDSA',
        'ECDSA-SHA2-512': 'SHA512withECDSA',
        'EDDSA-ED25519': 'Ed25519',
        'EDDSA-ED448': 'Ed448',
        'RSA-PSS-SHA1': 'SHA1withRSAandMGF1',
        'RSA-PSS-SHA2-224': 'SHA224withRSAandMGF1',
        'RSA-PSS-SHA2-256': 'SHA256withRSAandMGF1',
        'RSA-PSS-SHA2-384': 'SHA384withRSAandMGF1',
        'RSA-PSS-SHA2-512': 'SHA512withRSAandMGF1',
    }

    protocol_not_map = {
        'SSL2.0': 'SSLv2',
        'SSL3.0': 'SSLv3',
        'TLS1.0': 'TLSv1',
        'TLS1.1': 'TLSv1.1',
        'TLS1.2': 'TLSv1.2',
        'DTLS1.0': 'DTLSv1.0',
        'DTLS1.2': ''
    }

    mac_not_map = {
        'AEAD': '',
        'HMAC-MD5': 'HmacMD5',
        'HMAC-SHA1': 'HmacSHA1',
        'HMAC-SHA2-256': 'HmacSHA256',
        'HMAC-SHA2-384': 'HmacSHA384',
        'HMAC-SHA2-512': 'HmacSHA512',
    }

    @classmethod
    def generate_config(cls, policy):
        p = policy.enabled
        ip = policy.disabled
        sep = ', '

        shared = [  # unconditionally disabled
            'MD2', 'MD5withDSA', 'MD5withECDSA'
            'RIPEMD160withRSA', 'RIPEMD160withECDSA',
            'RIPEMD160withRSAandMGF1',
        ]

        for i in ip['sign']:
            try:
                shared.append(cls.sign_not_map[i])
            except KeyError:
                pass

        def keysize(keyword, size):
            return f'{keyword} keySize < {size}' if size else keyword

        shared.append(keysize('RSA', policy.integers['min_rsa_size']))
        shared.append(keysize('DSA', policy.integers['min_dsa_size']))
        shared.append(keysize('DH', policy.integers['min_dh_size']))

        # this unconditional measure is mostly because
        # jdk.tls.namedGroups, an allowlisting and, all around,
        # a mighty more preferable property,
        # is a system property that might not be picked up
        shared.append('EC keySize < 256')

        cfg = f'jdk.certpath.disabledAlgorithms={", ".join(shared)}'

        for i in ip['hash']:
            try:
                cfg = cls.append(cfg, cls.hash_not_map[i], sep)
            except KeyError:
                pass

        cfg += f'\njdk.tls.disabledAlgorithms={", ".join(shared)}'

        for i in ip['protocol']:
            try:
                cfg = cls.append(cfg, cls.protocol_not_map[i], sep)
            except KeyError:
                pass

        for i in ip['key_exchange']:
            try:
                cfg = cls.append(cfg, cls.key_exchange_not_map[i], sep)
            except KeyError:
                pass

        for i in ip['cipher']:
            try:
                cfg = cls.append(cfg, cls.cipher_not_map[i], sep)
            except KeyError:
                pass

        for i in ip['mac']:
            try:
                cfg = cls.append(cfg, cls.mac_not_map[i], sep)
            except KeyError:
                pass

        cfg += '\njdk.tls.legacyAlgorithms='
        s = ''
        for i in p['cipher']:
            try:
                s = cls.append(s, cls.cipher_legacy_map[i], sep)
            except KeyError:
                pass
        cfg += f'{s}\n'

        return cfg

    @classmethod
    def test_config(cls, config):  # pylint: disable=unused-argument
        return True


class JavaSystemGenerator(ConfigGenerator):
    CONFIG_NAME = 'javasystem'
    SCOPES = {'tls', 'ssl', 'java-tls'}

    group_map = {
        'X25519': 'x25519',
        'SECP256R1': 'secp256r1',
        'SECP384R1': 'secp384r1',
        'SECP521R1': 'secp521r1',
        'X448': 'x448',
        'FFDHE-2048': 'ffdhe2048',
        'FFDHE-3072': 'ffdhe3072',
        'FFDHE-4096': 'ffdhe4096',
        'FFDHE-6144': 'ffdhe6144',
        'FFDHE-8192': 'ffdhe8192',
    }

    @classmethod
    def generate_config(cls, policy):
        p = policy.enabled
        sep = ', '
        cfg = ''

        cfg += f'jdk.tls.ephemeralDHKeySize={policy.integers["min_dh_size"]}\n'

        s = ''
        for i in p['group']:
            try:
                s = cls.append(s, cls.group_map[i], sep)
            except KeyError:
                pass
        cfg += f'jdk.tls.namedGroups={s}\n'

        return cfg

    @classmethod
    def test_config(cls, config):  # pylint: disable=unused-argument
        return True
