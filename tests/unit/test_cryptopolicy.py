# SPDX-License-Identifier: LGPL-2.1-or-later

# Copyright (c) 2021 Red Hat, Inc.

import textwrap

import pytest

from python.cryptopolicies.cryptopolicies import (
    UnscopedCryptoPolicy,
    PolicySyntaxDeprecationWarning,
)
from python.cryptopolicies.alg_lists import glob

from python.cryptopolicies.validation import (
    PolicySyntaxError, PolicyFileNotFoundError
)


TESTPOL = '''
# boring policy
cipher = AES-*-GCM
'''
MINUS192 = 'cipher = -AES-192-*'


def _policy(tmpdir, **kwargs):
    subpolicy = False
    for k, v in kwargs.items():
        if not subpolicy:
            tmpdir.join(f'{k}.pol').write(v)
            subpolicy = True
        else:
            if not tmpdir.join('modules').check(dir=True):
                tmpdir.mkdir('modules')
            tmpdir.join('modules').join(f'{k}.pmod').write(v)
    # pylint: disable=no-value-for-parameter
    return UnscopedCryptoPolicy(*kwargs.keys(), policydir=str(tmpdir))


def test_cryptopolicy_is_empty(tmpdir):
    assert _policy(tmpdir, TESTPOL='').is_empty()
    assert _policy(tmpdir, TESTPOL=' \n\t').is_empty()


def test_cryptopolicy_not_found():
    with pytest.raises(PolicyFileNotFoundError):
        UnscopedCryptoPolicy('NONEX')


def test_cryptopolicy_smoke_broken(tmpdir):
    with pytest.raises(PolicySyntaxError):
        with pytest.warns(PolicySyntaxError):
            _policy(tmpdir, TESTPOL='a = b = c')


def test_cryptopolicy_smoke_basic(tmpdir):
    cp = _policy(tmpdir, TESTPOL='cipher = AES-*-GCM')
    assert cp.scoped({'tls'}).enabled['cipher'] == [
        'AES-256-GCM', 'AES-192-GCM', 'AES-128-GCM'
    ]


def test_cryptopolicy_smoke_subpolicy(tmpdir):
    cp = _policy(tmpdir,
                 TESTPOL='cipher = AES-*-GCM',
                 MINUS192='cipher = -AES-192-*')
    assert cp.scoped({'tls'}).enabled['cipher'] == [
        'AES-256-GCM', 'AES-128-GCM'
    ]


def test_cryptopolicy_smoke_several_subpolicies(tmpdir):
    cp = _policy(tmpdir,
                 TESTPOL='cipher = AES-*-GCM',
                 MINUS_192='cipher = -AES-192-*',
                 TLS_RESET='cipher@TLS = AES-*-GCM',
                 MINUS_128_SSH='cipher@SSH = -AES-128-*',
                 APPEND_NULL_TLS='cipher@TLS = NULL+',
                 PREPEND_RC4='cipher = +RC4-128')
    assert cp.scoped({'tls', 'openssl'}).enabled['cipher'] == [
        'RC4-128', 'AES-256-GCM', 'AES-192-GCM', 'AES-128-GCM', 'NULL'
    ]
    assert cp.scoped({'ssh', 'openssh'}).enabled['cipher'] == [
        'RC4-128', 'AES-256-GCM',
    ]
    assert 'AES-192-GCM' in cp.scoped({'ssh', 'openssh'}).disabled['cipher']
    assert 'AES-128-GCM' in cp.scoped({'ssh', 'openssh'}).disabled['cipher']
    assert 'NULL' in cp.scoped({'ssh', 'openssh'}).disabled['cipher']


def test_cryptopolicy_compat_diamond_new_recommended(tmpdir):
    with pytest.warns(PolicySyntaxDeprecationWarning):
        cp = _policy(tmpdir,
                     TESTPOL='''
                         tls_cipher = DES-CBC RC4-128
                         cipher = RC4-128 IDEA-CBC
                         # ssh_cipher derived as RC4-128 IDEA-CBC
                     ''',
                     TESTSUBPOL='''
                         # as simple and intuitive as it gets
                         cipher = -RC4-128
                     ''')
    assert cp.scoped({'tls', 'openssl'}).enabled['cipher'] == ['DES-CBC']
    assert cp.scoped({'ssh', 'openssh'}).enabled['cipher'] == ['IDEA-CBC']
    assert cp.scoped().enabled['cipher'] == ['IDEA-CBC']


def test_cryptopolicy_compat_diamond_old_recommended(tmpdir):
    with pytest.warns(PolicySyntaxDeprecationWarning):
        cp = _policy(tmpdir,
                     TESTPOL='''
                         tls_cipher = DES-CBC RC4-128
                         cipher = RC4-128 IDEA-CBC
                         # ssh_cipher derived as RC4-128 IDEA-CBC
                     ''',
                     TESTSUBPOL='''
                         # the current 'correct' way to disable ciphers
                         tls_cipher = -RC4-128
                         cipher = -RC4-128
                         ssh_cipher = -RC4-128
                     ''')
    assert cp.scoped({'tls', 'openssl'}).enabled['cipher'] == ['DES-CBC']
    assert cp.scoped({'ssh', 'openssh'}).enabled['cipher'] == ['IDEA-CBC']
    assert cp.scoped().enabled['cipher'] == ['IDEA-CBC']


def test_cryptopolicy_compat_diamond_breaking1(tmpdir):
    with pytest.warns(PolicySyntaxDeprecationWarning):
        cp = _policy(tmpdir,
                     TESTPOL='''
                         tls_cipher = DES-CBC RC4-128
                         cipher = RC4-128 IDEA-CBC
                         # ssh_cipher derived as RC4-128 IDEA-CBC
                     ''',
                     TESTSUBPOL='''
                         # BEHAVIOUR CHANGE!
                         # Modifying cipher in subpolicy previously
                         # didn't affect tls_cipher / ssh_cipher!
                         # Now it does affect cipher@tls / cipher@ssh,
                         # which is a sane, but backwards
                         # incompatible thing to do.
                         cipher = -RC4-128
                     ''')
    # Used to be ['DES-CBC', 'RC4-128']
    assert cp.scoped({'tls', 'openssl'}).enabled['cipher'] == ['DES-CBC']
    # Used to be ['RC4-128', 'IDEA-CBC']
    assert cp.scoped({'ssh', 'openssh'}).enabled['cipher'] == ['IDEA-CBC']
    assert cp.scoped().enabled['cipher'] == ['IDEA-CBC']


def test_cryptopolicy_compat_diamond_breaking2(tmpdir):
    with pytest.warns(PolicySyntaxDeprecationWarning):
        cp = _policy(tmpdir,
                     TESTPOL='''
                         cipher = RC4-128 IDEA-CBC
                         # tls_cipher derived as RC4-128 IDEA-CBC
                         # ssh_cipher derived as RC4-128 IDEA-CBC
                     ''',
                     TESTSUBPOL1='tls_cipher = NULL+',
                     # BEHAVIOUR CHANGE: same as above.
                     TESTSUBPOL2='cipher = -RC4-128',
                     TESTSUBPOL3='ssh_cipher = +NULL')
    # Used to be ['RC4-128', 'IDEA-CBC', 'NULL']
    assert cp.scoped({'tls', 'openssl'}).enabled['cipher'] == [
        'IDEA-CBC', 'NULL'
    ]
    # Used to be ['NULL', 'RC4-128', 'IDEA-CBC']
    assert cp.scoped({'ssh', 'openssh'}).enabled['cipher'] == [
        'NULL', 'IDEA-CBC'
    ]
    assert cp.scoped().enabled['cipher'] == ['IDEA-CBC']


def test_cryptopolicy_sha1_in_dnssec(tmpdir):
    with pytest.warns(PolicySyntaxDeprecationWarning):
        cp = _policy(tmpdir,
                     TESTPOL='''
                         hash = MD5
                         sha1_in_dnssec = 1
                     ''')
    assert cp.scoped({'tls', 'openssl'}).enabled['hash'] == ['MD5']
    assert cp.scoped({'tls', 'openssl'}).enabled['sign'] == []
    b = cp.scoped({'dnssec', 'bind'})
    assert b.enabled['hash'] == ['MD5', 'SHA1']
    assert b.enabled['sign'] == ['RSA-SHA1', 'ECDSA-SHA1']
    assert 'DSA-SHA1' in b.disabled['sign']


def test_cryptopolicy_prepend_order(tmpdir):
    assert glob('AES-192-*M', 'cipher') == ['AES-192-GCM', 'AES-192-CCM']
    # AES-192-*M expands to AES-192-GCM AES-192-CCM ...
    cp = _policy(tmpdir,
                 TESTPOL='cipher = NULL',
                 # ... but +AES-192-*M expands to +AES-192-CCM +AES-192-GCM
                 # so that -GCM ends up first and has higher priority
                 SUBPOL1='cipher = +AES-192-*M')
    assert cp.scoped({'tls', 'openssl'}).enabled['cipher'] == [
        'AES-192-GCM', 'AES-192-CCM', 'NULL'
    ]


def test_cryptopolicy_no_duplicates(tmpdir):
    cp = _policy(tmpdir, TESTPOL='cipher = AES-192-G* NULL AES-192-C*')
    assert cp.scoped({'tls', 'openssl'}).enabled['cipher'] == [
        'AES-192-GCM',
        'NULL',
        'AES-192-CCM', 'AES-192-CTR', 'AES-192-CBC', 'AES-192-CFB',
    ]
    cp = _policy(tmpdir,
                 TESTPOL='cipher = AES-192-G* NULL AES-192-C*',
                 SUBPOL1='cipher = AES-192-CTR+',  # no effect
                 SUBPOL2='cipher = +AES-192-CCM')  # moves CCM first

    assert cp.scoped({'tls', 'openssl'}).enabled['cipher'] == [
        'AES-192-CCM',
        'AES-192-GCM',
        'NULL',
        'AES-192-CTR', 'AES-192-CBC', 'AES-192-CFB',
    ]


def test_cryptopolicy_minver(tmpdir):
    cp = _policy(tmpdir, TESTPOL='protocol@TLS = TLS*\nmin_tls_version=TLS1.1')
    tls_cp = cp.scoped({'tls', 'openssl'})
    assert tls_cp.enabled['protocol'] == ['TLS1.3', 'TLS1.2', 'TLS1.1']
    assert tls_cp.min_tls_version == 'TLS1.1'
    assert tls_cp.max_tls_version == 'TLS1.3'
    assert tls_cp.min_dtls_version is None
    assert tls_cp.max_dtls_version is None


def test_cryptopolicy_maxver(tmpdir):
    cp = _policy(tmpdir,
                 TESTPOL='protocol@TLS = DTLS*\nmin_dtls_version=DTLS1.0')
    tls_cp = cp.scoped({'tls', 'openssl'})
    assert tls_cp.enabled['protocol'] == ['DTLS1.2', 'DTLS1.0']
    assert tls_cp.min_dtls_version == 'DTLS1.0'
    assert tls_cp.max_dtls_version == 'DTLS1.2'
    assert tls_cp.min_tls_version is None
    assert tls_cp.max_tls_version is None


def test_cryptopolicy_to_string_empty(tmpdir):
    reference = textwrap.dedent('''
        # Policy EMPTYPOL:EMPTYSUBPOL1:EMPTYSUBPOL2 dump
        #
        # Do not parse the contents of this file with automated tools,
        # it is provided for review convenience only.
        #
        # Baseline values for all scopes:
        cipher =
        group =
        hash =
        key_exchange =
        mac =
        protocol =
        sign =
        arbitrary_dh_groups = 0
        min_dh_size = 0
        min_dsa_size = 0
        min_rsa_size = 0
        __openssl_block_sha1_signatures = 0
        sha1_in_certs = 0
        ssh_certs = 0
        ssh_etm = 0
        __ems = DEFAULT
        # No scope-specific properties found.
    ''').lstrip()
    cp = _policy(tmpdir, EMPTYPOL='', EMPTYSUBPOL1='\n', EMPTYSUBPOL2='\t')
    print(repr(reference[:30]))
    print(repr(str(cp)[:30]))
    assert str(cp) == reference


def test_cryptopolicy_to_string_twisted(tmpdir):
    reference = textwrap.dedent('''
        # Policy TESTPOL dump
        #
        # Do not parse the contents of this file with automated tools,
        # it is provided for review convenience only.
        #
        # Baseline values for all scopes:
        cipher = RC4-128 IDEA-CBC
        group =
        hash = MD5
        key_exchange =
        mac =
        protocol =
        sign =
        arbitrary_dh_groups = 0
        min_dh_size = 0
        min_dsa_size = 0
        min_rsa_size = 0
        __openssl_block_sha1_signatures = 0
        sha1_in_certs = 0
        ssh_certs = 0
        ssh_etm = 0
        __ems = ENFORCE
        # Scope-specific properties derived for select backends:
        cipher@gnutls = DES-CBC
        hash@gnutls =
        sha1_in_certs@gnutls = 1
        cipher@java-tls = DES-CBC
        cipher@nss = DES-CBC
        __ems@nss = RELAX
        cipher@openssl = NULL DES-CBC
    ''').lstrip()
    cp = _policy(tmpdir,
                 TESTPOL='''
                     hash = MD5
                     cipher@openssl = SEED-CBC  # overridden in the next line
                     cipher = RC4-128 IDEA-CBC
                     cipher@tls = DES-CBC
                     cipher@openssl = +NULL
                     sha1_in_certs@gnutls = 1
                     hash@gnutls = -MD5
                     __ems = ENFORCE
                     __ems@nss = RELAX
                 ''')
    assert str(cp) == reference
