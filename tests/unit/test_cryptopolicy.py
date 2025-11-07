# SPDX-License-Identifier: LGPL-2.1-or-later

# Copyright (c) 2021 Red Hat, Inc.

import textwrap

import pytest

from python.cryptopolicies.alg_lists import glob
from python.cryptopolicies.cryptopolicies import (
    PolicySyntaxDeprecationWarning,
    UnscopedCryptoPolicy,
)
from python.cryptopolicies.validation import (
    PolicyFileNotFoundError,
    PolicySyntaxError,
)
from python.cryptopolicies.validation.alg_lists import ExperimentalValueWarning

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
    with pytest.raises(PolicySyntaxError), pytest.warns(PolicySyntaxError):
        _policy(tmpdir, TESTPOL='a = b = c')


def test_cryptopolicy_smoke_basic(tmpdir):
    cp = _policy(tmpdir, TESTPOL='cipher = AES-*-GCM')
    assert cp.scoped({'tls'}).enabled['cipher'] == [
        'AES-256-GCM', 'AES-192-GCM', 'AES-128-GCM',
    ]


def test_cryptopolicy_smoke_subpolicy(tmpdir):
    cp = _policy(tmpdir,
                 TESTPOL='cipher = AES-*-GCM',
                 MINUS192='cipher = -AES-192-*')
    assert cp.scoped({'tls'}).enabled['cipher'] == [
        'AES-256-GCM', 'AES-128-GCM',
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
        'RC4-128', 'AES-256-GCM', 'AES-192-GCM', 'AES-128-GCM', 'NULL',
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
        'IDEA-CBC', 'NULL',
    ]
    # Used to be ['NULL', 'RC4-128', 'IDEA-CBC']
    assert cp.scoped({'ssh', 'openssh'}).enabled['cipher'] == [
        'NULL', 'IDEA-CBC',
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


def test_cryptopolicy_value_replacement(tmpdir):
    with pytest.warns(
            PolicySyntaxDeprecationWarning,
            match='value X25519-MLKEM768 is deprecated, please rewrite your'
            ' rules using MLKEM768-X25519'):
        cp = _policy(tmpdir, TESTPOL='group = X25519-MLKEM768 P256-MLKEM768')
    assert cp.scoped().enabled['group'] == ['MLKEM768-X25519', 'P256-MLKEM768']


def test_cryptopolicy_compat_to_enum(tmpdir):
    with pytest.warns(
            PolicySyntaxDeprecationWarning,
            match='option ssh_etm = 0 is deprecated, please rewrite your'
            ' rules using etm@SSH = DISABLE_ETM;.*'):
        cp = _policy(tmpdir, TESTPOL='ssh_etm =  0')
    assert cp.scoped({'tls', 'openssl'}).enums['etm'] == 'ANY'
    assert cp.scoped({'ssh', 'openssh'}).enums['etm'] == 'DISABLE_ETM'


def test_cryptopolicy_compat_scoped_ssh_etm_to_enum(tmpdir):
    with pytest.warns(
            PolicySyntaxDeprecationWarning,
            match=r'option ssh_etm@{OpenSSH-server,OpenSSH-client} = 0 is'
            r' deprecated, please rewrite your rules using'
            r' etm@{OpenSSH-server,OpenSSH-client} = DISABLE_ETM;.*'):
        cp = _policy(tmpdir,
                     TESTPOL='ssh_etm@{OpenSSH-server,OpenSSH-client} = 0')
    assert cp.scoped({'tls', 'openssl'}).enums['etm'] == 'ANY'
    assert cp.scoped({'ssh', 'openssh'}).enums['etm'] == 'ANY'
    assert cp.scoped({'ssh', 'openssh-client'}).enums['etm'] == 'DISABLE_ETM'
    assert cp.scoped({'ssh', 'openssh-server'}).enums['etm'] == 'DISABLE_ETM'


def test_cryptopolicy_prepend_order(tmpdir):
    assert glob('AES-192-*M', 'cipher') == ['AES-192-GCM', 'AES-192-CCM']
    # AES-192-*M expands to AES-192-GCM AES-192-CCM ...
    cp = _policy(tmpdir,
                 TESTPOL='cipher = NULL',
                 # ... but +AES-192-*M expands to +AES-192-CCM +AES-192-GCM
                 # so that -GCM ends up first and has higher priority
                 SUBPOL1='cipher = +AES-192-*M')
    assert cp.scoped({'tls', 'openssl'}).enabled['cipher'] == [
        'AES-192-GCM', 'AES-192-CCM', 'NULL',
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


def test_cryptopolicy_experimental(tmpdir):
    plural = 'values `X448-MLKEM768`, `P384-MLKEM768` are experimental'
    with pytest.warns(ExperimentalValueWarning, match=plural):
        cp = _policy(tmpdir,
                     TESTPOL='group = +*-MLKEM768\ngroup = -*-MLKEM768')
    tls_cp = cp.scoped({'tls', 'openssl'})
    assert tls_cp.enabled['group'] == []


def test_cryptopolicy_experimental_warnings_suppression_none(recwarn, tmpdir):
    assert len(recwarn) == 0
    suppress_none = textwrap.dedent('''
        group = -MLKEM768
        sign = -MLDSA65-BP256
    ''').lstrip()
    _policy(tmpdir, TESTPOL=suppress_none)
    assert len(recwarn) == 2  # noqa: PLR2004
    assert recwarn[0].category == ExperimentalValueWarning
    assert '`group` value `MLKEM768` is ' in str(recwarn[0].message)
    assert recwarn[1].category == ExperimentalValueWarning
    assert '`sign` value `MLDSA65-BP256` is ' in str(recwarn[1].message)


def test_cryptopolicy_experimental_warnings_suppression_full(recwarn, tmpdir):
    assert len(recwarn) == 0
    suppress_full = textwrap.dedent('''
        # %suppress_experimental_value_warnings=true
        group = -MLKEM768
        sign = -MLDSA65-BP256
        # %suppress_experimental_value_warnings=false
    ''').lstrip()
    _policy(tmpdir, TESTPOL=suppress_full)
    assert len(recwarn) == 0


def test_cryptopolicy_experimental_warnings_suppression_part(recwarn, tmpdir):
    assert len(recwarn) == 0
    suppress_part = textwrap.dedent('''
        # %suppress_experimental_value_warnings=true
        group = -MLKEM768
        # %suppress_experimental_value_warnings=false
        sign = -MLDSA65-BP256
    ''').lstrip()
    _policy(tmpdir, TESTPOL=suppress_part)
    # this should be 1 warning, but deduplication broke =/
    assert len(recwarn) == 3  # noqa: PLR2004
    assert str(recwarn[0].message) == str(recwarn[1].message)
    assert recwarn[0].lineno == recwarn[1].lineno
    assert recwarn[0].category == recwarn[1].category
    assert recwarn[0].line == recwarn[1].line
    assert str(recwarn[0].message) == str(recwarn[2].message)
    assert recwarn[0].lineno == recwarn[2].lineno
    assert recwarn[0].category == recwarn[2].category
    assert recwarn[0].line == recwarn[2].line
    assert '`sign` value `MLDSA65-BP256` is ' in str(recwarn[0].message)


def test_cryptopolicy_experimental_warnings_suppression_reset(recwarn, tmpdir):
    assert len(recwarn) == 0
    suppress_pol = textwrap.dedent('''
        # %suppress_experimental_value_warnings=true
        group = -MLKEM768
    ''').lstrip()
    subpol = 'sign = -MLDSA65-BP256'  # warnings are not suppressed again
    _policy(tmpdir, TESTPOL=suppress_pol, SUBPOL=subpol)
    assert len(recwarn) == 1
    assert recwarn[0].category == ExperimentalValueWarning
    assert '`sign` value `MLDSA65-BP256` is ' in str(recwarn[0].message)


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
        sha1_in_certs = 0
        ssh_certs = 0
        min_ec_size = 256
        __openssl_block_sha1_signatures = 1
        etm = ANY
        __ems = DEFAULT
        # No scope-specific properties found.
    ''').lstrip()
    cp = _policy(tmpdir, EMPTYPOL='', EMPTYSUBPOL1='\n', EMPTYSUBPOL2='\t')
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
        sha1_in_certs = 0
        ssh_certs = 0
        min_ec_size = 256
        __openssl_block_sha1_signatures = 1
        etm = ANY
        __ems = ENFORCE
        # Scope-specific properties derived for select backends:
        cipher@gnutls = DES-CBC RC4-128 IDEA-CBC
        hash@gnutls =
        sha1_in_certs@gnutls = 1
        cipher@java-tls = DES-CBC RC4-128 IDEA-CBC
        etm@libssh = DISABLE_NON_ETM
        __ems@nss = RELAX
        cipher@nss-tls = DES-CBC RC4-128 IDEA-CBC
        cipher@nss-pkcs12 = IDEA-CBC
        cipher@nss-smime-import = RC4-128 SEED-CBC IDEA-CBC
        etm@openssh = DISABLE_NON_ETM
        hash@openssh-server = MD5 SHA1
        cipher@openssl = NULL DES-CBC RC4-128 IDEA-CBC
    ''').lstrip()
    cp = _policy(tmpdir,
                 TESTPOL='''
                     hash = MD5
                     cipher@openssl = SEED-CBC  # overridden in the next line
                     cipher = RC4-128 IDEA-CBC
                     cipher@tls = +DES-CBC
                     cipher@openssl = +NULL
                     cipher@pkcs12 = -RC4-128
                     cipher@nss-smime = IDEA-CBC
                     cipher@smime-import = +SEED-CBC
                     cipher@smime = +RC4-128  # cipher@nss-smime == cipher@nss
                     hash@openssh-server = SHA1+
                     sha1_in_certs@gnutls = 1
                     hash@gnutls = -MD5
                     etm@SSH = DISABLE_NON_ETM
                     __ems = ENFORCE
                     __ems@nss = RELAX
                 ''')
    assert str(cp) == reference
