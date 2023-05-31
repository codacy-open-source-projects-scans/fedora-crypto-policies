# SPDX-License-Identifier: LGPL-2.1-or-later

# Copyright (c) 2021 Red Hat, Inc.

import textwrap

import pytest

from python.cryptopolicies.cryptopolicies import (
    PolicySyntaxDeprecationWarning,
    preprocess_text,
)


def test_preprocess_text_basics():
    assert (preprocess_text('a=b\nc=d#protocol = TLS1.2\ne=f')
            == 'a = b\nc = d\ne = f')
    assert preprocess_text('a=b\n#protocol = TLS1.2') == 'a = b'
    assert preprocess_text('# commented out protocol = TLS1.2') == ''


def test_preprocess_text_compat():
    with pytest.warns(PolicySyntaxDeprecationWarning):
        # doesn't move or rewrite the rule, just warns
        assert (preprocess_text('protocol = TLS1.2\na=b')
                == 'protocol = TLS1.2\na = b')
    with pytest.warns(PolicySyntaxDeprecationWarning):
        # moves the rule to the end, rewrites it
        assert (preprocess_text('ike_protocol = IKEv1\na=b')
                == 'a = b\nprotocol@IKE = IKEv1')
    with pytest.warns(PolicySyntaxDeprecationWarning):
        assert preprocess_text('''  # reordering is intended
            ike_protocol = y
            protocol = x
            tls_cipher = a b
            cipher = a b c
            ssh_cipher = b c
        ''') == textwrap.dedent('''
            protocol = x
            cipher = a b c
            cipher@TLS = a b
            cipher@SSH = b c
            protocol@IKE = y
        ''').strip()


def test_preprocess_text_compat_problematic():
    with pytest.warns(PolicySyntaxDeprecationWarning):
        # moves the rule to the end, rewrites it
        assert (preprocess_text('tls_cipher = NULL+')
                == 'cipher@TLS = NULL+')
    with pytest.warns(PolicySyntaxDeprecationWarning):
        # moves the rule to the end, rewrites it
        assert (preprocess_text('tls_cipher = \\\n\\\nNULL+\na=b\\\n')
                == 'a = b\ncipher@TLS = NULL+')


def test_preprocess_text_compat_diamond_problem():
    with pytest.warns(PolicySyntaxDeprecationWarning):
        # previous behaviour: at the end of the policy (but not a subpolicy!)
        # derived properties were set to parent properties if missing;
        # e.g., ssh_cipher or tls_cipher were set to cipher

        # the current 'correct' way to disable ciphers, reordering is intended
        assert preprocess_text('''
            # policy
            tls_cipher = a b
            cipher = a b c
            ssh_cipher = b c
        ''') == textwrap.dedent('''
            cipher = a b c
            cipher@TLS = a b
            cipher@SSH = b c
        ''').strip()

        assert preprocess_text('''
            # the current way of disabling ciphers
            ssh_cipher = -b
            cipher = -b
            tls_cipher = -b
        ''') == textwrap.dedent('''
            cipher = -b
            cipher@TLS = -b
            cipher@SSH = -b
        ''').strip()

        # subpolicy which used to affects cipher&ssh_cipher, but not tls_cipher
        assert preprocess_text('''
            # subpolicy
            cipher = -b      # used to not affect tls_cipher (compat insanity)!
            ssh_cipher = -b  # does affect cipher@SSH
        ''') == textwrap.dedent('''
            cipher = -b
            cipher@SSH = -b
        ''').strip()
