# SPDX-License-Identifier: LGPL-2.1-or-later

# Copyright (c) 2021 Red Hat, Inc.

import pytest

from python.cryptopolicies.cryptopolicies import ScopeSelector
from python.cryptopolicies.validation.scope import (
    ScopeSelectorCommaError,
    ScopeSelectorCurlyBracketsError,
    ScopeSelectorEmptyError,
    ScopeSelectorIllegalCharacterError,
    ScopeSelectorMatchedNothingError,
    ScopeUnknownError,
)


def test_scope_selector_any():
    scope_any = ScopeSelector()
    assert str(scope_any) == "<ScopeSelector pattern='*'>"
    assert scope_any.matches({'ssh'})
    assert scope_any.matches({'tls', 'gnutls'})
    assert scope_any.matches({})


def test_scope_selector_tls():
    scope_tls = ScopeSelector('tls')
    assert str(scope_tls) == "<ScopeSelector pattern='tls'>"
    assert scope_tls.matches({'tls', 'gnutls'})
    assert not scope_tls.matches({'ssh', 'openssh'})


def test_scope_selector_nontls():
    scope_nontls = ScopeSelector('!tls')
    assert not scope_nontls.matches({'tls', 'gnutls'})
    assert scope_nontls.matches({'ssh', 'openssh'})


def test_scope_selector_posglob():
    scope_posglob = ScopeSelector('tls*')
    assert str(scope_posglob) == "<ScopeSelector pattern='tls*'>"
    assert scope_posglob.matches({'tls'})
    assert not scope_posglob.matches({'gnutls'})
    assert not scope_posglob.matches({'ssh'})
    assert not scope_posglob.matches({'openssh'})


def test_scope_selector_negglob():
    scope_negglob = ScopeSelector('!tls*')
    assert str(scope_negglob) == "<ScopeSelector pattern='!tls*'>"
    assert not scope_negglob.matches({'tls', 'gnutls'})
    assert scope_negglob.matches({'ssh', 'openssh'})


def test_scope_selector_posmixed():
    scope_posmixed = ScopeSelector('{*utls,ssh}')
    assert str(scope_posmixed) == "<ScopeSelector pattern='{*utls,ssh}'>"
    assert scope_posmixed.matches({'tls', 'gnutls'})
    assert scope_posmixed.matches({'ssh', 'openssh'})
    assert not scope_posmixed.matches({'tls', 'openssl'})
    assert not scope_posmixed.matches({'krb5'})


def test_scope_selector_negmixed():
    scope_negmixed = ScopeSelector('!{*utls,ssh}')
    assert str(scope_negmixed) == "<ScopeSelector pattern='!{*utls,ssh}'>"
    assert not scope_negmixed.matches({'tls', 'gnutls'})
    assert not scope_negmixed.matches({'ssh', 'openssh'})
    assert scope_negmixed.matches({'tls', 'openssl'})
    assert scope_negmixed.matches({'krb5'})


def test_scope_selector_curly_brackets():
    for s in ('{', '}', '{a', '{a{', 'a{}', 'a}}', 'a}', '{{},a}'):
        with pytest.raises(ScopeSelectorCurlyBracketsError):
            ScopeSelector(s)


def test_scope_selector_empty():
    for s in ('', '!', '{}', '!{}', '{tls,}'):
        with pytest.raises(ScopeSelectorEmptyError):
            ScopeSelector(s)


def test_scope_selector_illegal_character():
    for s in (' ', '! ', '{ }', '!{ }', '3#', 'a+b'):
        with pytest.raises(ScopeSelectorIllegalCharacterError):
            ScopeSelector(s)


def test_scope_selector_comma():
    with pytest.raises(ScopeSelectorCommaError):
        ScopeSelector(',')
    with pytest.raises(ScopeSelectorCommaError):
        ScopeSelector('tls,ssh')


def test_scope_selector_unknown():
    with pytest.raises(ScopeUnknownError):
        ScopeSelector('nonex')
    with pytest.raises(ScopeUnknownError):
        ScopeSelector('!nonex')
    with pytest.raises(ScopeUnknownError):
        ScopeSelector('!{nonex,tls}')


def test_scope_selector_nomatch():
    with pytest.raises(ScopeSelectorMatchedNothingError):
        ScopeSelector('*nonex*')
    with pytest.raises(ScopeSelectorMatchedNothingError):
        ScopeSelector('!*nonex*')
    with pytest.raises(ScopeSelectorMatchedNothingError):
        ScopeSelector('{tls,*nonex*}')
    with pytest.raises(ScopeSelectorMatchedNothingError):
        ScopeSelector('!{tls,*nonex*}')
