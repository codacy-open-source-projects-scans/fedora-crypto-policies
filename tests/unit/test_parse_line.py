# SPDX-License-Identifier: LGPL-2.1-or-later

# Copyright (c) 2021 Red Hat, Inc.

import pytest

from python.cryptopolicies.cryptopolicies import (
    Directive,
    Operation,
    parse_line,
)
from python.cryptopolicies.validation.rules import MalformedLineError


def test_parse_line():
    assert parse_line('cipher = AES-128-GCM AES-256-GCM') == [
        Directive(prop_name='cipher', scope='*',
                  operation=Operation.RESET, value=None),
        Directive(prop_name='cipher', scope='*',
                  operation=Operation.APPEND, value='AES-128-GCM'),
        Directive(prop_name='cipher', scope='*',
                  operation=Operation.APPEND, value='AES-256-GCM'),
    ]
    assert parse_line('cipher@gnutls = +AES-128-GCM') == [
        Directive(prop_name='cipher', scope='gnutls',
                  operation=Operation.PREPEND, value='AES-128-GCM'),
    ]
    assert parse_line('cipher@*SSH = AES-128-CBC+ -NULL') == [
        Directive(prop_name='cipher', scope='*ssh',
                  operation=Operation.APPEND, value='AES-128-CBC'),
        Directive(prop_name='cipher', scope='*ssh',
                  operation=Operation.OMIT, value='NULL'),
    ]
    assert parse_line('cipher =') == [
        Directive(prop_name='cipher', scope='*',
                  operation=Operation.RESET, value=None),
    ]
    assert parse_line('\t\t') == []


def test_parse_bad():
    with pytest.raises(MalformedLineError):
        parse_line('a = b = c')
    with pytest.raises(MalformedLineError):
        parse_line('test')
    with pytest.raises(MalformedLineError):
        parse_line('=4')
    with pytest.raises(MalformedLineError):
        parse_line('=')
