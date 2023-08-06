# SPDX-License-Identifier: LGPL-2.1-or-later

# Copyright (c) 2021 Red Hat, Inc.

import pytest

from python.cryptopolicies.cryptopolicies import Operation, parse_rhs

from python.cryptopolicies.validation.alg_lists import (
    AlgorithmClassUnknownError, AlgorithmEmptyMatchError,
)
from python.cryptopolicies.validation.rules import (
    MixedDifferentialNonDifferentialError,
    IntPropertyNonIntValueError,
    NonIntPropertyIntValueError,
    BadEnumValueError,
)


def test_parse_rhs():
    assert parse_rhs('+NULL', 'cipher') == [(Operation.PREPEND, 'NULL')]
    assert parse_rhs('-NULL', 'cipher') == [(Operation.OMIT, 'NULL')]
    assert parse_rhs('IDEA-CBC NULL', 'cipher') == [
        (Operation.RESET, None),
        (Operation.APPEND, 'IDEA-CBC'),
        (Operation.APPEND, 'NULL')
    ]
    with pytest.raises(AlgorithmEmptyMatchError):
        parse_rhs('NULL NONEX', 'cipher')
    with pytest.raises(AlgorithmEmptyMatchError):
        parse_rhs('NULL NONEX-*', 'cipher')
    with pytest.raises(AlgorithmClassUnknownError):
        parse_rhs('NULL', 'nonex_algo_class')
    with pytest.raises(MixedDifferentialNonDifferentialError):
        parse_rhs('+IDEA-CBC NULL', 'cipher')

    with pytest.raises(IntPropertyNonIntValueError):
        parse_rhs('something', 'sha1_in_certs')
    with pytest.raises(NonIntPropertyIntValueError):
        parse_rhs('0', 'cipher')
    with pytest.raises(AlgorithmClassUnknownError):
        parse_rhs('0', 'nonex_algo_class')

    assert parse_rhs('RELAX', '__ems') == [(Operation.SET_ENUM, 'RELAX')]
    with pytest.raises(NonIntPropertyIntValueError):
        parse_rhs('0', '__ems')
    with pytest.raises(BadEnumValueError):
        parse_rhs('INVALID', '__ems')
