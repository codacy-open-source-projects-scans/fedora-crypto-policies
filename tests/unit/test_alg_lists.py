# SPDX-License-Identifier: LGPL-2.1-or-later

# Copyright (c) 2021 Red Hat, Inc.

import pytest

from python.cryptopolicies.alg_lists import (
    glob, ALL,
    min_tls_version, min_dtls_version, max_tls_version, max_dtls_version,
)
from python.cryptopolicies.validation.alg_lists import (
    AlgorithmClassUnknownError, AlgorithmEmptyMatchError,
)


def test_glob_alg_sanity():
    assert glob('SEED-CBC', 'cipher') == ['SEED-CBC']
    assert glob('*EED*', 'cipher') == ['SEED-CBC']
    assert glob('*', 'cipher') == list(ALL['cipher'])


def test_glob_alg_globbing():
    gs = glob('GOST*', 'cipher')
    assert gs
    assert all(g.startswith('GOST') for g in gs)


def test_glob_alg_algorithm_empty():
    with pytest.raises(AlgorithmEmptyMatchError):
        glob('NONEX-*', 'cipher')


def test_glob_alg_algorithm_class_unknown():
    with pytest.raises(AlgorithmClassUnknownError):
        glob('*', 'nonex')


def test_min_versions():
    assert min_tls_version(['TLS1.2', 'SSL3.0', 'TLS1.3']) == 'SSL3.0'
    assert min_tls_version(['TLS1.2']) == 'TLS1.2'
    assert min_tls_version(['nonex']) is None
    assert min_tls_version([]) is None
    assert min_dtls_version(['DTLS1.2', 'DTLS1.0']) == 'DTLS1.0'
    assert min_dtls_version(['DTLS1.2']) == 'DTLS1.2'
    assert min_dtls_version(['nonex']) is None
    assert min_dtls_version([]) is None


def test_max_versions():
    assert max_tls_version(['TLS1.2', 'SSL3.0', 'TLS1.3']) == 'TLS1.3'
    assert max_tls_version(['TLS1.2']) == 'TLS1.2'
    assert max_tls_version(['nonex']) is None
    assert max_tls_version([]) is None
    assert max_dtls_version(['DTLS1.2', 'DTLS1.0']) == 'DTLS1.2'
    assert max_dtls_version(['DTLS1.2']) == 'DTLS1.2'
    assert max_dtls_version(['nonex']) is None
    assert max_dtls_version([]) is None
