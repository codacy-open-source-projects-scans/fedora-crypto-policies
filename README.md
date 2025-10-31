This repository contains the crypto-policies data and scripts used in
Fedora.

# Purpose

The purpose is to unify the crypto policies used by different applications
and libraries. It should be possible to set consistent cryptographic defaults
across all applications in a Fedora system,
irrespective of the cryptographic library in use.

# Description

The basic idea was to have few predefined security policies, such as LEGACY,
DEFAULT and FUTURE, which are set system-wide by the administrator.
Then applications that have no special needs will follow these policies
by default. That way the management of the various crypto applications and
libraries used in a system simplifies significantly.

Since then the project has grown additional capabilities.
The administrator can now layer subpolicies on top of policies,
define their own policies and subpolicies
and configure back-ends differently.

The supported back-ends in Fedora are:
 * GnuTLS
 * OpenSSL
 * NSS
 * BIND
 * libkrb5
 * OpenSSH
 * Java via OpenJDK
 * libssh
 * Libreswan
 * Sequioa
 * RPM through Sequioa (configured separately)

The primary interface for using crypto-policies is
`update-crypto-policy --set POLICYNAME:SUBPOLICY1:SUBPOLICY2`.
For more documentation, please refer to
[man crypto-policies](crypto-policies.7.txt) and
[man update-crypto-policies](update-crypto-policies.8.txt).

# Generating the policies

The policies are described in a simple policy language at `policies/POLICYFILE.pol`,
and they operate on strings defined at the beginning of `python/cryptopolicies.py`.
Individual application configuration generators are present in `python/policygenerators`.

To generate the policies per application use the script `python/build-crypto-policies.py
policydir DESTDIR` or `make install`.

For testing purpose the generated policies per application with the current
config are placed in `tests/outputs` and `make check` will verify whether the
generated policies match the stored. To reset the outputs use `make
reset-outputs` and `make check` to regenerate them.

# Contributing

See [our contribution guide](CONTRIBUTING.md).
