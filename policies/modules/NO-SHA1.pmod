# This is an example subpolicy dropping the SHA1 hash and signature support

hash = -SHA1
sign = -*-SHA1
sha1_in_certs = 0

# https://fedoraproject.org/wiki/Changes/OpenSSLDistrustSHA1SigVer
__openssl_block_sha1_signatures = 1
