# Restrict FIPS policy for the Common Criteria OSPP profile.

# SSH (upper limit)
# Ciphers: aes256-ctr, aes256-cbc, aes256-gcm@openssh.com
# PubkeyAcceptedKeyTypes: rsa-sha2-256, rsa‑sha2‑512
# MACs: hmac-sha2-256, hmac-sha2-512, implicit for aes256-gcm@openssh.com
# KexAlgorithms: ecdh-sha2-nistp384, ecdh-sha2-nistp521, diffie-hellman-group16-sha512, diffie-hellman-group18-sha512

# TLS ciphers (suggested minimal set for openssl)
# * TLS_RSA_WITH_AES_128_CBC_SHA     - excluded by FIPS, uses RSA key exchange
# * TLS_RSA_WITH_AES_256_CBC_SHA     - excluded by FIPS, uses RSA key exchange
# * TLS_RSA_WITH_AES_128_CBC_SHA256  - excluded by FIPS, uses RSA key exchange
# * TLS_RSA_WITH_AES_256_CBC_SHA256  - excluded by FIPS, uses RSA key exchange
# * TLS_RSA_WITH_AES_128_GCM_SHA256  - excluded by FIPS, uses RSA key exchange
# * TLS_RSA_WITH_AES_256_GCM_SHA384  - excluded by FIPS, uses RSA key exchange
# * TLS_DHE_RSA_WITH_AES_128_CBC_SHA256  - disabled, AES 128
# * TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
# * TLS_DHE_RSA_WITH_AES_128_GCM_SHA256  - disabled, AES 128
# * TLS_DHE_RSA_WITH_AES_256_GCM_SHA384
# * TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256  - disabled, AES 128
# * TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256  - disabled, AES 128
# * TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA384  - disabled in openssl itself
# * TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
# * TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA256  - disabled, AES 128
# * TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256  - disabled, AES 128
# * TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA384  - disabled in openssl itself
# * TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
# Supported Groups Extension in ClientHello: secp256r1, secp384r1, secp521r1

mac = -HMAC-SHA1  # see above, both SSH and TLS ended up not using it

group = -X25519-MLKEM768 -P256-MLKEM768 -P384-MLKEM1024 -SECP256R1 -FFDHE-2048

hash = -SHA2-224 -SHA3-256 -SHA3-384 -SHA3-512 -SHA3-224

sign = -MLDSA44 -MLDSA65 -MLDSA87 \
    -ECDSA-SHA2-224 -ECDSA-SHA2-256 -RSA-PSS-SHA2-224 -RSA-SHA2-224

# a necessary change =(
cipher@!{SSH,TLS} = -AES-256-CTR -AES-128-CTR -AES-256-CCM -AES-128-CCM -AES-128-CBC -AES-128-GCM -AES-128-CFB

ssh_cipher = -AES-256-CCM -AES-128-CCM -AES-128-GCM -AES-128-CTR

tls_cipher = -AES-256-CCM -AES-128-CCM -AES-128-GCM -AES-128-CBC

key_exchange = -KEM-ECDH  # no KEM-ECDH, just to be sure

ssh_certs = 0
etm@SSH = DISABLE_ETM

protocol = -TLS1.3

min_dh_size = 3072
min_rsa_size = 3072

arbitrary_dh_groups = 0
