# Adds GOST algorithms.
# This is an example subpolicy, the algorithm names might differ in reality.

mac = +*STREEBOG-* +*-OMAC +*-OMAC-ACPKM +GOST28147* +AEAD

group = +*GOST*

hash = +*STREEBOG* +*GOST*

sign = +*GOST*

cipher@TLS = +GOST28147-TC26Z-CNT +GOST28147-CPA-CFB +MAGMA-CTR-ACPKM +KUZNYECHIK-CTR-ACPKM

cipher@!TLS = +GOST28147-TC26Z-CNT +MAGMA-CTR-ACPKM +KUZNYECHIK-CTR-ACPKM +GOST28147-CPA-CFB +GOST28147-CPB-CFB +GOST28147-CPC-CFB +GOST28147-CPD-CFB +GOST28147-TC26Z-CFB

key_exchange = +*GOST*
