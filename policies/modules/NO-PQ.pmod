# A subpolicy that's meant to disable everything TEST-PQ enables.
# At the time of the introduction, FEDORA43:NO-PQ should be equal to FEDORA42,
# and so should a FEDORA42:TEST-PQ:NO-PQ.
# May disappear with the next update.

# %suppress_experimental_value_warnings=true

group = -*MLKEM*

sign = -*SPHINCS* -*FALCON* -*MLDSA*

key_exchange = -SNTRUP -KEM-ECDH

# %suppress_experimental_value_warnings=false
