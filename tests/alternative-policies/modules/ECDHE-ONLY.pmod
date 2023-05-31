# This is an example of a subpolicy
# enforcing ECDHE and ECDHE with PSK key exchanges

key_exchange = ECDHE ECDHE-PSK
group = -FFDHE-1536 -FFDHE-2048 -FFDHE-3072 -FFDHE-4096 -FFDHE-6144 \
        -FFDHE-8192 -FFDHE-1024
