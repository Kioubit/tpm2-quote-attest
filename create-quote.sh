#!/usr/bin/env sh
set -euox

mkdir data

#ECDSA with transient objects
tpm2_createek -c ek.handle -G ecc -u ek.pub
tpm2_createak -C ek.handle -G ecc -g sha256 -s ecdsa --ak-context "ak.ctx" --public "ak_public.pem" --format "pem"
tpm2_quote --key-context ak.ctx --pcr-list sha256:1,2,3,4,5,6,7,8,9 --qualification quote.nonce --message "quote.out" --signature "quote.sig" --pcr "quote.pcr" --pcrs_format=values --format=plain

#RSA with transient objects
#tpm2_createek -c ek.handle -G rsa -u ek_rsa.pub
#tpm2_createak -C ek.handle -G rsa -g sha256 -s rsassa --ak-context "ak.ctx" --public "ak_public.pem" --format "pem"
#tpm2_quote --key-context ak.ctx --pcr-list sha256:1,2,3,4,5,6,7,8,9 --qualification quote.nonce --message "quote.out" --signature "quote.sig" --pcr "quote.pcr" --pcrs_format=values --format=plain

# Persistent objects
#tpm2_createek -G rsa -c 0x810XXXXX -u ek_rsa.pub
#tpm2_createak --ek-context 0x810XXXXX -G rsa -g sha256 -s rsassa --ak-context "ak.ctx" --public "ak_public.pem" --format "pem"
#tpm2_evictcontrol -C o -c ak.ctx 0x8101000D
#tpm2_quote --key-context ak.ctx --pcr-list sha256:1,2,3,4,5,6,7,8,9 --qualification quote.nonce --message "quote.out" --signature "quote.sig" --pcr "quote.pcr" --pcrs_format=values --format=plain

# View persistent objects
# tpm2_getcap handles-persistent

# Delete persistent object
# tpm2_evictcontrol tpm2_evictcontrol -C o -c 0x81010002