#http://www.yassl.com/yaSSL/Docs-cyassl-manual-2-building-cyassl.html
#http://yassl.com/yaSSL/Docs-cyassl-manual-4-features.html
#https://github.com/wolfSSL/wolfssl.git
#CYASSL_CFLAGS=-DOLD_HELLO_ALLOWED

CYASSL_BUILD_OPTS="--enable-static --enable-sniffer"

CYASSL_BUILD_OPTS="$CYASSL_BUILD_OPTS --enable-hugecache --enable-fastmath"
CYASSL_BUILD_OPTS="$CYASSL_BUILD_OPTS --enable-singlethreaded" 
#CYASSL_BUILD_OPTS="$CYASSL_BUILD_OPTS --enable-gcc-hardening"
#CYASSL_BUILD_OPTS="$CYASSL_BUILD_OPTS --enable-fortress  --enable-chacha --enable-fips"
CYASSL_BUILD_OPTS="$CYASSL_BUILD_OPTS --enable-errorstrings --enable-extended-master --enable-jobserver=no --disable-examples"
#CYASSL_BUILD_OPTS="$CYASSL_BUILD_OPTS --enable-sep --disable-shared --enable-ocsp --enable-bump --enable-atomicuser --enable-sessioncerts"

#CYASSL_BUILD_OPTS="$CYASSL_BUILD_OPTS --enable-renegotiation-indication --with-libz" 
CYASSL_BUILD_OPTS="$CYASSL_BUILD_OPTS --enable-secure-renegotiation"
CYASSL_BUILD_OPTS="$CYASSL_BUILD_OPTS --enable-sni --enable-tlsx"
#CYASSL_BUILD_OPTS="$CYASSL_BUILD_OPTS  --with-ntru --enable-qsh"

CYASSL_BUILD_OPTS="$CYASSL_BUILD_OPTS --enable-oldtls --enable-dtls"
CYASSL_BUILD_OPTS="$CYASSL_BUILD_OPTS --enable-tls13 --enable-tlsv10"
#CYASSL_BUILD_OPTS="$CYASSL_BUILD_OPTS --enable-leanpsk --enable-leantls"
CYASSL_BUILD_OPTS="$CYASSL_BUILD_OPTS --enable-cmac --enable-truncatedhmac"

## HASH: MD2, MD4, MD5, SHA-1, SHA-2 (SHA-256, SHA-384, SHA-512), BLAKE2b, RIPEMD-160
CYASSL_BUILD_OPTS="$CYASSL_BUILD_OPTS --enable-md5 --enable-sha --enable-sha512"
CYASSL_BUILD_OPTS="$CYASSL_BUILD_OPTS --enable-md2 --enable-md4" # not secure not used in cipher suite
CYASSL_BUILD_OPTS="$CYASSL_BUILD_OPTS --enable-psk --enable-ripemd --enable-blake2"

## CYPHER FOR DATA ENCRYPTION: AES (CBC, CTR, GCM, CCM-8), Camellia, DES, 3DES, ARC4, RABBIT, HC-128
CYASSL_BUILD_OPTS="$CYASSL_BUILD_OPTS --enable-aes --enable-aesgcm --enable-aesni --enable-aesccm"

CYASSL_BUILD_OPTS="$CYASSL_BUILD_OPTS --enable-ecc"
CYASSL_BUILD_OPTS="$CYASSL_BUILD_OPTS --enable-fpecc --enable-supportedcurves"
CYASSL_BUILD_OPTS="$CYASSL_BUILD_OPTS --enable-eccencrypt"
CYASSL_BUILD_OPTS="$CYASSL_BUILD_OPTS --enable-curve25519 --enable-ed25519"

CYASSL_BUILD_OPTS="$CYASSL_BUILD_OPTS --enable-camellia --enable-des3 --enable-nullcipher  --enable-arc4"
CYASSL_BUILD_OPTS="$CYASSL_BUILD_OPTS --enable-dsa --enable-hc128 --enable-rabbit --enable-xts"

## PUBLIC KEY EXCHANGE ALGO: RSA, DSS, DH, EDH, NTRU
CYASSL_BUILD_OPTS="$CYASSL_BUILD_OPTS --enable-rsa --enable-dh"
#CYASSL_BUILD_OPTS="$CYASSL_BUILD_OPTS --enable-ntru"

## Password-based Key Derivation: HMAC, PBKDF2, PKCS #5
CYASSL_BUILD_OPTS="$CYASSL_BUILD_OPTS --enable-hkdf"
CYASSL_BUILD_OPTS="$CYASSL_BUILD_OPTS --enable-chacha"
CYASSL_BUILD_OPTS="$CYASSL_BUILD_OPTS --enable-poly1305"
CYASSL_BUILD_OPTS="$CYASSL_BUILD_OPTS --enable-hashdrbg"

#added in 3.6.8
CYASSL_BUILD_OPTS="$CYASSL_BUILD_OPTS --enable-idea --enable-stunnel --enable-sslv3 --enable-srp --enable-alpn --enable-anon"
#CYASSL_BUILD_OPTS="$CYASSL_BUILD_OPTS --enable-intelasm"

#CYASSL_BUILD_OPTS="$CYASSL_BUILD_OPTS --enable-fips"
#CYASSL_BUILD_OPTS="$CYASSL_BUILD_OPTS --enable-leanpsk" # not works-> configure: error: please disable dsa if disabling asn.

#CYASSL_BUILD_OPTS="$CYASSL_BUILD_OPTS --enable-pkcs7"

CYASSL_BUILD_DBG_OPTS="--enable-debug"
#* rsa * dh * dsa* md5 * sha * arc4 * null    (allow NULL ciphers) * oldtls  (only use TLS 1.2 * asn     (no certs or public keys allowed)

### OPTIMIZATION
#export CFLAGS="-mtune=intel"
#CYASSL_BUILD_OPTS="$CYASSL_BUILD_OPTS --with-tune=intel"
#CYASSL_BUILD_OPTS="$CYASSL_BUILD_OPTS --with-arch=ivybridge"

FLAGS="-ggdb -g -Wno-unused-parameter -DHAVE_SNI -DOLD_HELLO_ALLOWED -DSTARTTLS_ALLOWED"
#FLAGS="$FLAGS -DSNIFFER_LOCK_SERVER_LIST"

export C_EXTRA_FLAGS=$FLAGS
#export USER_C_EXTRA_FLAGS=$FLAGS

echo "FLAGS:"
echo "$CYASSL_BUILD_OPTS"

./configure $CYASSL_BUILD_OPTS
[ $? -eq 0 ] || exit 1
make
