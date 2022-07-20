#include <stddef.h>
#include <string.h>

#include "hal.h"

int randombytes(unsigned char *dst, size_t len);

int do_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);

int do_crypto_sign_signature(uint8_t *sig, size_t *siglen,
                          const uint8_t *m, size_t mlen,
                          const uint8_t *sk);

int do_crypto_sign(uint8_t *sm, size_t *smlen,
                const uint8_t *m, size_t mlen,
                const uint8_t *sk);

int do_crypto_sign_verify(const uint8_t *sig, size_t siglen,
                       const uint8_t *m, size_t mlen,
                       const uint8_t *pk);

int do_crypto_sign_open(uint8_t *m, size_t *mlen,
                     const uint8_t *sm, size_t smlen,
                     const uint8_t *pk);

int crypto_sign_keypair(uint8_t *pk, uint8_t *sk) {
    //hal_send_str("k");
    return do_crypto_sign_keypair(pk, sk);
}

//int crypto_sign_signature(uint8_t *sig, size_t *siglen,
//                          const uint8_t *m, size_t mlen,
//                          const uint8_t *sk) {
//	return crypto_sign_signa

int crypto_sign(uint8_t *sm, size_t *smlen,
                const uint8_t *m, size_t mlen,
                const uint8_t *sk) {
    //hal_send_str("s");
    return do_crypto_sign(sm, smlen, m, mlen, sk);
}

//int crypto_sign_verify(const uint8_t *sig, size_t siglen,
//                       const uint8_t *m, size_t mlen,
//                       const uint8_t *pk);

int crypto_sign_open(uint8_t *m, size_t *mlen,
                     const uint8_t *sm, size_t smlen,
                     const uint8_t *pk) {
    //hal_send_str("o");
    return do_crypto_sign_open(m, mlen, sm, smlen, pk);
}

