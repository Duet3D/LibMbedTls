/*
 * aes_alt.h
 *
 * Alternative AES context for MBEDTLS_AES_ALT.
 * Used on SAME70 and SAME5x where the on-chip AES peripheral provides
 * hardware-accelerated ECB block encryption via aes_ecb_crypt() (AesEcb.cpp).
 *
 * The context just stores the raw key; key expansion is done in hardware.
 */

#ifndef MBEDTLS_AES_ALT_H
#define MBEDTLS_AES_ALT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define MBEDTLS_AES_ALT_MAX_KEY_BYTES  32u

typedef struct mbedtls_aes_context
{
    unsigned char   key[MBEDTLS_AES_ALT_MAX_KEY_BYTES]; /*!< raw AES key       */
    size_t          key_len;                              /*!< key length, bytes */
    int             encrypt;                              /*!< 1=enc, 0=dec      */
} mbedtls_aes_context;

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_AES_ALT_H */
