/*
 * gcm_alt.h
 *
 * Hardware GCM context for MBEDTLS_GCM_ALT.
 * Used on SAME70 and SAME5x where the on-chip AES peripheral supports GCM.
 *
 * This ALT implementation delegates the final crypto operation to CoreN2G
 * AesGcm.cpp.  The streaming API (starts/update/finish) stores a zero-copy
 * pointer to the caller's input buffer; finish() passes it directly to the
 * hardware.  One-shot crypt_and_tag()/auth_decrypt() bypass the streaming
 * path entirely.
 */

#ifndef MBEDTLS_GCM_ALT_H
#define MBEDTLS_GCM_ALT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum sizes for staged record data */
#define MBEDTLS_GCM_ALT_MAX_KEY_BYTES   32u
#define MBEDTLS_GCM_ALT_MAX_IV_BYTES    12u
#define MBEDTLS_GCM_ALT_MAX_AAD_BYTES   32u

typedef struct mbedtls_gcm_context
{
    unsigned char   key[MBEDTLS_GCM_ALT_MAX_KEY_BYTES];
    size_t          key_len;

    unsigned char   iv[MBEDTLS_GCM_ALT_MAX_IV_BYTES];
    size_t          iv_len;
    int             mode;

    unsigned char   aad[MBEDTLS_GCM_ALT_MAX_AAD_BYTES];
    size_t          aad_len;

    /* Zero-copy streaming: pointers set by update(), used by finish().
     * Only one update() call is supported per starts/finish cycle. */
    const unsigned char *input;
    size_t              data_len;
    unsigned char      *output;
} mbedtls_gcm_context;

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_GCM_ALT_H */
