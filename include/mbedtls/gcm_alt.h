/*
 * gcm_alt.h
 *
 * Hardware GCM context for MBEDTLS_GCM_ALT.
 * Used on SAME70 and SAME5x where the on-chip AES peripheral supports GCM.
 *
 * This ALT implementation delegates the final crypto operation to CoreN2G
 * AesGcm.cpp and uses a single shared staging buffer in the driver for the
 * mbedTLS starts/update/finish API.
 *
 * Important runtime constraint:
 * - Only one mbedtls_gcm_context can own the shared staging buffer at a time.
 * - starts()/update()/finish() for a second active context are rejected with
 *   MBEDTLS_ERR_GCM_BAD_INPUT until the current owner completes or is freed.
 * - One-shot crypt_and_tag()/auth_decrypt() do not use the shared buffer.
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

#if defined(MBEDTLS_SSL_IN_CONTENT_LEN)
#define MBEDTLS_GCM_ALT_MAX_DATA_BYTES  ((size_t)MBEDTLS_SSL_IN_CONTENT_LEN)
#else
#define MBEDTLS_GCM_ALT_MAX_DATA_BYTES  16384u
#endif

typedef struct mbedtls_gcm_context
{
    unsigned char   key[MBEDTLS_GCM_ALT_MAX_KEY_BYTES];
    size_t          key_len;

    unsigned char   iv[MBEDTLS_GCM_ALT_MAX_IV_BYTES];
    size_t          iv_len;
    int             mode;

    unsigned char   aad[MBEDTLS_GCM_ALT_MAX_AAD_BYTES];
    size_t          aad_len;

    /* Number of bytes currently staged in the driver's single shared
     * global payload buffer (not in this context struct).
     * Valid only while this context owns the shared buffer. */
    size_t          buf_len;

    unsigned char  *output;
} mbedtls_gcm_context;

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_GCM_ALT_H */
