/*
 * gcm_alt.h
 *
 * Hardware GCM context for MBEDTLS_GCM_ALT.
 * Used on SAME70 and SAME5x where the on-chip AES peripheral supports GCM.
 *
 * The context stores the key and (for the streaming API) accumulates IV, AAD,
 * and ciphertext/plaintext until mbedtls_gcm_finish() is called, at which
 * point the one-shot hardware driver is invoked.
 *
 * TLS 1.2 AES-GCM record sizes are bounded (max ~16 KB), so the streaming
 * buffers use fixed sizes.  If hardware GCM is not available for the current
 * chip AES_GCM_NOT_AVAILABLE will be defined and the functions fall back to
 * returning an error — the software gcm.c must not be linked in that case.
 */

#ifndef MBEDTLS_GCM_ALT_H
#define MBEDTLS_GCM_ALT_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Maximum sizes matching TLS 1.2 record limits */
#define MBEDTLS_GCM_ALT_MAX_KEY_BYTES   32          /* AES-256 */
#define MBEDTLS_GCM_ALT_MAX_IV_BYTES    12          /* GCM standard nonce */
#define MBEDTLS_GCM_ALT_MAX_AAD_BYTES   32          /* TLS additional data is ~13 bytes */
#define MBEDTLS_GCM_ALT_MAX_DATA_BYTES  16384       /* TLS max record payload */

/**
 * \brief  Hardware GCM context.
 *
 * For crypt_and_tag / auth_decrypt the key is set once via setkey() and the
 * operation is driven entirely by the single crypt_and_tag() call.
 *
 * The streaming path (starts / update_ad / update / finish) accumulates data
 * into fixed buffers and executes the hardware on finish().
 */
typedef struct mbedtls_gcm_context
{
    /* Key material set by mbedtls_gcm_setkey() */
    unsigned char   key[MBEDTLS_GCM_ALT_MAX_KEY_BYTES];
    size_t          key_len;            /*!< key length in bytes */

    /* State set by mbedtls_gcm_starts() */
    unsigned char   iv[MBEDTLS_GCM_ALT_MAX_IV_BYTES];
    size_t          iv_len;
    int             mode;               /*!< MBEDTLS_GCM_ENCRYPT or MBEDTLS_GCM_DECRYPT */

    /* Accumulated AAD (update_ad) */
    unsigned char   aad[MBEDTLS_GCM_ALT_MAX_AAD_BYTES];
    size_t          aad_len;

    /* Input data accumulated during update() */
    unsigned char   buf[MBEDTLS_GCM_ALT_MAX_DATA_BYTES];
    size_t          buf_len;

    /* Output buffer pointer supplied by the first update() call.
     * The hardware writes the result here during finish(). */
    unsigned char  *output;
} mbedtls_gcm_context;

#ifdef __cplusplus
}
#endif

#endif /* MBEDTLS_GCM_ALT_H */
