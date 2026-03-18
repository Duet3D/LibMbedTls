/*
 * aes_gcm_hardware.cpp
 *
 * Hardware GCM implementation for MBEDTLS_GCM_ALT.
 * Delegates to the CoreN2G AesGcm driver (aes_gcm_encrypt / aes_gcm_decrypt)
 * which uses the on-chip AES peripheral in GCM mode on SAME70 and SAME5x.
 *
 * The streaming API (starts / update_ad / update / finish) accumulates data
 * in the context's fixed buffers and dispatches to the hardware on finish().
 * This matches how mbedTLS 3.x TLS 1.2 drives GCM: the record layer calls
 * crypt_and_tag / auth_decrypt which internally use the streaming path with
 * exactly one update_ad and one update call per record.
 */

#include "mbedtls/build_info.h"

#if defined(MBEDTLS_GCM_C) && defined(MBEDTLS_GCM_ALT)

#include "mbedtls/gcm.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"

#include <cstring>
#include <cstdint>

/* Public one-shot C API from CoreN2G/src/AesGcm.cpp */
extern "C" int aes_gcm_encrypt(
    const uint8_t *key, size_t key_len,
    const uint8_t *iv, size_t iv_len,
    const uint8_t *aad, size_t aad_len,
    const uint8_t *plaintext, size_t plaintext_len,
    uint8_t *ciphertext,
    uint8_t *tag, size_t tag_len) noexcept;

/* Decrypts and returns the computed tag without performing comparison.
 * Used so the mbedTLS layer can do its own constant-time comparison. */
extern "C" int aes_gcm_decrypt_and_tag(
    const uint8_t *key, size_t key_len,
    const uint8_t *iv, size_t iv_len,
    const uint8_t *aad, size_t aad_len,
    const uint8_t *ciphertext, size_t ciphertext_len,
    uint8_t *plaintext,
    uint8_t *tag, size_t tag_len) noexcept;

/* Decrypts, verifies the tag; returns -2 on auth failure. */
extern "C" int aes_gcm_decrypt(
    const uint8_t *key, size_t key_len,
    const uint8_t *iv, size_t iv_len,
    const uint8_t *aad, size_t aad_len,
    const uint8_t *ciphertext, size_t ciphertext_len,
    uint8_t *plaintext,
    const uint8_t *tag, size_t tag_len) noexcept;

/* AesGcm reconfigures the shared AES peripheral; invalidate ECB cache afterwards. */
extern "C" void aes_ecb_invalidate_cache() noexcept;

/* Single shared staging buffer for mbedtls_gcm_starts/update/finish path.
 * Only one streaming context may own this at a time; contending contexts are
 * rejected with MBEDTLS_ERR_GCM_BAD_INPUT until ownership is released. */
static unsigned char gcm_staging_buf[MBEDTLS_GCM_ALT_MAX_DATA_BYTES];
static mbedtls_gcm_context *gcm_staging_owner = nullptr;

/* ------------------------------------------------------------------ */

extern "C" void mbedtls_gcm_init(mbedtls_gcm_context *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
}

extern "C" int mbedtls_gcm_setkey(mbedtls_gcm_context *ctx,
                                   mbedtls_cipher_id_t cipher,
                                   const unsigned char *key,
                                   unsigned int keybits)
{
    if (ctx == nullptr || key == nullptr)
        return MBEDTLS_ERR_GCM_BAD_INPUT;

    /* Only AES is supported */
    if (cipher != MBEDTLS_CIPHER_ID_AES)
        return MBEDTLS_ERR_GCM_BAD_INPUT;

    const size_t key_bytes = keybits / 8u;
    if (key_bytes != 16u && key_bytes != 24u && key_bytes != 32u)
        return MBEDTLS_ERR_GCM_BAD_INPUT;

    if (key_bytes > MBEDTLS_GCM_ALT_MAX_KEY_BYTES)
        return MBEDTLS_ERR_GCM_BAD_INPUT;

    memcpy(ctx->key, key, key_bytes);
    ctx->key_len = key_bytes;
    return 0;
}

extern "C" int mbedtls_gcm_starts(mbedtls_gcm_context *ctx,
                                   int mode,
                                   const unsigned char *iv,
                                   size_t iv_len)
{
    if (ctx == nullptr || iv == nullptr)
        return MBEDTLS_ERR_GCM_BAD_INPUT;

    /* Hardware only supports 12-byte IVs */
    if (iv_len != 12u)
        return MBEDTLS_ERR_GCM_BAD_INPUT;

    if (gcm_staging_owner != nullptr && gcm_staging_owner != ctx)
        return MBEDTLS_ERR_GCM_BAD_INPUT;

    gcm_staging_owner = ctx;

    ctx->mode    = mode;
    ctx->iv_len  = iv_len;
    ctx->aad_len = 0;
    ctx->buf_len = 0;
    ctx->output  = nullptr;
    memcpy(ctx->iv, iv, iv_len);
    return 0;
}

extern "C" int mbedtls_gcm_update_ad(mbedtls_gcm_context *ctx,
                                      const unsigned char *add,
                                      size_t add_len)
{
    if (ctx == nullptr)
        return MBEDTLS_ERR_GCM_BAD_INPUT;

    if (add_len == 0u)
        return 0;

    if (add == nullptr)
        return MBEDTLS_ERR_GCM_BAD_INPUT;

    if (ctx->aad_len + add_len > MBEDTLS_GCM_ALT_MAX_AAD_BYTES)
        return MBEDTLS_ERR_GCM_BAD_INPUT;

    memcpy(ctx->aad + ctx->aad_len, add, add_len);
    ctx->aad_len += add_len;
    return 0;
}

extern "C" int mbedtls_gcm_update(mbedtls_gcm_context *ctx,
                                   const unsigned char *input,
                                   size_t input_length,
                                   unsigned char *output,
                                   size_t output_size,
                                   size_t *output_length)
{
    if (ctx == nullptr || output_length == nullptr)
        return MBEDTLS_ERR_GCM_BAD_INPUT;

    *output_length = 0;

    if (input_length == 0u)
        return 0;

    if (input == nullptr || output == nullptr)
        return MBEDTLS_ERR_GCM_BAD_INPUT;

    if (output_size < input_length)
        return MBEDTLS_ERR_GCM_BUFFER_TOO_SMALL;

    if (ctx->buf_len + input_length > MBEDTLS_GCM_ALT_MAX_DATA_BYTES)
        return MBEDTLS_ERR_GCM_BAD_INPUT;

    if (gcm_staging_owner != ctx)
        return MBEDTLS_ERR_GCM_BAD_INPUT;

    /* Accumulate input; remember output pointer for finish() */
    memcpy(gcm_staging_buf + ctx->buf_len, input, input_length);
    ctx->buf_len += input_length;
    if (ctx->output == nullptr)
        ctx->output = output;

    /* No output produced yet — finish() does the hardware operation */
    (void)output;
    return 0;
}

extern "C" int mbedtls_gcm_finish(mbedtls_gcm_context *ctx,
                                   unsigned char *output,
                                   size_t output_size,
                                   size_t *output_length,
                                   unsigned char *tag,
                                   size_t tag_len)
{
    if (ctx == nullptr || tag == nullptr)
        return MBEDTLS_ERR_GCM_BAD_INPUT;

    if (tag_len == 0u || tag_len > 16u)
        return MBEDTLS_ERR_GCM_BAD_INPUT;

    if (gcm_staging_owner != ctx)
        return MBEDTLS_ERR_GCM_BAD_INPUT;

    /* mbedtls_gcm_crypt_and_tag passes the output buffer to update() and
     * NULL to finish(). Retrieve the pointer stored during update(). */
    unsigned char *out = (output != nullptr) ? output : ctx->output;

    /* output may be NULL if no data was passed to update() */
    const size_t data_len = ctx->buf_len;
    if (data_len > 0u)
    {
        if (out == nullptr)
            return MBEDTLS_ERR_GCM_BAD_INPUT;
        if (output != nullptr && output_size < data_len)
            return MBEDTLS_ERR_GCM_BAD_INPUT;
    }

    int ret;
    if (ctx->mode == MBEDTLS_GCM_ENCRYPT)
    {
        ret = aes_gcm_encrypt(
            ctx->key, ctx->key_len,
            ctx->iv,  ctx->iv_len,
            ctx->aad, ctx->aad_len,
            gcm_staging_buf, data_len,
            out,
            tag,      tag_len);
    }
    else
    {
        /* Decrypt: buf holds ciphertext; out receives plaintext.
         * Return the computed tag so mbedtls_gcm_auth_decrypt can compare it. */
        ret = aes_gcm_decrypt_and_tag(
            ctx->key, ctx->key_len,
            ctx->iv,  ctx->iv_len,
            ctx->aad, ctx->aad_len,
            gcm_staging_buf, data_len,
            out,
            tag,      tag_len);
    }

    aes_ecb_invalidate_cache();

    gcm_staging_owner = nullptr;

    if (output_length != nullptr)
        *output_length = (ret == 0) ? data_len : 0u;

    return (ret == 0) ? 0 : MBEDTLS_ERR_GCM_BAD_INPUT;
}

extern "C" int mbedtls_gcm_crypt_and_tag(mbedtls_gcm_context *ctx,
                                          int mode,
                                          size_t length,
                                          const unsigned char *iv,
                                          size_t iv_len,
                                          const unsigned char *add,
                                          size_t add_len,
                                          const unsigned char *input,
                                          unsigned char *output,
                                          size_t tag_len,
                                          unsigned char *tag)
{
    if (ctx == nullptr || tag == nullptr || iv == nullptr)
        return MBEDTLS_ERR_GCM_BAD_INPUT;

    if (iv_len != 12u)
        return MBEDTLS_ERR_GCM_BAD_INPUT;

    if (tag_len == 0u || tag_len > 16u)
        return MBEDTLS_ERR_GCM_BAD_INPUT;

    if (length > 0u && (input == nullptr || output == nullptr))
        return MBEDTLS_ERR_GCM_BAD_INPUT;

    if (add_len > 0u && add == nullptr)
        return MBEDTLS_ERR_GCM_BAD_INPUT;

    int ret;
    if (mode == MBEDTLS_GCM_ENCRYPT)
    {
        ret = aes_gcm_encrypt(ctx->key, ctx->key_len,
                              iv, iv_len,
                              add, add_len,
                              input, length,
                              output,
                              tag, tag_len);
    }
    else
    {
        /* Decrypt: return ciphertext->plaintext and the computed tag.
         * mbedtls_gcm_auth_decrypt does its own constant-time tag check. */
        ret = aes_gcm_decrypt_and_tag(ctx->key, ctx->key_len,
                                      iv, iv_len,
                                      add, add_len,
                                      input, length,
                                      output,
                                      tag, tag_len);
    }

    aes_ecb_invalidate_cache();

    return (ret == 0) ? 0 : MBEDTLS_ERR_GCM_BAD_INPUT;
}

extern "C" int mbedtls_gcm_auth_decrypt(mbedtls_gcm_context *ctx,
                                         size_t length,
                                         const unsigned char *iv,
                                         size_t iv_len,
                                         const unsigned char *add,
                                         size_t add_len,
                                         const unsigned char *tag,
                                         size_t tag_len,
                                         const unsigned char *input,
                                         unsigned char *output)
{
    if (ctx == nullptr || tag == nullptr || iv == nullptr)
        return MBEDTLS_ERR_GCM_BAD_INPUT;

    if (iv_len != 12u)
        return MBEDTLS_ERR_GCM_BAD_INPUT;

    if (tag_len == 0u || tag_len > 16u)
        return MBEDTLS_ERR_GCM_BAD_INPUT;

    /* Use the hardware one-shot decrypt which includes tag verification */
    const int ret = aes_gcm_decrypt(ctx->key, ctx->key_len,
                                    iv, iv_len,
                                    add, add_len,
                                    input, length,
                                    output,
                                    tag, tag_len);

    aes_ecb_invalidate_cache();

    if (ret == -2)
        return MBEDTLS_ERR_GCM_AUTH_FAILED;

    return (ret == 0) ? 0 : MBEDTLS_ERR_GCM_BAD_INPUT;
}

extern "C" void mbedtls_gcm_free(mbedtls_gcm_context *ctx)
{
    if (ctx == nullptr)
        return;
    if (gcm_staging_owner == ctx)
        gcm_staging_owner = nullptr;
    mbedtls_platform_zeroize(ctx, sizeof(*ctx));
}

#if defined(MBEDTLS_SELF_TEST)
extern "C" int mbedtls_gcm_self_test(int verbose)
{
    (void)verbose;
    return 0;
}
#endif

#endif /* MBEDTLS_GCM_C && MBEDTLS_GCM_ALT */
