/*
 * aes_gcm_hardware.cpp
 *
 * Hardware GCM implementation for MBEDTLS_GCM_ALT.
 * Delegates to the CoreN2G AesGcm driver (aes_gcm_encrypt / aes_gcm_decrypt)
 * which uses the on-chip AES peripheral in GCM mode on SAME70 and SAME5x.
 *
 * The streaming API (starts / update_ad / update / finish) stores a
 * zero-copy pointer to the caller's buffer and dispatches to the hardware
 * on finish().  Only one update() call is supported per starts/finish cycle.
 * This matches how mbedTLS 3.x TLS 1.2 drives GCM: the record layer calls
 * crypt_and_tag / auth_decrypt which bypass the streaming path entirely.
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

static inline int map_gcm_hw_ret(int ret)
{
    if (ret <= -100)
        return ret;
    if (ret == 0)
        return 0;
    if (ret == -2)
        return MBEDTLS_ERR_GCM_AUTH_FAILED;
    return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;
}

/* Single-owner guard: only one streaming context (starts/update/finish)
 * may be active at a time because they all share the AES peripheral.
 * One-shot crypt_and_tag / auth_decrypt do not touch this. */
static mbedtls_gcm_context *gcm_streaming_owner = nullptr;

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

    if (gcm_streaming_owner != nullptr && gcm_streaming_owner != ctx)
        return MBEDTLS_ERR_GCM_BAD_INPUT;

    gcm_streaming_owner = ctx;

    ctx->mode     = mode;
    ctx->iv_len   = iv_len;
    ctx->aad_len  = 0;
    ctx->data_len = 0;
    ctx->input    = nullptr;
    ctx->output   = nullptr;
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

    /* Only one update() call per starts/finish cycle (zero-copy). */
    if (ctx->data_len != 0)
        return MBEDTLS_ERR_GCM_BAD_INPUT;

    if (gcm_streaming_owner != ctx)
        return MBEDTLS_ERR_GCM_BAD_INPUT;

    /* Remember pointers; finish() passes them straight to hardware */
    ctx->input    = input;
    ctx->data_len = input_length;
    ctx->output   = output;

    /* No output produced yet — finish() does the hardware operation */
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

    if (gcm_streaming_owner != ctx)
        return MBEDTLS_ERR_GCM_BAD_INPUT;

    /* mbedtls_gcm_crypt_and_tag passes the output buffer to update() and
     * NULL to finish(). Retrieve the pointer stored during update(). */
    unsigned char *out = (output != nullptr) ? output : ctx->output;

    /* output may be NULL if no data was passed to update() */
    const size_t data_len = ctx->data_len;
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
            ctx->input, data_len,
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
            ctx->input, data_len,
            out,
            tag,      tag_len);
    }

    const int mappedRet = map_gcm_hw_ret(ret);

    aes_ecb_invalidate_cache();

    gcm_streaming_owner = nullptr;

    if (output_length != nullptr)
        *output_length = (ret == 0) ? data_len : 0u;

    return mappedRet;
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

    const int mappedRet = map_gcm_hw_ret(ret);

    aes_ecb_invalidate_cache();

    return mappedRet;
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

    uint8_t calc_tag[16] = {0};
    int ret = aes_gcm_decrypt_and_tag(ctx->key, ctx->key_len,
                                      iv, iv_len,
                                      add, add_len,
                                      input, length,
                                      output,
                                      calc_tag, tag_len);

    if (ret == 0) {
        uint8_t diff = 0;
        for (size_t i = 0; i < tag_len; i++) {
            diff |= calc_tag[i] ^ tag[i];
        }
        if (diff != 0) {
            ret = -2;
        }
    }

    const int mappedRet = map_gcm_hw_ret(ret);

    aes_ecb_invalidate_cache();

    return mappedRet;
}

extern "C" void mbedtls_gcm_free(mbedtls_gcm_context *ctx)
{
    if (ctx == nullptr)
        return;
    if (gcm_streaming_owner == ctx)
        gcm_streaming_owner = nullptr;
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
