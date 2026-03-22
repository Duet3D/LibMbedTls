/*
 * aes_hardware.cpp
 *
 * MBEDTLS_AES_ALT implementation for SAME70 and SAME5x.
 *
 * Replaces mbedTLS software aes.c with hardware ECB via aes_ecb_crypt()
 * from CoreN2G/src/AesEcb.cpp.  Only ECB and the internal single-block
 * encrypt/decrypt primitives are overridden here; CBC/CTR/CFB/OFB are
 * implemented in mbedTLS library code on top of mbedtls_aes_crypt_ecb().
 */

#include "mbedtls/build_info.h"

#if defined(MBEDTLS_AES_C) && defined(MBEDTLS_AES_ALT)

#include "mbedtls/aes.h"
#include "mbedtls/platform_util.h"
#include "mbedtls/error.h"

#include <cstring>
#include <cstdint>

/* Hardware AES-ECB from CoreN2G/src/AesEcb.cpp */
extern "C" int aes_ecb_crypt(
    bool encrypt,
    const uint8_t *key, size_t key_len,
    const uint8_t input[16], uint8_t output[16]) noexcept;
extern "C" void mbedtls_aes_init(mbedtls_aes_context *ctx)
{
    memset(ctx, 0, sizeof(*ctx));
}

extern "C" void mbedtls_aes_free(mbedtls_aes_context *ctx)
{
    if (ctx == nullptr)
        return;
    mbedtls_platform_zeroize(ctx, sizeof(*ctx));
}

extern "C" int mbedtls_aes_setkey_enc(mbedtls_aes_context *ctx,
                                       const unsigned char *key,
                                       unsigned int keybits)
{
    if (ctx == nullptr || key == nullptr)
        return MBEDTLS_ERR_AES_INVALID_KEY_LENGTH;

    const size_t key_bytes = keybits / 8u;
    if (key_bytes != 16u && key_bytes != 24u && key_bytes != 32u)
        return MBEDTLS_ERR_AES_INVALID_KEY_LENGTH;

    memcpy(ctx->key, key, key_bytes);
    ctx->key_len = key_bytes;
    ctx->encrypt = 1;
    return 0;
}

extern "C" int mbedtls_aes_setkey_dec(mbedtls_aes_context *ctx,
                                       const unsigned char *key,
                                       unsigned int keybits)
{
    if (ctx == nullptr || key == nullptr)
        return MBEDTLS_ERR_AES_INVALID_KEY_LENGTH;

    const size_t key_bytes = keybits / 8u;
    if (key_bytes != 16u && key_bytes != 24u && key_bytes != 32u)
        return MBEDTLS_ERR_AES_INVALID_KEY_LENGTH;

    memcpy(ctx->key, key, key_bytes);
    ctx->key_len = key_bytes;
    ctx->encrypt = 0;
    return 0;
}

extern "C" int mbedtls_aes_crypt_ecb(mbedtls_aes_context *ctx,
                                      int mode,
                                      const unsigned char input[16],
                                      unsigned char output[16])
{
    if (ctx == nullptr || input == nullptr || output == nullptr)
        return MBEDTLS_ERR_AES_BAD_INPUT_DATA;

    if (ctx->key_len != 16u && ctx->key_len != 24u && ctx->key_len != 32u)
        return MBEDTLS_ERR_AES_INVALID_KEY_LENGTH;

    const bool enc = (mode == MBEDTLS_AES_ENCRYPT);
    const int ret = aes_ecb_crypt(enc, ctx->key, ctx->key_len, input, output);
    if (ret != 0)
        return MBEDTLS_ERR_PLATFORM_HW_ACCEL_FAILED;

    return 0;
}

extern "C" int mbedtls_internal_aes_encrypt(mbedtls_aes_context *ctx,
                                             const unsigned char input[16],
                                             unsigned char output[16])
{
    return mbedtls_aes_crypt_ecb(ctx, MBEDTLS_AES_ENCRYPT, input, output);
}

extern "C" int mbedtls_internal_aes_decrypt(mbedtls_aes_context *ctx,
                                             const unsigned char input[16],
                                             unsigned char output[16])
{
    return mbedtls_aes_crypt_ecb(ctx, MBEDTLS_AES_DECRYPT, input, output);
}

#endif /* MBEDTLS_AES_C && MBEDTLS_AES_ALT */
