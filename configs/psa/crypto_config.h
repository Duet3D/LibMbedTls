/**
 * Minimal PSA crypto configuration for RepRapFirmware TLS 1.3 targets.
 *
 * This file overrides include/psa/crypto_config.h because `configs` appears
 * before `include` in the LibMbedTls include search path.
 */

#ifndef PSA_CRYPTO_CONFIG_H
#define PSA_CRYPTO_CONFIG_H

/* TLS 1.3 core key schedule + transcript hashes */
#define PSA_WANT_ALG_HKDF_EXTRACT               1
#define PSA_WANT_ALG_HKDF_EXPAND                1
#define PSA_WANT_ALG_SHA_256                    1
#if defined(MBEDTLS_SHA384_C)
#define PSA_WANT_ALG_SHA_384                    1
#endif

/* ECDHE + ECDSA authentication */
#define PSA_WANT_ALG_ECDH                       1
#define PSA_WANT_ALG_ECDSA                      1
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_BASIC      1
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_IMPORT   1
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_EXPORT   1
#define PSA_WANT_KEY_TYPE_ECC_KEY_PAIR_GENERATE 1
#define PSA_WANT_KEY_TYPE_ECC_PUBLIC_KEY        1
#define PSA_WANT_ECC_SECP_R1_256                1
#if defined(MBEDTLS_ECP_DP_CURVE25519_ENABLED)
#define PSA_WANT_ECC_MONTGOMERY_255             1
#endif
#if defined(MBEDTLS_ECP_DP_SECP384R1_ENABLED)
#define PSA_WANT_ECC_SECP_R1_384                1
#endif

/* AEAD for TLS 1.3 ciphersuites */
#define PSA_WANT_ALG_GCM                        1
#define PSA_WANT_KEY_TYPE_AES                   1

/* Random generation for ephemeral secrets and nonces */
#define PSA_WANT_ALG_CTR_DRBG                   1
#define PSA_WANT_ALG_HMAC                       1

#endif /* PSA_CRYPTO_CONFIG_H */
