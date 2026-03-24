/*
 * pukcc_hardware.cpp
 *
 * mbedTLS ALT hooks for SAME5x PUKCC hardware ECC acceleration.
 * Delegates to the CoreN2G pukcc driver (pukcc.c / pukcc.h).
 *
 * Provides:
 *   - MBEDTLS_ECP_MUL_ALT:     P-256 scalar multiplication
 *   - MBEDTLS_ECDSA_SIGN_ALT:  P-256 ECDSA signing
 *   - MBEDTLS_ECDSA_VERIFY_ALT: P-256 ECDSA verification
 */

#include "mbedtls/build_info.h"

#if defined(MBEDTLS_ECP_C) && defined(__SAME54P20A__)

#define MBEDTLS_ALLOW_PRIVATE_ACCESS

#include "mbedtls/ecp.h"
#include "mbedtls/bignum.h"
#include "mbedtls/platform_util.h"

#include <cstring>
#include <cstdint>

#include "pukcc/pukcc.h"

static bool hwInitDone = false;
static bool hwInitOk = false;

static constexpr size_t P256_BYTES = 32;

static bool ensureHwInit() noexcept
{
    if (!hwInitDone) {
        hwInitDone = true;
        hwInitOk = (ecc_p256_init() == 0);
    }
    return hwInitOk;
}

// =========================================================================
// MBEDTLS_ECP_MUL_ALT — P-256 scalar multiplication
// =========================================================================

#if defined(MBEDTLS_ECP_MUL_ALT)

extern "C"
int mbedtls_ecp_mul_alt(mbedtls_ecp_group *grp, mbedtls_ecp_point *R,
                         const mbedtls_mpi *m, const mbedtls_ecp_point *P)
{
    if (grp->id != MBEDTLS_ECP_DP_SECP256R1)
        return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;
    if (!ensureHwInit())
        return MBEDTLS_ERR_ECP_FEATURE_UNAVAILABLE;

    uint8_t k[P256_BYTES];
    if (mbedtls_mpi_write_binary(m, k, P256_BYTES) != 0)
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;

    uint8_t px_buf[P256_BYTES], py_buf[P256_BYTES];
    if (mbedtls_mpi_write_binary(&P->X, px_buf, P256_BYTES) != 0)
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    if (mbedtls_mpi_write_binary(&P->Y, py_buf, P256_BYTES) != 0)
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;

    uint8_t rx_buf[P256_BYTES], ry_buf[P256_BYTES];
    int ret = ecc_p256_mul(k, px_buf, py_buf, rx_buf, ry_buf);

    mbedtls_platform_zeroize(k, sizeof(k));

    if (ret != 0)
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;

    int err;
    if ((err = mbedtls_mpi_read_binary(&R->X, rx_buf, P256_BYTES)) != 0)
        return err;
    if ((err = mbedtls_mpi_read_binary(&R->Y, ry_buf, P256_BYTES)) != 0)
        return err;
    if ((err = mbedtls_mpi_lset(&R->Z, 1)) != 0)
        return err;

    return 0;
}

#endif /* MBEDTLS_ECP_MUL_ALT */

// =========================================================================
// MBEDTLS_ECDSA_SIGN_ALT — P-256 ECDSA signature generation
// =========================================================================

#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECDSA_SIGN_ALT)

#include "mbedtls/ecdsa.h"

/*
 * mbedtls_ecdsa_sign — replaces the software implementation when
 * MBEDTLS_ECDSA_SIGN_ALT is defined.
 *
 * For P-256: delegates to PUKCC ZpEcDsaGenerateFast.
 * For other curves: returns MBEDTLS_ERR_ECP_BAD_INPUT_DATA (no fallback
 * possible since ALT replaces the function entirely).
 */
extern "C"
int mbedtls_ecdsa_sign(mbedtls_ecp_group *grp, mbedtls_mpi *r, mbedtls_mpi *s,
                        const mbedtls_mpi *d, const unsigned char *buf, size_t blen,
                        int (*f_rng)(void *, unsigned char *, size_t), void *p_rng)
{
    if (grp->id != MBEDTLS_ECP_DP_SECP256R1 || blen > P256_BYTES)
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    if (!ensureHwInit())
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;

    /* Export private key d to 32-byte big-endian */
    uint8_t priv[P256_BYTES];
    if (mbedtls_mpi_write_binary(d, priv, P256_BYTES) != 0)
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;

    /* Prepare hash: left-pad to 32 bytes if shorter */
    uint8_t hash[P256_BYTES];
    memset(hash, 0, P256_BYTES);
    memcpy(hash + P256_BYTES - blen, buf, blen);

    /* Generate ephemeral nonce k in [1, n-1] */
    mbedtls_mpi k;
    mbedtls_mpi_init(&k);
    int ret = mbedtls_ecp_gen_privkey(grp, &k, f_rng, p_rng);
    if (ret != 0) {
        mbedtls_platform_zeroize(priv, sizeof(priv));
        mbedtls_mpi_free(&k);
        return ret;
    }

    uint8_t nonce[P256_BYTES];
    ret = mbedtls_mpi_write_binary(&k, nonce, P256_BYTES);
    mbedtls_mpi_free(&k);
    if (ret != 0) {
        mbedtls_platform_zeroize(priv, sizeof(priv));
        return ret;
    }

    /* Hardware ECDSA sign */
    uint8_t sig_r[P256_BYTES], sig_s[P256_BYTES];
    ret = ecc_p256_ecdsa_sign(hash, priv, nonce, sig_r, sig_s);

    /* Clear sensitive data from stack */
    mbedtls_platform_zeroize(priv, sizeof(priv));
    mbedtls_platform_zeroize(nonce, sizeof(nonce));

    if (ret != 0)
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;

    /* Import (r, s) into MPIs */
    int err;
    if ((err = mbedtls_mpi_read_binary(r, sig_r, P256_BYTES)) != 0)
        return err;
    if ((err = mbedtls_mpi_read_binary(s, sig_s, P256_BYTES)) != 0)
        return err;

    return 0;
}

#endif /* MBEDTLS_ECDSA_C && MBEDTLS_ECDSA_SIGN_ALT */

// =========================================================================
// MBEDTLS_ECDSA_VERIFY_ALT — P-256 ECDSA signature verification
// =========================================================================

#if defined(MBEDTLS_ECDSA_C) && defined(MBEDTLS_ECDSA_VERIFY_ALT)

#include "mbedtls/ecdsa.h"

/*
 * mbedtls_ecdsa_verify — replaces the software implementation when
 * MBEDTLS_ECDSA_VERIFY_ALT is defined.
 */
extern "C"
int mbedtls_ecdsa_verify(mbedtls_ecp_group *grp,
                          const unsigned char *buf, size_t blen,
                          const mbedtls_ecp_point *Q,
                          const mbedtls_mpi *r, const mbedtls_mpi *s)
{
    if (grp->id != MBEDTLS_ECP_DP_SECP256R1 || blen > P256_BYTES)
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    if (!ensureHwInit())
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;

    /* Prepare hash: left-pad to 32 bytes if shorter */
    uint8_t hash[P256_BYTES];
    memset(hash, 0, P256_BYTES);
    memcpy(hash + P256_BYTES - blen, buf, blen);

    /* Export public key Q */
    uint8_t pub_x[P256_BYTES], pub_y[P256_BYTES];
    if (mbedtls_mpi_write_binary(&Q->X, pub_x, P256_BYTES) != 0)
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    if (mbedtls_mpi_write_binary(&Q->Y, pub_y, P256_BYTES) != 0)
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;

    /* Export signature (r, s) */
    uint8_t sig_r[P256_BYTES], sig_s[P256_BYTES];
    if (mbedtls_mpi_write_binary(r, sig_r, P256_BYTES) != 0)
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;
    if (mbedtls_mpi_write_binary(s, sig_s, P256_BYTES) != 0)
        return MBEDTLS_ERR_ECP_BAD_INPUT_DATA;

    /* Hardware ECDSA verify */
    int ret = ecc_p256_ecdsa_verify(hash, pub_x, pub_y, sig_r, sig_s);

    if (ret != 0)
        return MBEDTLS_ERR_ECP_VERIFY_FAILED;

    return 0;
}

#endif /* MBEDTLS_ECDSA_C && MBEDTLS_ECDSA_VERIFY_ALT */

#endif /* MBEDTLS_ECP_C && __SAME54P20A__ */
