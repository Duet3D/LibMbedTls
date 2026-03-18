/**
 * Custom Mbed TLS configuration for RepRapFirmware — SAME5x (Duet 3 Mini 5+)
 *
 * Minimal TLS 1.2 server configuration for HTTPS support on embedded ARM targets.
 * Based on the Suite B profile (RFC 6460) — ECC only, no RSA.
 *
 * Target MCU: SAME54P20A (Cortex-M4, 256 KB RAM)
 * Has hardware AES with GCM support.
 *
 * mbedTLS 3.6 LTS
 *
 * Memory saving measures vs config-same70.h:
 *  - SSL_IN_CONTENT_LEN reduced to 2048 (MBEDTLS_SSL_RECORD_SIZE_LIMIT / RFC 8449
 *    ensures compliant browsers will not send records larger than this)
 *  - SSL_OUT_CONTENT_LEN reduced to 2048
 *  - Session cache limited to 2 entries
 */

#ifndef MBEDTLS_CONFIG_SAME5X_H
#define MBEDTLS_CONFIG_SAME5X_H

/* ============================================================
 * System support
 * ============================================================ */
#define MBEDTLS_HAVE_ASM

/* ============================================================
 * Platform — no POSIX, we use LwIP + FreeRTOS
 * ============================================================ */
#define MBEDTLS_PLATFORM_C

/* Route mbedTLS allocations through the lwIP heap (mem_malloc/mem_free)
   instead of the newlib system heap, to avoid blocking on mallocMutex. */
#define MBEDTLS_PLATFORM_MEMORY
#define MBEDTLS_PLATFORM_CALLOC_MACRO   mbedtls_lwip_calloc
#define MBEDTLS_PLATFORM_FREE_MACRO     mbedtls_lwip_free

/* Wrappers with stable size_t signature, defined in LwipEthernetInterface.cpp
   which has lwIP headers available. This avoids mem_size_t type conflicts
   between SAME54 (u16_t) and SAME70 (u32_t). */
#include <stddef.h>
#ifdef __cplusplus
extern "C" {
#endif
void *mbedtls_lwip_calloc(size_t count, size_t size);
void  mbedtls_lwip_free(void *ptr);
#ifdef __cplusplus
}
#endif

/* Redirect snprintf/vsnprintf to SafeSnprintf/SafeVsnprintf (RRFLibraries)
   to avoid pulling in newlib's snprintf which uses _malloc_r internally. */
#define MBEDTLS_PLATFORM_SNPRINTF_MACRO    mbedtls_platform_snprintf
#define MBEDTLS_PLATFORM_VSNPRINTF_MACRO   mbedtls_platform_vsnprintf

#include <stddef.h>
#include <stdarg.h>
#ifdef __cplusplus
extern "C" {
#endif
int mbedtls_platform_snprintf(char *s, size_t n, const char *format, ...);
int mbedtls_platform_vsnprintf(char *s, size_t n, const char *format, va_list args);
#ifdef __cplusplus
}
#endif

/* We provide hardware entropy via mbedtls_hardware_poll() using TRNG */
#define MBEDTLS_ENTROPY_HARDWARE_ALT

/* Disable platform entropy poll (no /dev/urandom on bare-metal) */
#define MBEDTLS_NO_PLATFORM_ENTROPY

/* ============================================================
 * TLS protocol configuration
 * ============================================================ */

/* Key exchange: ECDHE-ECDSA only (no RSA, no PSK) */
#define MBEDTLS_KEY_EXCHANGE_ECDHE_ECDSA_ENABLED

/* TLS 1.2 only */
#define MBEDTLS_SSL_PROTO_TLS1_2

/* TLS server only */
#define MBEDTLS_SSL_SRV_C
#define MBEDTLS_SSL_TLS_C

/* Restrict to our chosen cipher suites to save code size */
#define MBEDTLS_SSL_CIPHERSUITES \
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256, \
    MBEDTLS_TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384

/* SSL features we want */
#define MBEDTLS_SSL_SERVER_NAME_INDICATION
#define MBEDTLS_SSL_RECORD_SIZE_LIMIT   /* RFC 8449 backported to TLS 1.2: server advertises IN_CONTENT_LEN so browsers limit their record size */
#define MBEDTLS_SSL_CACHE_C
#define MBEDTLS_SSL_ALL_ALERT_MESSAGES

/* Use hardware AES-ECB and AES-GCM.
   AES_ALT (aes_hardware.cpp + CoreN2G AesEcb.cpp) replaces software aes.c.
   GCM_ALT (aes_gcm_hardware.cpp + CoreN2G AesGcm.cpp) replaces software gcm.c
   and uses a single shared staging buffer in the LibMbedTls driver. */
#define MBEDTLS_AES_ALT
#define MBEDTLS_GCM_ALT

/* ============================================================
 * ECC curves — secp256r1 and secp384r1 (Suite B)
 * ============================================================ */
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
#define MBEDTLS_ECP_DP_SECP384R1_ENABLED

/* ============================================================
 * Crypto modules — only what TLS 1.2 ECDHE-ECDSA + AES-GCM needs
 * ============================================================ */
#define MBEDTLS_AES_C
#define MBEDTLS_ASN1_PARSE_C
#define MBEDTLS_ASN1_WRITE_C
#define MBEDTLS_BIGNUM_C
#define MBEDTLS_CIPHER_C
#define MBEDTLS_CTR_DRBG_C
#define MBEDTLS_ECDH_C
#define MBEDTLS_ECDSA_C
#define MBEDTLS_ECP_C
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_GCM_C
#define MBEDTLS_MD_C
#define MBEDTLS_OID_C
#define MBEDTLS_PK_C
#define MBEDTLS_PK_PARSE_C
#define MBEDTLS_SHA256_C
#define MBEDTLS_SHA384_C
#define MBEDTLS_SHA512_C

/* X.509 certificate support */
#define MBEDTLS_X509_CRT_PARSE_C
#define MBEDTLS_X509_USE_C

/* PEM parsing for certificates */
#define MBEDTLS_BASE64_C
#define MBEDTLS_PEM_PARSE_C

/* ============================================================
 * Memory optimisations for embedded
 * ============================================================ */

/* Use ROM tables for AES to save ~8KB RAM at cost of ~8KB flash */
#define MBEDTLS_AES_ROM_TABLES

/* Limit MPI size to 384-bit curves (48 bytes) */
#define MBEDTLS_MPI_MAX_SIZE    48

/* Smaller ECP window saves RAM at cost of speed */
#define MBEDTLS_ECP_WINDOW_SIZE        2
#define MBEDTLS_ECP_FIXED_POINT_OPTIM  0

/* NIST curve optimisation */
#define MBEDTLS_ECP_NIST_OPTIM

/* ============================================================
 * Buffer sizes — reduced for SAME54 (256 KB RAM)
 *
 * MBEDTLS_SSL_RECORD_SIZE_LIMIT (RFC 8449) is enabled above, so the server
 * advertises IN_CONTENT_LEN to the client during the handshake.  Any
 * RFC 8449-compliant peer (all modern browsers) will limit its outgoing
 * record size accordingly, so decryption never needs more than this.
 * ============================================================ */
#define MBEDTLS_SSL_IN_CONTENT_LEN     2048
#define MBEDTLS_SSL_OUT_CONTENT_LEN    2048
#define MBEDTLS_SSL_CACHE_DEFAULT_MAX_ENTRIES  2
#define MBEDTLS_SSL_CACHE_DEFAULT_TIMEOUT      3600

/* Single entropy source (hardware TRNG) */
#define MBEDTLS_ENTROPY_MAX_SOURCES    1

/* ============================================================
 * Disable features not needed
 * ============================================================ */
//#define MBEDTLS_NET_C                          // requires POSIX sockets
//#define MBEDTLS_TIMING_C                       // requires POSIX time
//#define MBEDTLS_SSL_CLI_C                      // no TLS client
//#define MBEDTLS_DEBUG_C                        // enable for debugging only
//#define MBEDTLS_ERROR_C                        // enable for debugging only

/* Do NOT include check_config.h here — build_info.h handles the correct
 * include order: user config → config_adjust_* → check_config.h */

#endif /* MBEDTLS_CONFIG_SAME5X_H */
