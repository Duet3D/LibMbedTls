# Local changes to mbedTLS (based on 3.6 LTS)

This file documents all modifications made to the upstream mbedTLS source
for use in RepRapFirmware.  Keep it up to date when editing mbedTLS files.


## New files

### configs/config-same5x.h + configs/config-same70.h

Per-target TLS configurations for RepRapFirmware.  Both are minimal
TLS 1.3 server configs (ECC only, no RSA) with:

- Platform memory routed through LwIP heap (`mbedtls_lwip_calloc`/`free`)
- `snprintf`/`vsnprintf` redirected to `SafeSnprintf` (RRFLibraries)
  to avoid newlib's `_malloc_r`
- Hardware entropy via TRNG (`MBEDTLS_ENTROPY_HARDWARE_ALT`)
- Hardware AES-ECB + AES-GCM (`MBEDTLS_AES_ALT`, `MBEDTLS_GCM_ALT`)
- RFC 8449 `record_size_limit` so browsers respect reduced buffer sizes
- Session tickets for TLS 1.3 PSK-ephemeral resumption

SAME5x differences (256 KB RAM):
- P-256 only; PUKCC hardware accelerator for ECDHE/ECDSA
- `SSL_IN_CONTENT_LEN` = 2048, `SSL_OUT_CONTENT_LEN` = 1024
- `MPI_MAX_SIZE` = 32

SAME70 differences (512 KB RAM):
- P-256, P-384, X25519 (avoids HRR for browsers)
- SHA-384/SHA-512 enabled for P-384
- `SSL_IN_CONTENT_LEN` = 2048, `SSL_OUT_CONTENT_LEN` = 2048
- `MPI_MAX_SIZE` = 48

### drivers/entropy_hardware.cpp

`mbedtls_hardware_poll()` using the SAME5x/SAME70 TRNG via CoreN2G.

### drivers/platform_snprintf.cpp

`mbedtls_platform_snprintf()` / `mbedtls_platform_vsnprintf()` forwarding
to `SafeSnprintf()` / `SafeVsnprintf()` from RRFLibraries.

### drivers/aes_hardware.cpp + include/mbedtls/aes_alt.h

`MBEDTLS_AES_ALT` implementation.  Replaces software `aes.c` with
hardware AES-ECB via `aes_ecb_crypt()` from CoreN2G `AesEcb.cpp`.
Only the ECB primitive is overridden; modes (CBC/CTR/etc.) are built
on top by mbedTLS library code.

### drivers/aes_gcm_hardware.cpp + include/mbedtls/gcm_alt.h

`MBEDTLS_GCM_ALT` implementation.  Replaces software `gcm.c` with
hardware AES-GCM via CoreN2G `AesGcm.cpp`.  Uses a zero-copy streaming
approach: `update()` stores a pointer, `finish()` passes it to hardware.

### drivers/pukcc_hardware.cpp (SAME5x only)

`MBEDTLS_ECP_MUL_ALT`, `MBEDTLS_ECDSA_SIGN_ALT`, `MBEDTLS_ECDSA_VERIFY_ALT`.
Uses the PUKCC ROM cryptographic coprocessor on SAME54 for P-256:
- `ZpEccMulFast` - scalar multiplication (ECDHE, ~80ms)
- `ZpEcDsaGenerateFast` - ECDSA signing
- `ZpEcDsaVerifyFast` - ECDSA verification

Non-P-256 curves and PUKCC errors fall through to software.

### Makefiles/SAME5x.mk + Makefiles/SAME70.mk

Per-target Makefiles listing the mbedTLS source files to compile.

### .cproject + .project

Eclipse CDT project files for the library.


## Modified upstream files

### include/mbedtls/mbedtls_config.h

- Enabled `MBEDTLS_PLATFORM_MEMORY` (was commented out).
- Enabled `MBEDTLS_GCM_ALT` (was commented out).

### include/mbedtls/config_adjust_ssl.h - record_size_limit for TLS 1.2

Upstream `#undef`s `MBEDTLS_SSL_RECORD_SIZE_LIMIT` when TLS 1.3 is not
enabled, because the extension was originally implemented only for 1.3.
Changed to keep it defined for TLS 1.2 builds.  Without this, TLS 1.2
browsers assume 16 KB records, which overflow the reduced input buffer.

### include/mbedtls/check_config.h - relaxed prerequisite check

Upstream requires `MBEDTLS_SSL_PROTO_TLS1_3` for `MBEDTLS_SSL_RECORD_SIZE_LIMIT`.
Changed to accept TLS 1.3 or TLS 1.2, matching the config_adjust_ssl.h change.

### include/mbedtls/ssl.h - DTLS CID compat guard

Changed `#if MBEDTLS_SSL_DTLS_CONNECTION_ID_COMPAT == 0` to
`#if !defined(...) || ... == 0` to avoid compile error when DTLS is not
enabled (macro undefined, implicit `#if 0`  works but `-Wundef` warns).

### library/ssl_tls12_server.c - record_size_limit extension (RFC 8449)

Backported the record_size_limit extension from the TLS 1.3 code to the
TLS 1.2 ServerHello path.  Three additions:

1. `ssl_parse_record_size_limit_ext()` - parses the extension from
   ClientHello and stores `record_size_limit` in the session.
2. `ssl_write_record_size_limit_ext()` - writes the extension in
   ServerHello, advertising `MBEDTLS_SSL_IN_CONTENT_LEN` as our limit.
3. Extension dispatch in `ssl_parse_client_hello()` for
   `MBEDTLS_TLS_EXT_RECORD_SIZE_LIMIT`.

This is essential for embedded targets with reduced buffer sizes.  Without
it, TLS 1.2 browsers send 16 KB records that overflow the 2 KB input buffer.

4. `ssl_parse_max_fragment_length_ext()` - added validation that the
   client's requested MFL value does not exceed `MBEDTLS_SSL_IN_CONTENT_LEN`.
   Upstream blindly accepts any valid MFL code (512/1024/2048/4096) and
   echoes it back; RFC 6066 does not allow the server to negotiate a smaller
   value, so MFL=4096 with a 2 KB input buffer would cause oversized records.
   Now rejects with `illegal_parameter` alert if the value is too large.

5. Mandatory record size extension check (only when
   `MBEDTLS_SSL_IN_CONTENT_LEN < 16384`): after parsing all ClientHello
   extensions, the handshake is aborted with `missing_extension` (alert 109)
   if the client offered neither `record_size_limit` (RFC 8449) nor
   `max_fragment_length` (RFC 6066).  Without one of these extensions the
   server cannot enforce `MBEDTLS_SSL_IN_CONTENT_LEN` and the peer may
   send 16 KB records that overflow the input buffer.  When the input
   buffer is full-sized (>= 16 KB) the check is skipped.

### library/ssl_tls13_server.c - mandatory record_size_limit

After parsing all ClientHello extensions, the handshake is aborted with
`missing_extension` (alert 109) if the client did not offer
`record_size_limit` (RFC 8449).  TLS 1.3 replaced `max_fragment_length`
with `record_size_limit`, so only the latter is checked.  Without the
extension the peer may send 16 KB records that overflow
`MBEDTLS_SSL_IN_CONTENT_LEN`.  Only active when
`MBEDTLS_SSL_IN_CONTENT_LEN < 16384`.

### library/entropy.c

Cosmetic: removed a blank line.
