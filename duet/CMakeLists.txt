# mbedTLS 3.6 LTS with the Duet3D hardware crypto drivers, built for DUET_MCU, which the consuming
# project's toolchain file sets along with the core's code generation flags. See LOCAL_CHANGES.md.
#
#   DUET_MCU          SAME70 or SAME5x; selects configs/config-<mcu>.h
#   DUET_PART_DEFINE  the macro naming the MCU part, e.g. __SAME70Q20B__
#
# Target: Duet::LibMbedTls. Needs Duet::CoreN2G and Duet::RRFLibraries (the drivers use the
# hardware and SafeSnprintf).
#
# Only the modules the configuration enables are compiled, so the source list is explicit. The
# upstream build in the parent directory is not used.

cmake_minimum_required(VERSION 3.25)
project(LibMbedTls LANGUAGES C CXX)

cmake_path(GET CMAKE_CURRENT_SOURCE_DIR PARENT_PATH _root)

set(_drivers entropy_hardware aes_hardware aes_gcm_hardware)
if(DUET_MCU STREQUAL "SAME70")
    set(_config config-same70.h)
elseif(DUET_MCU STREQUAL "SAME5x")
    set(_config config-same5x.h)
    list(APPEND _drivers pukcc_hardware)    # PUKCC elliptic curve accelerator
else()
    message(FATAL_ERROR "LibMbedTls: unsupported DUET_MCU '${DUET_MCU}'")
endif()
list(APPEND _drivers platform_snprintf)

set(_modules
    # TLS
    ssl_cache ssl_ciphersuites ssl_msg ssl_ticket ssl_tls ssl_tls13_generic ssl_tls13_keys
    ssl_tls13_server
    # X.509
    x509 x509_crt
    # Crypto
    aes asn1parse asn1write base64 bignum bignum_core bignum_mod bignum_mod_raw cipher cipher_wrap
    constant_time ctr_drbg ecdh ecdsa ecp ecp_curves ecp_curves_new entropy entropy_poll gcm md oid
    pem pk pk_ecc pkparse pk_wrap platform platform_util sha256 sha512
    # PSA crypto, which mbedTLS 3.6 uses internally even without MBEDTLS_USE_PSA_CRYPTO
    psa_crypto psa_crypto_aead psa_crypto_cipher psa_crypto_client
    psa_crypto_driver_wrappers_no_static psa_crypto_ecp psa_crypto_hash psa_crypto_mac
    psa_crypto_slot_management psa_util
    # Needed by the modules above
    hmac_drbg)
list(TRANSFORM _modules REPLACE "(.+)" "${_root}/library/\\1.c")
list(TRANSFORM _drivers REPLACE "(.+)" "${_root}/drivers/\\1.cpp")

add_library(LibMbedTls STATIC ${_modules} ${_drivers})
add_library(Duet::LibMbedTls ALIAS LibMbedTls)

set_target_properties(LibMbedTls PROPERTIES
    CXX_STANDARD 20
    CXX_STANDARD_REQUIRED ON
    CXX_EXTENSIONS OFF)

# include/ and configs/ both have a psa/crypto_config.h. The library's own sources find Duet's
# minimal one in configs/ first, but consumers find upstream's full one in include/ first.
target_include_directories(LibMbedTls
    PRIVATE "${_root}/configs" "${_root}/drivers"
    PUBLIC "${_root}/include" "${_root}/library" "${_root}/configs")
target_compile_definitions(LibMbedTls
    PRIVATE ${DUET_PART_DEFINE}
    PUBLIC "MBEDTLS_CONFIG_FILE=\"${_config}\"")

target_link_libraries(LibMbedTls PRIVATE Duet::CoreN2G Duet::RRFLibraries)

target_compile_options(LibMbedTls PRIVATE
    -fsingle-precision-constant
    -Wall
    -Wundef
    -Wdouble-promotion
    -Werror=return-type
    $<$<COMPILE_LANGUAGE:C>:-Werror=implicit>
    $<$<COMPILE_LANGUAGE:CXX>:-fno-threadsafe-statics;-fno-rtti;-fexceptions;-Wsuggest-override;-Werror;-Wnoexcept;-Wshadow;-Wsign-promo>
    -fstack-usage
    -fdump-rtl-expand
    # __FILE__ relative to the library root, so the image does not depend on the checkout location
    "-fmacro-prefix-map=${_root}/=")
