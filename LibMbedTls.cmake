# LibMbedTls (mbedTLS 3.6 LTS plus the Duet hardware-crypto drivers) as a reusable CMake component.
# See lib/FreeRTOS/FreeRTOS.cmake for the pattern.
#
#   libmbedtls_add_library(TARGET <name> MCU <SAME70|SAME5x> ARCH <interface target>)
#
# Only the mbedTLS modules enabled in the per-MCU config header are compiled, so the list is
# explicit rather than globbed.

set(LIBMBEDTLS_DIR "${CMAKE_CURRENT_LIST_DIR}")
set(LIBMBEDTLS_LIBRARY_FLAGS)
set(LIBMBEDTLS_LIBRARY_ARGS)

function(libmbedtls_add_library OUT_TARGET)
    cmake_parse_arguments(PARSE_ARGV 1 ARG "${LIBMBEDTLS_LIBRARY_FLAGS}" "${DEFAULT_LIBRARY_ARGS};${LIBMBEDTLS_LIBRARY_ARGS}" "")
    if(ARG_UNPARSED_ARGUMENTS)
        message(FATAL_ERROR "libmbedtls_add_library: unknown arguments: ${ARG_UNPARSED_ARGUMENTS}")
    endif()

    get_enabled_features(_enabled_features ${LIBMBEDTLS_LIBRARY_FLAGS})
    make_library_name(_target "LibMbedTls" STATIC ${ARG_MCU} ${_enabled_features})
    set(${OUT_TARGET} "${_target}" PARENT_SCOPE)
    if(TARGET ${_target})
        return()  # already built for this MCU and feature set
    endif()

    set(_root "${LIBMBEDTLS_DIR}")
    set(_core "${LIBMBEDTLS_DIR}/../CoreN2G/src")
    set(_lib "${LIBMBEDTLS_DIR}/..")

    if(ARG_MCU STREQUAL "SAME70")
        set(_part_define "__SAME70Q20B__")
        set(_config_header "config-same70.h")
        set(_cmsis_inc
            "${_core}/SAM4S_4E_E70/asf/common/utils"
            "${_core}/SAM4S_4E_E70/asf/sam/utils/cmsis/same70/include"
            "${_core}/SAM4S_4E_E70/SAME70")
        set(_freertos_port "portable/GCC/ARM_CM7/r0p1")
    else()
        message(FATAL_ERROR "libmbedtls_add_library: unsupported MCU '${ARG_MCU}' (only SAME70 is wired up so far)")
    endif()

    set(_c_srcs
        ssl_cache ssl_ciphersuites ssl_msg ssl_ticket ssl_tls ssl_tls13_generic
        ssl_tls13_keys ssl_tls13_server
        x509 x509_crt
        aes asn1parse asn1write base64 bignum bignum_core bignum_mod bignum_mod_raw
        cipher cipher_wrap constant_time ctr_drbg ecdh ecdsa ecp ecp_curves ecp_curves_new
        entropy entropy_poll gcm md oid pem pk pk_ecc pkparse pk_wrap platform platform_util
        sha256 sha512
        psa_crypto psa_crypto_aead psa_crypto_cipher psa_crypto_client
        psa_crypto_driver_wrappers_no_static psa_crypto_ecp psa_crypto_hash psa_crypto_mac
        psa_crypto_slot_management psa_util
        hmac_drbg)
    list(TRANSFORM _c_srcs PREPEND "${_root}/library/")
    list(TRANSFORM _c_srcs APPEND ".c")

    set(_cpp_srcs
        "${_root}/drivers/entropy_hardware.cpp"
        "${_root}/drivers/aes_hardware.cpp"
        "${_root}/drivers/aes_gcm_hardware.cpp"
        "${_root}/drivers/platform_snprintf.cpp")

    add_library(${_target} STATIC ${_c_srcs} ${_cpp_srcs})

    target_include_directories(${_target} PRIVATE
        "${_root}/configs"
        "${_root}/drivers"
        "${_root}/include"
        "${_root}/library"
        "${_core}"
        ${_cmsis_inc}
        "${_core}/arm/CMSIS/5.4.0/CMSIS/Core/Include"
        "${_lib}/RRFLibraries/src"
        "${_lib}/FreeRTOS/src/include"
        "${_lib}/FreeRTOS/src/${_freertos_port}")
    target_include_directories(${_target} INTERFACE
        "${_root}/include" "${_root}/library" "${_root}/configs")

    target_compile_definitions(${_target} PRIVATE
        ${_part_define} "MBEDTLS_CONFIG_FILE=\"${_config_header}\"")

    target_compile_options(${_target} PRIVATE
        -ffunction-sections -fdata-sections -nostdlib
        -Wall -Wundef -Wdouble-promotion -Werror=return-type -fsingle-precision-constant
        $<$<COMPILE_LANGUAGE:C>:-Werror=implicit>
        $<$<COMPILE_LANGUAGE:CXX>:-std=c++20;-fno-threadsafe-statics;-fno-rtti;-fexceptions;-Wsuggest-override;-Werror;-Wnoexcept;-Wshadow;-Wsign-promo>
        # mbedTLS bignum inline asm exhausts the register allocator at -O0, so debug uses -Og.
        $<$<NOT:$<CONFIG:Debug>>:-O2>
        $<$<CONFIG:Debug>:-Og;-g3>)

    target_link_libraries(${_target} PRIVATE ${ARG_ARCH})
endfunction()
