# LibMbedTls SAME5x Configuration Makefile
# Target: Duet 3 Mini 5+ (SAME54P20A, Cortex-M4)
# mbedTLS 3.6 LTS — all source in library/

SAME5x_BUILD_DIR := SAME5x
SAME5x_TARGET := $(SAME5x_BUILD_DIR)/libLibMbedTls.a

# ============================================================
# Source files — same modules as SAME70, just different CPU flags
# ============================================================

# TLS/SSL layer
SAME5x_TLS_SRCS := \
	library/ssl_cache.c \
	library/ssl_ciphersuites.c \
	library/ssl_msg.c \
	library/ssl_ticket.c \
	library/ssl_tls.c \
	library/ssl_tls13_generic.c \
	library/ssl_tls13_keys.c \
	library/ssl_tls13_server.c

# X.509 certificate handling
SAME5x_X509_SRCS := \
	library/x509.c \
	library/x509_crt.c

# Crypto modules
SAME5x_CRYPTO_SRCS := \
	library/aes.c \
	library/asn1parse.c \
	library/asn1write.c \
	library/base64.c \
	library/bignum.c \
	library/bignum_core.c \
	library/bignum_mod.c \
	library/bignum_mod_raw.c \
	library/cipher.c \
	library/cipher_wrap.c \
	library/constant_time.c \
	library/ctr_drbg.c \
	library/ecdh.c \
	library/ecdsa.c \
	library/ecp.c \
	library/ecp_curves.c \
	library/ecp_curves_new.c \
	library/entropy.c \
	library/entropy_poll.c \
	library/gcm.c \
	library/md.c \
	library/oid.c \
	library/pem.c \
	library/pk.c \
	library/pk_ecc.c \
	library/pkparse.c \
	library/pk_wrap.c \
	library/platform.c \
	library/platform_util.c \
	library/sha256.c \
	library/sha512.c

# PSA crypto (used internally by mbedTLS 3.6 even without MBEDTLS_USE_PSA_CRYPTO)
SAME5x_PSA_SRCS := \
	library/psa_crypto.c \
	library/psa_crypto_aead.c \
	library/psa_crypto_cipher.c \
	library/psa_crypto_client.c \
	library/psa_crypto_driver_wrappers_no_static.c \
	library/psa_crypto_ecp.c \
	library/psa_crypto_hash.c \
	library/psa_crypto_mac.c \
	library/psa_crypto_slot_management.c \
	library/psa_util.c

# Additional support needed by the modules above
SAME5x_SUPPORT_SRCS := \
	library/hmac_drbg.c

SAME5x_C_SRCS := $(SAME5x_TLS_SRCS) $(SAME5x_X509_SRCS) $(SAME5x_CRYPTO_SRCS) $(SAME5x_PSA_SRCS) $(SAME5x_SUPPORT_SRCS)

# Hardware drivers (C++)
SAME5x_CPP_SRCS := \
	drivers/entropy_hardware.cpp \
	drivers/aes_hardware.cpp \
	drivers/aes_gcm_hardware.cpp \
	drivers/pukcc_hardware.cpp \
	drivers/platform_snprintf.cpp

# Include paths
# ============================================================
SAME5x_INCLUDES := \
	-Iconfigs \
	-Idrivers \
	-Iinclude \
	-Ilibrary \
	-I../CoreN2G/src \
	-I../CoreN2G/src/SAME5x_C21/SAME5x \
	-I../CoreN2G/src/SAME5x_C21/SAME5x/hal/include \
	-I../CoreN2G/src/SAME5x_C21/SAME5x/hal/utils/include \
	-I../CoreN2G/src/SAME5x_C21/SAME5x/hri \
	-I../CoreN2G/src/SAME5x_C21/SAME5x/Config \
	-I../CoreN2G/src/atmel/SAME54_DFP/1.1.134/include \
	-I../CoreN2G/src/arm/CMSIS/5.4.0/CMSIS/Core/Include \
	-I../RRFLibraries/src \
	-I../FreeRTOS/src/include \
	-I../FreeRTOS/src/portable/GCC/ARM_CM4F

# ============================================================
# Preprocessor defines
# ============================================================
SAME5x_DEFINES := \
	-D__SAME54P20A__ \
	-DMBEDTLS_CONFIG_FILE=\"config-same5x.h\"

# ============================================================
# Compiler flags — Cortex-M4 with FPv4
# ============================================================
SAME5x_CFLAGS := -c -std=gnu11 \
	-mcpu=cortex-m4 \
	-mthumb \
	-mfpu=fpv4-sp-d16 \
	-mfloat-abi=hard \
	-mfp16-format=ieee \
	-ffunction-sections \
	-fdata-sections \
	-nostdlib \
	-Wall \
	-Wundef \
	-Wdouble-promotion \
	-Werror=return-type \
	-Werror=implicit \
	-fsingle-precision-constant \
	$(SAME5x_INCLUDES) \
	$(SAME5x_DEFINES)

SAME5x_CXXFLAGS := -c -std=gnu++17 \
	-mcpu=cortex-m4 \
	-mthumb \
	-mfpu=fpv4-sp-d16 \
	-mfloat-abi=hard \
	-mfp16-format=ieee \
	-ffunction-sections \
	-fdata-sections \
	-fno-exceptions \
	-fno-rtti \
	-nostdlib \
	-Wall \
	-Wundef \
	-Wdouble-promotion \
	-Werror=return-type \
	-fsingle-precision-constant \
	$(SAME5x_INCLUDES) \
	$(SAME5x_DEFINES)

# Optimise for size by default
ifeq ($(DEBUG),1)
SAME5x_CFLAGS += -O0 -g3
SAME5x_CXXFLAGS += -O0 -g3
else
SAME5x_CFLAGS += -Os
SAME5x_CXXFLAGS += -Os
endif

# ============================================================
# Build rules
# ============================================================

SAME5x_C_OBJS := $(SAME5x_C_SRCS:%.c=$(SAME5x_BUILD_DIR)/%.o)
SAME5x_CPP_OBJS := $(SAME5x_CPP_SRCS:%.cpp=$(SAME5x_BUILD_DIR)/%.o)
SAME5x_OBJS := $(SAME5x_C_OBJS) $(SAME5x_CPP_OBJS)
SAME5x_DEPS := $(SAME5x_OBJS:.o=.d)

.PHONY: SAME5x
SAME5x: $(SAME5x_TARGET)

$(SAME5x_TARGET): $(SAME5x_OBJS)
	$(Q)echo "  AR      $@"
	$(Q)mkdir -p $(@D)
	$(Q)$(AR) rcs $@ $^

$(SAME5x_BUILD_DIR)/%.o: %.c
	$(Q)echo "  CC      $<"
	$(Q)mkdir -p $(@D)
	$(Q)$(CC) $(SAME5x_CFLAGS) -MMD -MP -o $@ $<

$(SAME5x_BUILD_DIR)/%.o: %.cpp
	$(Q)echo "  CXX     $<"
	$(Q)mkdir -p $(@D)
	$(Q)$(CXX) $(SAME5x_CXXFLAGS) -MMD -MP -o $@ $<

-include $(SAME5x_DEPS)

.PHONY: clean-SAME5x
clean-SAME5x:
	$(Q)echo "  RM      $(SAME5x_BUILD_DIR)"
	$(Q)rm -rf $(SAME5x_BUILD_DIR)
