# LibMbedTls SAME70 Configuration Makefile
# Target: Duet 3 MB6HC (SAME70Q20B, Cortex-M7)
# mbedTLS 3.6 LTS — all source in library/

SAME70_BUILD_DIR := SAME70
SAME70_TARGET := $(SAME70_BUILD_DIR)/libLibMbedTls.a

# ============================================================
# Source files — only the modules enabled in config-rrf.h
# ============================================================

# TLS/SSL layer
SAME70_TLS_SRCS := \
	library/ssl_cache.c \
	library/ssl_ciphersuites.c \
	library/ssl_msg.c \
	library/ssl_tls.c \
	library/ssl_tls12_server.c

# X.509 certificate handling
SAME70_X509_SRCS := \
	library/x509.c \
	library/x509_crt.c

# Crypto modules
SAME70_CRYPTO_SRCS := \
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
SAME70_PSA_SRCS := \
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
SAME70_SUPPORT_SRCS := \
	library/block_cipher.c \
	library/hmac_drbg.c

SAME70_C_SRCS := $(SAME70_TLS_SRCS) $(SAME70_X509_SRCS) $(SAME70_CRYPTO_SRCS) $(SAME70_PSA_SRCS) $(SAME70_SUPPORT_SRCS)

# Hardware drivers (C++)
SAME70_CPP_SRCS := \
	drivers/entropy_hardware.cpp \
	drivers/gcm_hardware.cpp \
	drivers/platform_snprintf.cpp
# Include paths
# ============================================================
SAME70_INCLUDES := \
	-Iconfigs \
	-Idrivers \
	-Iinclude \
	-Ilibrary \
	-I../CoreN2G/src \
	-I../CoreN2G/src/SAM4S_4E_E70/asf/common/utils \
	-I../CoreN2G/src/SAM4S_4E_E70/asf/sam/utils/cmsis/same70/include \
	-I../CoreN2G/src/SAM4S_4E_E70/SAME70 \
	-I../CoreN2G/src/arm/CMSIS/5.4.0/CMSIS/Core/Include \
	-I../RRFLibraries/src \
	-I../FreeRTOS/src/include \
	-I../FreeRTOS/src/portable/GCC/ARM_CM7/r0p1

# ============================================================
# Preprocessor defines
# ============================================================
SAME70_DEFINES := \
	-D__SAME70Q20B__ \
	-DMBEDTLS_CONFIG_FILE=\"config-rrf.h\"

# ============================================================
# Compiler flags
# ============================================================
SAME70_CFLAGS := -c -std=gnu11 \
	-mcpu=cortex-m7 \
	-mthumb \
	-mfpu=fpv5-d16 \
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
	$(SAME70_INCLUDES) \
	$(SAME70_DEFINES)

SAME70_CXXFLAGS := -c -std=gnu++17 \
	-mcpu=cortex-m7 \
	-mthumb \
	-mfpu=fpv5-d16 \
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
	$(SAME70_INCLUDES) \
	$(SAME70_DEFINES)

# Optimise for size by default — flash is tight on Q20B
ifeq ($(DEBUG),1)
SAME70_CFLAGS += -O0 -g3
SAME70_CXXFLAGS += -O0 -g3
else
SAME70_CFLAGS += -Os
SAME70_CXXFLAGS += -Os
endif

# ============================================================
# Build rules
# ============================================================

SAME70_C_OBJS := $(SAME70_C_SRCS:%.c=$(SAME70_BUILD_DIR)/%.o)
SAME70_CPP_OBJS := $(SAME70_CPP_SRCS:%.cpp=$(SAME70_BUILD_DIR)/%.o)
SAME70_OBJS := $(SAME70_C_OBJS) $(SAME70_CPP_OBJS)
SAME70_DEPS := $(SAME70_OBJS:.o=.d)

.PHONY: SAME70
SAME70: $(SAME70_TARGET)

$(SAME70_TARGET): $(SAME70_OBJS)
	$(Q)echo "  AR      $@"
	$(Q)mkdir -p $(@D)
	$(Q)$(AR) rcs $@ $^

$(SAME70_BUILD_DIR)/%.o: %.c
	$(Q)echo "  CC      $<"
	$(Q)mkdir -p $(@D)
	$(Q)$(CC) $(SAME70_CFLAGS) -MMD -MP -o $@ $<

$(SAME70_BUILD_DIR)/%.o: %.cpp
	$(Q)echo "  CXX     $<"
	$(Q)mkdir -p $(@D)
	$(Q)$(CXX) $(SAME70_CXXFLAGS) -MMD -MP -o $@ $<

-include $(SAME70_DEPS)

.PHONY: clean-SAME70
clean-SAME70:
	$(Q)echo "  RM      $(SAME70_BUILD_DIR)"
	$(Q)rm -rf $(SAME70_BUILD_DIR)
