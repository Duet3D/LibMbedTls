# LibMbedTls Master Makefile
# Builds Mbed TLS 3.6 library for various MCU configurations

# Cross-compiler toolchain.
# RepRapFirmware exports CROSS_COMPILE when building this as a submodule.
# When building LibMbedTls standalone, fall back to a toolchain on PATH.
ARM_GNU_TOOLCHAIN_VERSION ?= 15.2.rel1
ifeq ($(OS),Windows_NT)
HOST_ARCH_RAW := $(subst AMD64,x86_64,$(subst ARM64,aarch64,$(PROCESSOR_ARCHITECTURE)))
else
HOST_ARCH_RAW := $(shell uname -m)
HOST_OS_RAW := $(shell uname -s)
endif

ifeq ($(HOST_ARCH_RAW),aarch64)
ARM_GNU_TOOLCHAIN_HOST_ARCH := aarch64
else ifeq ($(HOST_ARCH_RAW),arm64)
ARM_GNU_TOOLCHAIN_HOST_ARCH := aarch64
else ifeq ($(HOST_ARCH_RAW),x86_64)
ARM_GNU_TOOLCHAIN_HOST_ARCH := x86_64
else ifeq ($(HOST_ARCH_RAW),amd64)
ARM_GNU_TOOLCHAIN_HOST_ARCH := x86_64
else
ARM_GNU_TOOLCHAIN_HOST_ARCH := $(HOST_ARCH_RAW)
endif

ifeq ($(OS),Windows_NT)
ARM_GNU_TOOLCHAIN_HOST := mingw-w64-$(ARM_GNU_TOOLCHAIN_HOST_ARCH)
else ifeq ($(HOST_OS_RAW),Darwin)
ARM_GNU_TOOLCHAIN_HOST := darwin-$(subst aarch64,arm64,$(ARM_GNU_TOOLCHAIN_HOST_ARCH))
else
ARM_GNU_TOOLCHAIN_HOST := $(ARM_GNU_TOOLCHAIN_HOST_ARCH)
endif

CROSS_COMPILE ?= $(abspath ../arm-gnu-toolchain-$(ARM_GNU_TOOLCHAIN_VERSION)-$(ARM_GNU_TOOLCHAIN_HOST)-arm-none-eabi/bin/arm-none-eabi-)
export CROSS_COMPILE

# Toolchain commands
CC = $(CROSS_COMPILE)gcc
CXX = $(CROSS_COMPILE)g++
AS = $(CROSS_COMPILE)gcc
AR = $(CROSS_COMPILE)ar

# Quiet build support (V=1 for verbose)
ifeq ($(V),1)
	Q :=
else
	Q := @
endif
export Q

# Available build configurations
CONFIGS := SAME70 SAME5x

# Default target
.DEFAULT_GOAL := SAME70

# Print available targets
.PHONY: help
help:
	@echo "LibMbedTls Build System"
	@echo "Available targets:"
	@for config in $(CONFIGS); do echo "  make $$config"; done
	@echo ""
	@echo "Other targets:"
	@echo "  make all            - Build all configurations"
	@echo "  make clean          - Clean all build outputs"
	@echo "  make clean-<config> - Clean specific configuration"
	@echo ""
	@echo "Options:"
	@echo "  DEBUG=1             - Build with debug symbols"
	@echo "  V=1                 - Verbose output"

# Build all configurations
.PHONY: all
all:
	$(Q)$(MAKE) SAME70
	$(Q)$(MAKE) SAME5x

# Include configuration-specific makefiles only when building that specific config
ifeq ($(MAKECMDGOALS),SAME70)
-include Makefiles/SAME70.mk
endif
ifeq ($(MAKECMDGOALS),SAME5x)
-include Makefiles/SAME5x.mk
endif

# Generic clean target
.PHONY: clean
clean:
	@echo "Cleaning all LibMbedTls build outputs..."
	@for config in $(CONFIGS); do \
		if [ -d "$$config" ]; then \
			echo "  Cleaning $$config..."; \
			rm -rf "$$config"; \
		fi; \
	done
