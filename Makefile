# LibMbedTls Master Makefile
# Builds Mbed TLS 3.6 library for various MCU configurations

# Cross-compiler toolchain
CROSS_COMPILE ?= ../arm-gnu-toolchain-15.2.rel1-x86_64-arm-none-eabi/bin/arm-none-eabi-
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
