/*
 * platform_snprintf.cpp
 *
 * Redirects mbedTLS snprintf/vsnprintf to RRFLibraries' SafeSnprintf/SafeVsnprintf.
 * This avoids pulling in newlib's snprintf which internally calls _malloc_r,
 * causing a multiple-definition conflict with RRF's custom nano-mallocr.
 *
 * These functions are referenced via MBEDTLS_PLATFORM_SNPRINTF_MACRO and
 * MBEDTLS_PLATFORM_VSNPRINTF_MACRO in config-rrf.h.
 */

#include <General/SafeVsnprintf.h>

extern "C" int mbedtls_platform_snprintf(char *s, size_t n, const char *format, ...)
{
	va_list args;
	va_start(args, format);
	const int ret = SafeVsnprintf(s, n, format, args);
	va_end(args);
	return ret;
}

extern "C" int mbedtls_platform_vsnprintf(char *s, size_t n, const char *format, va_list args)
{
	return SafeVsnprintf(s, n, format, args);
}
