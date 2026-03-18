/*
 * entropy_hardware.cpp
 *
 * Hardware entropy source for mbedTLS using CoreN2G's random32() TRNG driver.
 * Implements mbedtls_hardware_poll() as required by MBEDTLS_ENTROPY_HARDWARE_ALT.
 *
 * The SAME70 and SAME5x MCUs have a True Random Number Generator (TRNG)
 * peripheral. CoreN2G's random32() provides 32 bits of hardware randomness
 * per call, initialized at startup by RandomInit() in CoreInit().
 */

#include <cstring>
#include <Core.h>

extern "C" int mbedtls_hardware_poll(void *data,
                                     unsigned char *output, size_t len, size_t *olen)
{
	(void)data;

	size_t pos = 0;
	while (pos < len)
	{
		const uint32_t val = random32();
		const size_t remaining = len - pos;
		const size_t chunk = (remaining < sizeof(val)) ? remaining : sizeof(val);
		memcpy(output + pos, &val, chunk);
		pos += chunk;
	}

	*olen = len;
	return 0;
}
