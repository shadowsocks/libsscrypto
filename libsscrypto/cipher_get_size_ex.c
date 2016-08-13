#include <mbedtls/cipher.h>

size_t cipher_get_size_ex()
{
	return sizeof(mbedtls_cipher_context_t);
}