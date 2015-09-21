#include "stdafx.h"
#include "libsscrypto.h"

LIBSSCRYPTO_API
void aes_init(mbedtls_aes_context *ctx)
{
	mbedtls_aes_init(ctx);
}

LIBSSCRYPTO_API
void aes_free(mbedtls_aes_context *ctx)
{
	mbedtls_aes_free(ctx);
}

LIBSSCRYPTO_API
int aes_setkey_enc(mbedtls_aes_context *ctx, const unsigned char *key,
	unsigned int keybits)
{
	return mbedtls_aes_setkey_enc(ctx, key, keybits);
}

LIBSSCRYPTO_API
int aes_crypt_cfb128(mbedtls_aes_context *ctx,
	int mode,
	size_t length,
	size_t *iv_off,
	unsigned char iv[16],
	const unsigned char *input,
	unsigned char *output)
{
	return mbedtls_aes_crypt_cfb128(ctx, mode, length, iv_off, iv, input, output);
}

LIBSSCRYPTO_API
void arc4_init(mbedtls_arc4_context *ctx)
{
	mbedtls_arc4_init(ctx);
}

LIBSSCRYPTO_API
void arc4_free(mbedtls_arc4_context *ctx)
{
	mbedtls_arc4_free(ctx);
}

LIBSSCRYPTO_API
void arc4_setup(mbedtls_arc4_context *ctx, const unsigned char *key,
	unsigned int keylen)
{
	mbedtls_arc4_setup(ctx, key, keylen);
}

LIBSSCRYPTO_API
int arc4_crypt(mbedtls_arc4_context *ctx, size_t length, const unsigned char *input,
	unsigned char *output)
{
	return mbedtls_arc4_crypt(ctx, length, input, output);
}

