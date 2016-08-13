#include <mbedtls/cipher.h>

void cipher_set_operation_ex(mbedtls_cipher_context_t *ctx, int operation )
{
	if(ctx == NULL) return;
	ctx->operation = operation;
}