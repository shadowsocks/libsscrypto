#include <mbedtls/md.h>

void ss_sha1_hmac_ex(const unsigned char *key, size_t keylen,
	const unsigned char *input, int ioff, size_t ilen,
	unsigned char output[20])
{
	mbedtls_md_hmac(mbedtls_md_info_from_type(MBEDTLS_MD_SHA1), key, keylen, input + ioff, ilen, output);
}
