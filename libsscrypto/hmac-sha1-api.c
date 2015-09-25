#include <hmac-sha1.h>

void ss_sha1_hmac_ex(const unsigned char *key, size_t keylen,
	const unsigned char *input, int ioff, size_t ilen,
	unsigned char output[20])
{
	ss_sha1_hmac(key, keylen, input + ioff, ilen, output);
}
