#include <string.h>
#include <mbedtls/md.h>

/**
*  \name X509 Error codes
*  \{
*/
#define MBEDTLS_ERR_HKDF_BAD_PARAM  -0x5300  /**< Bad parameter */
/* \} name */

#ifdef __cplusplus
extern "C" {
#endif

	/**
	*  \brief  HMAC-based Extract-and-Expand Key Derivation Function
	*
	*  \param  md        a hash function; md.size denotes the length of the hash
	*                    function output in bytes
	*  \param  salt      optional salt value (a non-secret random value);
	*                    if not provided, it is set to a string of md.size zeros.
	*  \param  salt_len  length in bytes of the optional \p salt
	*  \param  ikm       (low-entropy) input keying material
	*  \param  ikm_len   length in bytes of \p ikm
	*  \param  info      optional context and application specific information
	*                    (can be a zero-length string)
	*  \param  info_len  length of \p info in bytes
	*  \param  okm       output keying material (of \p okm_len bytes)
	*  \param  okm_len   length of output keying material in octets
	*                    (<= 255*md.size)
	*
	*  \return 0 on success or one of the failure codes from mbedtls_hkdf_extract
	*          or mbedtls_hkdf_expand
	*/
	int mbedtls_hkdf(const unsigned char *salt,
		int salt_len, const unsigned char *ikm, int ikm_len,
		const unsigned char *info, int info_len, unsigned char *okm,
		int okm_len);

	/**
	*  \brief  Take the input keying material \p ikm and extract from it a
	*          fixed-length pseudorandom key \p prk
	*
	*  \param  md        a hash function; md.size denotes the length of the hash
	*                    function output in bytes
	*  \param  salt      optional salt value (a non-secret random value);
	*                    if not provided, it is set to a string of md.size zeros.
	*  \param  salt_len  length in bytes of the optional \p salt
	*  \param  ikm       (low-entropy) input keying material
	*  \param  ikm_len   length in bytes of \p ikm
	*  \param  prk       a pseudorandom key (of md.size bytes)
	*
	*  \return 0 on success, MBEDTLS_ERR_HKDF_BAD_PARAM or one of mbedtls_md_*
	*          error codes on failure
	*/
	int mbedtls_hkdf_extract(const mbedtls_md_info_t *md, const unsigned char *salt,
		int salt_len, const unsigned char *ikm, int ikm_len,
		unsigned char *prk);

	/**
	*  \brief  Expand the supplied \p prk into several additional pseudorandom keys
	*          (the output of the KDF).
	*
	*  \param  md          a hash function; md.size denotes the length of the hash
	*                      function output in bytes
	*  \param  prk         a pseudorandom key of at least md.size bytes; usually,
	*                      the output from the extract step
	*  \param  prk_len     length of \p prk in bytes
	*  \param  info        optional context and application specific information
	*                      (can be a zero-length string)
	*  \param  info_len    length of \p info in bytes
	*  \param  okm         output keying material (of \p okm_len bytes)
	*  \param  okm_len     length of output keying material in octets
	*                      (<= 255*md.size)
	*
	*  \return 0 on success, MBEDTLS_ERR_HKDF_BAD_PARAM or a failure code from the
	*          mbedtls_md_* family
	*/
	int mbedtls_hkdf_expand(const mbedtls_md_info_t *md, const unsigned char *prk,
		int prk_len, const unsigned char *info, int info_len,
		unsigned char *okm, int okm_len);

#ifdef __cplusplus
}
#endif

/* HKDF-Extract + HKDF-Expand */
int mbedtls_hkdf(const unsigned char *salt,
                 int salt_len, const unsigned char *ikm, int ikm_len,
                 const unsigned char *info, int info_len, unsigned char *okm,
                 int okm_len)
{
    // HKDF_SHA1
    const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);

    unsigned char prk[MBEDTLS_MD_MAX_SIZE];

    return mbedtls_hkdf_extract(md, salt, salt_len, ikm, ikm_len, prk) ||
           mbedtls_hkdf_expand(md, prk, mbedtls_md_get_size(md), info, info_len,
                               okm, okm_len);
}

/* HKDF-Extract(salt, IKM) -> PRK */
int mbedtls_hkdf_extract(const mbedtls_md_info_t *md, const unsigned char *salt,
                         int salt_len, const unsigned char *ikm, int ikm_len,
                         unsigned char *prk)
{
    int hash_len;
    unsigned char null_salt[MBEDTLS_MD_MAX_SIZE] = { '\0' };

    if (salt_len < 0) {
        return MBEDTLS_ERR_HKDF_BAD_PARAM;
    }

    hash_len = mbedtls_md_get_size(md);

    if (salt == NULL) {
        salt = null_salt;
        salt_len = hash_len;
    }

    return mbedtls_md_hmac(md, salt, salt_len, ikm, ikm_len, prk);
}

/* HKDF-Expand(PRK, info, L) -> OKM */
int mbedtls_hkdf_expand(const mbedtls_md_info_t *md, const unsigned char *prk,
                        int prk_len, const unsigned char *info, int info_len,
                        unsigned char *okm, int okm_len)
{
    int hash_len;
    int N;
    int T_len = 0, where = 0, i, ret;
    mbedtls_md_context_t ctx;
    unsigned char T[MBEDTLS_MD_MAX_SIZE];

    if (info_len < 0 || okm_len < 0 || okm == NULL) {
        return MBEDTLS_ERR_HKDF_BAD_PARAM;
    }

    hash_len = mbedtls_md_get_size(md);

    if (prk_len < hash_len) {
        return MBEDTLS_ERR_HKDF_BAD_PARAM;
    }

    if (info == NULL) {
        info = (const unsigned char *)"";
    }

    N = okm_len / hash_len;

    if ((okm_len % hash_len) != 0) {
        N++;
    }

    if (N > 255) {
        return MBEDTLS_ERR_HKDF_BAD_PARAM;
    }

    mbedtls_md_init(&ctx);

    if ((ret = mbedtls_md_setup(&ctx, md, 1)) != 0) {
        mbedtls_md_free(&ctx);
        return ret;
    }

    /* Section 2.3. */
    for (i = 1; i <= N; i++) {
        unsigned char c = i;

        ret = mbedtls_md_hmac_starts(&ctx, prk, prk_len) ||
              mbedtls_md_hmac_update(&ctx, T, T_len) ||
              mbedtls_md_hmac_update(&ctx, info, info_len) ||
              /* The constant concatenated to the end of each T(n) is a single
                 octet. */
              mbedtls_md_hmac_update(&ctx, &c, 1) ||
              mbedtls_md_hmac_finish(&ctx, T);

        if (ret != 0) {
            mbedtls_md_free(&ctx);
            return ret;
        }

        memcpy(okm + where, T, (i != N) ? hash_len : (okm_len - where));
        where += hash_len;
        T_len = hash_len;
    }

    mbedtls_md_free(&ctx);

    return 0;
}