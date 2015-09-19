#pragma once

#include "stdafx.h"
#include <mbedtls/aes.h>
#include <mbedtls/arc4.h>

#ifdef __cplusplus
#define LIBSSCRYPTO_EXTERN_C extern "C"
#else
#define LIBSSCRYPTO_EXTERN_C 
#endif

#ifdef LIBSSCRYPTO_EXPORTS
#define LIBSSCRYPTO_API LIBSSCRYPTO_EXTERN_C __declspec(dllexport)
#else
#define LIBSSCRYPTO_API LIBSSCRYPTO_EXTERN_C __declspec(dllimport)
#endif

#ifndef _SSIZE_T_DEFINED
typedef SSIZE_T ssize_t;
#endif


LIBSSCRYPTO_API
void aes_init(mbedtls_aes_context *ctx);

LIBSSCRYPTO_API
void aes_free(mbedtls_aes_context *ctx);

LIBSSCRYPTO_API
int aes_setkey_enc(mbedtls_aes_context *ctx, const unsigned char *key,
	unsigned int keybits);

LIBSSCRYPTO_API
int aes_crypt_cfb128(mbedtls_aes_context *ctx,
	int mode,
	size_t length,
	size_t *iv_off,
	unsigned char iv[16],
	const unsigned char *input,
	unsigned char *output);

LIBSSCRYPTO_API
void arc4_init(mbedtls_arc4_context *ctx);

LIBSSCRYPTO_API
void arc4_free(mbedtls_arc4_context *ctx);

LIBSSCRYPTO_API
void arc4_setup(mbedtls_arc4_context *ctx, const unsigned char *key,
	unsigned int keylen);

LIBSSCRYPTO_API
int arc4_crypt(mbedtls_arc4_context *ctx, size_t length, const unsigned char *input,
	unsigned char *output);


#define ONETIMEAUTH_BYTES 16U
#define ONETIMEAUTH_KEYBYTES 32U

#define ONETIMEAUTH_FLAG 0x10
#define ADDRTYPE_MASK 0xF

#define CRC_BUF_LEN 128
#define CRC_BYTES 2


#define EVP_MAX_MD_SIZE			64	/* longest known is SHA512 */
#define EVP_MAX_KEY_LENGTH		64
#define EVP_MAX_IV_LENGTH		16
#define EVP_MAX_BLOCK_LENGTH		32


#define MAX_KEY_LENGTH EVP_MAX_KEY_LENGTH
#define MAX_IV_LENGTH EVP_MAX_IV_LENGTH
#define MAX_MD_SIZE EVP_MAX_MD_SIZE

LIBSSCRYPTO_API
uint16_t crc16(const char *buf, int offset, int len);

LIBSSCRYPTO_API
int ss_check_crc(char *buf, ssize_t *buf_len, char *crc_buf, ssize_t *crc_idx);

LIBSSCRYPTO_API
int ss_gen_crc(char *buf, int *buf_offset, int *data_len,
	char *crc_buf, int *crc_idx, int buf_size);

LIBSSCRYPTO_API
int ss_onetimeauth(char *auth,
	char *msg, int msg_len,
	const char *iv, int iv_len,
	const char *key, int key_len);

LIBSSCRYPTO_API
int ss_onetimeauth_verify(char *auth,
	char *msg, int msg_len,
	const char *iv, int iv_len,
	const char *key, int key_len);
