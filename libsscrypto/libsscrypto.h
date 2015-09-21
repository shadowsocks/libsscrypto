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
