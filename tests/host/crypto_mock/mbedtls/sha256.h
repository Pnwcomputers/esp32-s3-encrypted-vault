#pragma once
/* Real SHA-256 (OpenSSL) behind the mbedtls API, so the firmware's PBKDF2
 * composition is checked against an independent PBKDF2 implementation. */
#include <stddef.h>
#include <openssl/sha.h>
#include <openssl/crypto.h>
typedef struct { SHA256_CTX c; } mbedtls_sha256_context;
static inline void mbedtls_sha256_init(mbedtls_sha256_context *x) { memset(x,0,sizeof(*x)); }
static inline void mbedtls_sha256_free(mbedtls_sha256_context *x) { OPENSSL_cleanse(x,sizeof(*x)); }
static inline void mbedtls_sha256_clone(mbedtls_sha256_context *d,const mbedtls_sha256_context *s) { *d=*s; }
static inline int mbedtls_sha256_starts(mbedtls_sha256_context *x,int is224) { return is224 || SHA256_Init(&x->c)!=1; }
static inline int mbedtls_sha256_update(mbedtls_sha256_context *x,const unsigned char *p,size_t n) { return SHA256_Update(&x->c,p,n)!=1; }
static inline int mbedtls_sha256_finish(mbedtls_sha256_context *x,unsigned char out[32]) { return SHA256_Final(out,&x->c)!=1; }
static inline int mbedtls_sha256(const unsigned char *p,size_t n,unsigned char out[32],int is224) { return is224 || !SHA256(p,n,out); }
