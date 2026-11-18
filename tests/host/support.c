#include <assert.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/statvfs.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "vault_crypto.h"
#include "vault_config.h"
#include "esp_http_server.h"
#include "nvs.h"
#include "status_led.h"
#include "freertos/semphr.h"
int64_t host_time = 1000000;
int host_commit_fail;
static unsigned char blob[512]; static size_t blob_len;
int64_t esp_timer_get_time(void) { return host_time; }
void esp_restart(void) {}
void vTaskDelay(unsigned n) { (void)n; }
void vTaskDelete(void *t) { (void)t; }
bool tud_msc_set_sense(uint8_t lun,uint8_t key,uint8_t asc,uint8_t ascq) { return true; }
int xTaskCreate(void (*fn)(void*), const char *n, unsigned s, void *a, unsigned p, void *h) { return 1; }
SemaphoreHandle_t xSemaphoreCreateMutex(void) { return (void *)1; }
int xSemaphoreTake(SemaphoreHandle_t m, unsigned n) { return 1; }
int xSemaphoreGive(SemaphoreHandle_t m) { return 1; }
void vault_status_led_set_state(vault_led_state_t s) {}
void vault_status_led_set_mode(vault_led_mode_t m) {}
esp_err_t esp_vfs_fat_info(const char *p, uint64_t *total, uint64_t *free_bytes) {
 struct statvfs st; if (statvfs(p,&st)) return ESP_FAIL;
 *total=(uint64_t)st.f_blocks*st.f_frsize;*free_bytes=(uint64_t)st.f_bavail*st.f_frsize;return ESP_OK;
}
void vault_secure_zero(void *p, size_t n) { OPENSSL_cleanse(p,n); }
esp_err_t vault_crypto_random(uint8_t *p,size_t n) { return RAND_bytes(p,n)==1?ESP_OK:ESP_FAIL; }
esp_err_t vault_crypto_kdf(const char *p,size_t n,const uint8_t *s,size_t sl,uint32_t rounds,uint8_t *out) {
 return PKCS5_PBKDF2_HMAC(p,n,s,sl,rounds,EVP_sha256(),32,out)==1?ESP_OK:ESP_FAIL;
}
esp_err_t vault_crypto_aes_gcm_encrypt(const uint8_t *key,const uint8_t *iv,size_t il,const uint8_t *aad,size_t al,const uint8_t *in,size_t n,uint8_t *out,uint8_t *tag,size_t tl) {
 EVP_CIPHER_CTX *c=EVP_CIPHER_CTX_new(); int len; uint8_t empty[16]; if(!out)out=empty;
 int ok=EVP_EncryptInit_ex(c,EVP_aes_256_gcm(),NULL,NULL,NULL)==1 && EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_SET_IVLEN,il,NULL)==1 && EVP_EncryptInit_ex(c,NULL,NULL,key,iv)==1 && EVP_EncryptUpdate(c,NULL,&len,aad,al)==1;
 if(n)ok=ok&&EVP_EncryptUpdate(c,out,&len,in,n)==1;
 ok=ok&&EVP_EncryptFinal_ex(c,out+n,&len)==1&&EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_GET_TAG,tl,tag)==1;EVP_CIPHER_CTX_free(c);return ok?ESP_OK:ESP_FAIL;
}
esp_err_t vault_crypto_aes_gcm_decrypt(const uint8_t *key,const uint8_t *iv,size_t il,const uint8_t *aad,size_t al,const uint8_t *in,size_t n,const uint8_t *tag,size_t tl,uint8_t *out) {
 EVP_CIPHER_CTX *c=EVP_CIPHER_CTX_new(); int len; uint8_t empty[16];if(!out)out=empty;
 int ok=EVP_DecryptInit_ex(c,EVP_aes_256_gcm(),NULL,NULL,NULL)==1&&EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_SET_IVLEN,il,NULL)==1&&EVP_DecryptInit_ex(c,NULL,NULL,key,iv)==1&&EVP_DecryptUpdate(c,NULL,&len,aad,al)==1;
 if(n)ok=ok&&EVP_DecryptUpdate(c,out,&len,in,n)==1;
 ok=ok&&EVP_CIPHER_CTX_ctrl(c,EVP_CTRL_GCM_SET_TAG,tl,(void*)tag)==1&&EVP_DecryptFinal_ex(c,out+n,&len)==1;EVP_CIPHER_CTX_free(c);return ok?ESP_OK:ESP_ERR_INVALID_STATE;
}
struct vault_gcm { uint8_t key[32]; };
vault_gcm_t *vault_gcm_create(const uint8_t key[32]) { if(!key)return NULL;vault_gcm_t *c=malloc(sizeof(*c));if(c)memcpy(c->key,key,32);return c; }
void vault_gcm_destroy(vault_gcm_t *c) { if(c){OPENSSL_cleanse(c,sizeof(*c));free(c);} }
esp_err_t vault_gcm_encrypt(vault_gcm_t *c,const uint8_t *iv,size_t il,const uint8_t *aad,size_t al,const uint8_t *in,size_t n,uint8_t *out,uint8_t *tag,size_t tl) {
 return c?vault_crypto_aes_gcm_encrypt(c->key,iv,il,aad,al,in,n,out,tag,tl):ESP_ERR_INVALID_ARG;
}
esp_err_t vault_gcm_decrypt(vault_gcm_t *c,const uint8_t *iv,size_t il,const uint8_t *aad,size_t al,const uint8_t *in,size_t n,const uint8_t *tag,size_t tl,uint8_t *out) {
 return c?vault_crypto_aes_gcm_decrypt(c->key,iv,il,aad,al,in,n,tag,tl,out):ESP_ERR_INVALID_ARG;
}
esp_err_t nvs_open(const char *n,int mode,nvs_handle_t *h) {*h=1;return ESP_OK;}
void nvs_close(nvs_handle_t h) {}
esp_err_t nvs_get_str(nvs_handle_t h,const char *k,char *v,size_t *n) {return ESP_ERR_NOT_FOUND;}
esp_err_t nvs_get_u8(nvs_handle_t h,const char *k,uint8_t *v) {return ESP_ERR_NOT_FOUND;}
esp_err_t nvs_get_u16(nvs_handle_t h,const char *k,uint16_t *v) {return ESP_ERR_NOT_FOUND;}
esp_err_t nvs_get_u32(nvs_handle_t h,const char *k,uint32_t *v) {return ESP_ERR_NOT_FOUND;}
esp_err_t nvs_get_blob(nvs_handle_t h,const char *k,void *v,size_t *n) {if(!blob_len)return ESP_ERR_NOT_FOUND;assert(*n>=blob_len);memcpy(v,blob,blob_len);*n=blob_len;return ESP_OK;}
esp_err_t nvs_set_blob(nvs_handle_t h,const char *k,const void *v,size_t n) {if(host_commit_fail)return ESP_FAIL;assert(n<=sizeof(blob));memcpy(blob,v,n);blob_len=n;return ESP_OK;}
esp_err_t nvs_commit(nvs_handle_t h) {return host_commit_fail?ESP_FAIL:ESP_OK;}
int httpd_req_recv(httpd_req_t *r,char *out,size_t n) {size_t left=r->content_len-r->offset;if(n>left)n=left;if(n>13)n=13;memcpy(out,r->body+r->offset,n);r->offset+=n;return n;}
esp_err_t httpd_resp_set_type(httpd_req_t *r,const char *s) {return ESP_OK;}
esp_err_t httpd_resp_set_status(httpd_req_t *r,const char *s) {snprintf(r->status,sizeof(r->status),"%s",s);return ESP_OK;}
esp_err_t httpd_resp_set_hdr(httpd_req_t *r,const char *k,const char *v) {return ESP_OK;}
esp_err_t httpd_resp_send(httpd_req_t *r,const char *s,ssize_t n) {if(n<0)n=strlen(s);assert(n<sizeof(r->response));memcpy(r->response,s,n);r->response[n]=0;return ESP_OK;}
esp_err_t httpd_resp_send_chunk(httpd_req_t *r,const char *s,ssize_t n) {if(!s)return ESP_OK;if(n<0)n=strlen(s);size_t cur=strlen(r->response);assert(cur+n<sizeof(r->response));memcpy(r->response+cur,s,n);r->response[cur+n]=0;return ESP_OK;}
esp_err_t httpd_req_get_hdr_value_str(httpd_req_t *r,const char *key,char *out,size_t n) {const char *v=!strcmp(key,"X-Vault-Token")?r->token:!strcmp(key,"Host")?(r->host?r->host:"192.168.4.1"):!strcmp(key,"Origin")?r->origin:!strcmp(key,"X-Vault-Request")?r->marker:NULL;if(!v||strlen(v)>=n)return ESP_FAIL;strcpy(out,v);return ESP_OK;}
esp_err_t httpd_req_get_url_query_str(httpd_req_t *r,char *out,size_t n) {const char *q=strchr(r->uri,'?');if(!q||strlen(q+1)>=n)return ESP_FAIL;strcpy(out,q+1);return ESP_OK;}
esp_err_t httpd_query_key_value(const char *q,const char *key,char *out,size_t n) {size_t k=strlen(key);if(strncmp(q,key,k)||q[k]!='='||strlen(q+k+1)>=n)return ESP_FAIL;strcpy(out,q+k+1);return ESP_OK;}
esp_err_t httpd_start(httpd_handle_t *h,const httpd_config_t *c) {*h=(void*)1;return ESP_OK;}
esp_err_t httpd_stop(httpd_handle_t h) {return ESP_OK;}
esp_err_t httpd_register_uri_handler(httpd_handle_t h,const httpd_uri_t *u) {return ESP_OK;}
esp_err_t httpd_resp_send_500(httpd_req_t *r) {return httpd_resp_set_status(r,"500");}
esp_err_t httpd_resp_send_404(httpd_req_t *r) {return httpd_resp_set_status(r,"404");}

size_t httpd_req_get_hdr_value_len(httpd_req_t *r, const char *key) { return !strcmp(key,"Origin") && r->origin ? strlen(r->origin) : 0; }
