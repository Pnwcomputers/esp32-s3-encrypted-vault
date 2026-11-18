#include <assert.h>
#include <stdio.h>
#include <openssl/evp.h>
#include "vault_crypto.c"
void esp_fill_random(void *p, size_t n) { memset(p,0x55,n); }
static void kdf_matches_openssl(const char *pin,size_t pin_len,const uint8_t *salt,size_t salt_len,uint32_t rounds) {
 uint8_t mine[32],ref[32];
 assert(vault_crypto_kdf(pin,pin_len,salt,salt_len,rounds,mine)==ESP_OK);
 assert(PKCS5_PBKDF2_HMAC(pin,(int)pin_len,salt,(int)salt_len,(int)rounds,EVP_sha256(),32,ref)==1);
 assert(!memcmp(mine,ref,32));
}
int main(void) {
 uint8_t key[32]={0},iv[12]={0},aad[4]={0},tag[16];
 assert(vault_crypto_aes_gcm_encrypt(key,iv,12,aad,4,NULL,0,NULL,tag,16)==ESP_OK);
 assert(vault_crypto_aes_gcm_decrypt(key,iv,12,aad,4,NULL,0,tag,16,NULL)==ESP_OK);
 tag[0]^=1;
 assert(vault_crypto_aes_gcm_decrypt(key,iv,12,aad,4,NULL,0,tag,16,NULL)==ESP_ERR_INVALID_STATE);
 assert(vault_crypto_aes_gcm_encrypt(key,iv,12,aad,4,NULL,1,NULL,tag,16)==ESP_ERR_INVALID_ARG);
 uint8_t input[1]={7},out[1]={0};
 assert(vault_crypto_aes_gcm_encrypt(key,iv,12,aad,4,input,1,out,tag,16)==ESP_OK && out[0]==7);
 /* The reusable context keeps the same empty-message contract. */
 vault_gcm_t *gcm=vault_gcm_create(key);assert(gcm);
 assert(vault_gcm_encrypt(gcm,iv,12,aad,4,NULL,0,NULL,tag,16)==ESP_OK);
 assert(vault_gcm_decrypt(gcm,iv,12,aad,4,NULL,0,tag,16,NULL)==ESP_OK);
 assert(vault_gcm_encrypt(gcm,iv,12,aad,4,NULL,1,NULL,tag,16)==ESP_ERR_INVALID_ARG);
 vault_gcm_destroy(gcm);assert(!vault_gcm_create(NULL));
 /* Cloned-pad PBKDF2 equals standard PBKDF2-HMAC-SHA256, including RFC 7914
  * vectors' shapes, long (>64-byte, pre-hashed) keys and the vault's 10000 rounds. */
 const uint8_t salt[32]={1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31,32};
 kdf_matches_openssl("passwd",6,(const uint8_t*)"salt",4,1);
 kdf_matches_openssl("123456",6,salt,32,2);
 kdf_matches_openssl("correct horse battery staple",28,salt,32,VAULT_PBKDF2_ROUNDS);
 char longpin[100];memset(longpin,'x',sizeof(longpin));
 kdf_matches_openssl(longpin,64,salt,32,3);kdf_matches_openssl(longpin,65,salt,32,3);kdf_matches_openssl(longpin,100,salt,7,3);
 uint8_t dk[32];assert(vault_crypto_kdf("123456",6,salt,32,0,dk)==ESP_ERR_INVALID_ARG);
 puts("Crypto checks passed (ESP-IDF empty-message requirement, reusable GCM context, PBKDF2 vs OpenSSL)");
}
