//对称加密

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/err.h>
 
void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}
 
int aes_encrypt(unsigned char *key, unsigned char *plaintext, int plaintext_len, unsigned char *iv, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx;
 
    if(!(ctx = EVP_CIPHER_CTX_new())) 
        handleErrors();
 
    if(1 != EVP_EncryptInit_ex(ctx, aria_128_cbc(), NULL, key, iv))
        handleErrors();
 
    int len = 0;
    if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
        handleErrors();
 
    if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) 
        handleErrors();
 
    EVP_CIPHER_CTX_free(ctx);
 
    return len;
}
 
int aes_decrypt(unsigned char *key, unsigned char *ciphertext, int ciphertext_len, unsigned char *iv, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx;
 
    if(!(ctx = EVP_CIPHER_CTX_new())) 
        handleErrors();
 
    if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv))
        handleErrors();
 
    int len = 0;
    if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
 
    if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) 
        handleErrors();
 
    EVP_CIPHER_CTX_free(ctx);
 
    return len;
}
 
int main() {
    OpenSSL_add_all_algorithms();
 
    // 示例密钥和初始化向量，应该使用随机数据
    unsigned char *key = (unsigned char *)"0123456789abcdef0123456789abcdef";
    unsigned char *iv = (unsigned char *)"fedcba9876543210fedcba9876543210";
 
    // 原文和密文
    unsigned char *plaintext = (unsigned char *)"Hello World!";
    int plaintext_len = strlen((const char *)plaintext);
    unsigned char ciphertext[128];
    unsigned char decryptedtext[128];
 
    // 加密
    int ciphertext_len = aes_encrypt(key, plaintext, plaintext_len, iv, ciphertext);
    printf("Ciphertext is: ");
    for(int i = 0; i < ciphertext_len; ++i) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");
 
    // 解密
    int decryptedtext_len = aes_decrypt(key, ciphertext, ciphertext_len, iv, decryptedtext);
    printf("Decrypted text is: %s\n", decryptedtext);
 
    return 0;
}