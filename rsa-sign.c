#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <openssl/sha.h>

// 打印错误信息
void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

// 生成 RSA 密钥对
RSA* generate_RSA_key(int bits) {
    RSA* rsa = RSA_generate_key(bits, RSA_F4, NULL, NULL);
    if (rsa == NULL) {
        handleErrors();
    }
    return rsa;
}

// 签名函数
unsigned char* sign_message(RSA* rsa, unsigned char* message, unsigned int* sig_len) {
    unsigned char* sig = malloc(RSA_size(rsa));
    if (sig == NULL) {
        handleErrors();
    }

    // 使用 SHA256 哈希消息
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(message, strlen((char*)message), hash);

    // 生成签名
    if (RSA_sign(NID_sha256, hash, SHA256_DIGEST_LENGTH, sig, sig_len, rsa) != 1) {
        handleErrors();
    }

    return sig;
}

// 验证签名函数
int verify_signature(RSA* rsa, unsigned char* message, unsigned char* sig, unsigned int sig_len) {
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(message, strlen((char*)message), hash);

    // 验证签名
    if (RSA_verify(NID_sha256, hash, SHA256_DIGEST_LENGTH, sig, sig_len, rsa) != 1) {
        return 0; // 验证失败
    }
    return 1; // 验证成功
}

int main() {
    // 生成 RSA 密钥对
    int bits = 2048; // 密钥长度
    RSA* rsa = generate_RSA_key(bits);

    // 要签名的消息
    unsigned char* message = (unsigned char*)"Hello World!";
    unsigned int sig_len;

    // 签名
    unsigned char* sig = sign_message(rsa, message, &sig_len);
    printf("Signature generated successfully!\n");

    // 验证签名
    int result = verify_signature(rsa, message, sig, sig_len);
    if (result == 1) {
        printf("Signature verified successfully!\n");
    } else {
        printf("Signature verification failed!\n");
    }

    // 释放资源
    free(sig);
    RSA_free(rsa);
    return 0;
}
