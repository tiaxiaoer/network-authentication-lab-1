#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/dh.h>
#include <openssl/pem.h>
#include <openssl/err.h>

// 打印错误信息
void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

// 生成并返回固定的 DH 参数 (p 和 g)
DH* get_dh_params() {
    DH *dh = DH_new();
    if (dh == NULL) handleErrors();

    // 使用预定义的安全参数 p 和 g
    const char *p_hex = "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E08"
                        "8A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD"
                        "3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7"
                        "EC6F44C42E9A637ED6B0BFF5CB6F406B7ED5AF080777109839A"
                        "25204742D1843AEE9F07FCB6F423F87796094A0A0F743D87F57"
                        "D438732BE";
    const char *g_hex = "02";

    BIGNUM *p = NULL, *g = NULL;
    if (!BN_hex2bn(&p, p_hex) || !BN_hex2bn(&g, g_hex)) {
        handleErrors();
    }

    if (!DH_set0_pqg(dh, p, NULL, g)) {
        handleErrors();
    }

    return dh;
}

// 生成 DH 密钥对
DH* generate_dh_key(DH *dh_params) {
    DH *dh = DH_new();
    if (dh == NULL) handleErrors();

    if (!DH_set0_pqg(dh, BN_dup(DH_get0_p(dh_params)), NULL, BN_dup(DH_get0_g(dh_params)))) {
        handleErrors();
    }

    // 生成密钥对
    if (DH_generate_key(dh) != 1) {
        handleErrors();
    }

    return dh;
}

// 计算共享密钥
unsigned char* compute_shared_secret(DH *dh, const BIGNUM *peer_pub_key, int *secret_len) {
    unsigned char *secret = malloc(DH_size(dh));
    if (secret == NULL) handleErrors();

    *secret_len = DH_compute_key(secret, peer_pub_key, dh);
    if (*secret_len < 0) {
        handleErrors();
    }

    return secret;
}

// 将 BIGNUM 转换为字符串
void print_bignum(const BIGNUM *bn) {
    char *bn_str = BN_bn2dec(bn);
    printf("%s\n", bn_str);
    OPENSSL_free(bn_str);
}

int main() {
    // 获取固定的 DH 参数
    DH *dh_params = get_dh_params();

    // A 和 B 使用相同的 DH 参数
    DH *dhA = generate_dh_key(dh_params);
    const BIGNUM *pub_key_A, *priv_key_A;
    DH_get0_key(dhA, &pub_key_A, &priv_key_A);
    printf("A's public key:\n");
    print_bignum(pub_key_A);

    DH *dhB = generate_dh_key(dh_params);
    const BIGNUM *pub_key_B, *priv_key_B;
    DH_get0_key(dhB, &pub_key_B, &priv_key_B);
    printf("B's public key:\n");
    print_bignum(pub_key_B);

    // A 计算共享密钥
    int secret_len_A;
    unsigned char *shared_secret_A = compute_shared_secret(dhA, pub_key_B, &secret_len_A);
    printf("A's shared secret length: %d\n", secret_len_A);

    // B 计算共享密钥
    int secret_len_B;
    unsigned char *shared_secret_B = compute_shared_secret(dhB, pub_key_A, &secret_len_B);
    printf("B's shared secret length: %d\n", secret_len_B);

    // 检查共享密钥是否相同
    if (secret_len_A == secret_len_B && memcmp(shared_secret_A, shared_secret_B, secret_len_A) == 0) {
        printf("Shared secrets match!\n");
    } else {
        printf("Shared secrets do not match!\n");
    }

    // 释放资源
    free(shared_secret_A);
    free(shared_secret_B);
    DH_free(dhA);
    DH_free(dhB);
    DH_free(dh_params);

    return 0;
}
