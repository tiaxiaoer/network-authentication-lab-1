#include <stdio.h>
#include <openssl/bn.h>
#include <openssl/dh.h>
#include <openssl/rand.h>

// ElGamal 密钥结构
typedef struct {
    BIGNUM *p;  // 大素数
    BIGNUM *g;  // 生成元
    BIGNUM *x;  // 私钥
    BIGNUM *y;  // 公钥
} ElGamalKey;

// 初始化 ElGamal 密钥
void elgamal_keygen(ElGamalKey *key, int bits) {
    // 初始化 BIGNUM 结构
    key->p = BN_new();
    key->g = BN_new();
    key->x = BN_new();
    key->y = BN_new();

    // 生成大素数 p
    BN_generate_prime_ex(key->p, bits, 1, NULL, NULL, NULL);

    // 设置生成元 g 为 2
    BN_set_word(key->g, 2);

    // 生成私钥 x (1 < x < p-1)
    BIGNUM *p_minus_1 = BN_new();
    BN_copy(p_minus_1, key->p);
    BN_sub_word(p_minus_1, 1);
    BN_rand_range(key->x, p_minus_1);

    // 生成公钥 y = g^x mod p
    BN_CTX *ctx = BN_CTX_new();
    BN_mod_exp(key->y, key->g, key->x, key->p, ctx);

    // 释放临时变量
    BN_free(p_minus_1);
    BN_CTX_free(ctx);
}

// 使用 ElGamal 公钥加密
void elgamal_encrypt(BIGNUM *c1, BIGNUM *c2, const BIGNUM *message, const ElGamalKey *key) {
    BIGNUM *k = BN_new();
    BIGNUM *g_k = BN_new();
    BIGNUM *y_k = BN_new();

    BN_CTX *ctx = BN_CTX_new();

    // 生成随机数 k (1 < k < p-1)
    BIGNUM *p_minus_1 = BN_new();
    BN_copy(p_minus_1, key->p);
    BN_sub_word(p_minus_1, 1);
    BN_rand_range(k, p_minus_1);

    // 计算 c1 = g^k mod p
    BN_mod_exp(c1, key->g, k, key->p, ctx);

    // 计算 c2 = m * y^k mod p
    BN_mod_exp(y_k, key->y, k, key->p, ctx);
    BN_mod_mul(c2, message, y_k, key->p, ctx);

    // 释放临时变量
    BN_free(k);
    BN_free(g_k);
    BN_free(y_k);
    BN_free(p_minus_1);
    BN_CTX_free(ctx);
}

// 使用 ElGamal 私钥解密
void elgamal_decrypt(BIGNUM *message, const BIGNUM *c1, const BIGNUM *c2, const ElGamalKey *key) {
    BIGNUM *c1_x = BN_new();
    BIGNUM *inv_c1_x = BN_new();
    BN_CTX *ctx = BN_CTX_new();

    // 计算 c1^x mod p
    BN_mod_exp(c1_x, c1, key->x, key->p, ctx);

    // 计算 c1^(-x) mod p
    BN_mod_inverse(inv_c1_x, c1_x, key->p, ctx);

    // 计算 m = c2 * c1^(-x) mod p
    BN_mod_mul(message, c2, inv_c1_x, key->p, ctx);

    // 释放临时变量
    BN_free(c1_x);
    BN_free(inv_c1_x);
    BN_CTX_free(ctx);
}

int main() {
    // 初始化 ElGamal 密钥
    ElGamalKey key;
    elgamal_keygen(&key, 512);  // 生成 512 位密钥

    // 明文消息
    BIGNUM *message = BN_new();
    BN_set_word(message, 42);  // 加密消息 42

    // 加密
    BIGNUM *c1 = BN_new();
    BIGNUM *c2 = BN_new();
    elgamal_encrypt(c1, c2, message, &key);

    printf("Ciphertext1: ");
    BN_print_fp(stdout, c1);
    printf("\nCiphertext2: ");
    BN_print_fp(stdout, c2);
    printf("\n");

    // 解密
    BIGNUM *decrypted_message = BN_new();
    elgamal_decrypt(decrypted_message, c1, c2, &key);

    printf("Decrypted message: ");
    BN_print_fp(stdout, decrypted_message);
    printf("\n");

    // 释放内存
    BN_free(message);
    BN_free(c1);
    BN_free(c2);
    BN_free(decrypted_message);
    BN_free(key.p);
    BN_free(key.g);
    BN_free(key.x);
    BN_free(key.y);

    return 0;
}
