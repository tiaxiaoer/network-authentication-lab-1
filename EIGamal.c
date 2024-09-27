#include <stdio.h>
#include <stdlib.h>
#include <gmp.h>

// ElGamal 公钥结构
typedef struct {
    mpz_t p; // 大素数
    mpz_t g; // 生成元
    mpz_t y; // y = g^x mod p, x 是私钥
} ElGamalPublicKey;

// ElGamal 私钥结构
typedef struct {
    mpz_t p; // 与公钥相同的大素数
    mpz_t x; // 私钥 x
} ElGamalPrivateKey;

// 初始化 ElGamal 公钥和私钥
void elgamal_keygen(ElGamalPublicKey *pubKey, ElGamalPrivateKey *privKey, unsigned int key_size) {
    mpz_t q;
    mpz_init(q);

    // 初始化 p 和 g
    mpz_init(pubKey->p);
    mpz_init(pubKey->g);
    mpz_init(pubKey->y);
    mpz_init(privKey->p);
    mpz_init(privKey->x);

    // 生成大素数 p
    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, rand());
    mpz_urandomb(pubKey->p, state, key_size);
    mpz_nextprime(pubKey->p, pubKey->p);

    // 设置 g 为 p 的生成元
    mpz_set_ui(pubKey->g, 2);

    // 生成私钥 x (1 < x < p-1)
    mpz_sub_ui(q, pubKey->p, 1);
    mpz_urandomm(privKey->x, state, q);
    mpz_add_ui(privKey->x, privKey->x, 1); // 保证 x > 1

    // 生成公钥 y = g^x mod p
    mpz_powm(pubKey->y, pubKey->g, privKey->x, pubKey->p);

    // 私钥的 p 与公钥的 p 相同
    mpz_set(privKey->p, pubKey->p);

    mpz_clear(q);
    gmp_randclear(state);
}

// 使用公钥进行 ElGamal 加密
void elgamal_encrypt(mpz_t ciphertext1, mpz_t ciphertext2, const mpz_t message, const ElGamalPublicKey *pubKey) {
    mpz_t k, p1;
    mpz_init(k);
    mpz_init(p1);

    // 生成随机数 k (1 < k < p-1)
    mpz_t q;
    mpz_init(q);
    mpz_sub_ui(q, pubKey->p, 1);
    gmp_randstate_t state;
    gmp_randinit_default(state);
    gmp_randseed_ui(state, rand());
    mpz_urandomm(k, state, q);
    mpz_add_ui(k, k, 1);

    // 计算 ciphertext1 = g^k mod p
    mpz_powm(ciphertext1, pubKey->g, k, pubKey->p);

    // 计算 ciphertext2 = m * y^k mod p
    mpz_powm(p1, pubKey->y, k, pubKey->p);
    mpz_mul(ciphertext2, message, p1);
    mpz_mod(ciphertext2, ciphertext2, pubKey->p);

    mpz_clear(k);
    mpz_clear(p1);
    mpz_clear(q);
    gmp_randclear(state);
}

// 使用私钥进行 ElGamal 解密
void elgamal_decrypt(mpz_t message, const mpz_t ciphertext1, const mpz_t ciphertext2, const ElGamalPrivateKey *privKey) {
    mpz_t p1;
    mpz_init(p1);

    // 计算 p1 = ciphertext1^x mod p
    mpz_powm(p1, ciphertext1, privKey->x, privKey->p);

    // 计算 m = ciphertext2 / p1 mod p
    mpz_invert(p1, p1, privKey->p);
    mpz_mul(message, ciphertext2, p1);
    mpz_mod(message, message, privKey->p);

    mpz_clear(p1);
}

int main() {
    // 初始化公钥和私钥
    ElGamalPublicKey pubKey;
    ElGamalPrivateKey privKey;
    elgamal_keygen(&pubKey, &privKey, 512);  // 生成 512 位密钥

    // 明文消息 (例如 42)
    mpz_t message;
    mpz_init_set_ui(message, 42);

    // 加密
    mpz_t ciphertext1, ciphertext2;
    mpz_init(ciphertext1);
    mpz_init(ciphertext2);
    elgamal_encrypt(ciphertext1, ciphertext2, message, &pubKey);

    printf("Ciphertext1: ");
    mpz_out_str(stdout, 10, ciphertext1);
    printf("\nCiphertext2: ");
    mpz_out_str(stdout, 10, ciphertext2);
    printf("\n");

    // 解密
    mpz_t decrypted_message;
    mpz_init(decrypted_message);
    elgamal_decrypt(decrypted_message, ciphertext1, ciphertext2, &privKey);

    printf("Decrypted message: ");
    mpz_out_str(stdout, 10, decrypted_message);
    printf("\n");

    // 清除内存
    mpz_clear(message);
    mpz_clear(ciphertext1);
    mpz_clear(ciphertext2);
    mpz_clear(decrypted_message);
    mpz_clear(pubKey.p);
    mpz_clear(pubKey.g);
    mpz_clear(pubKey.y);
    mpz_clear(privKey.p);
    mpz_clear(privKey.x);

    return 0;
}
