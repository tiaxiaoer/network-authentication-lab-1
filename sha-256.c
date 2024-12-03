#include <stdio.h>
#include <openssl/sha.h>
#include <string.h>

// 打印SHA256哈希值
void print_sha256(unsigned char hash[SHA256_DIGEST_LENGTH]) {
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        printf("%02x", hash[i]);
    }
    printf("\n");
}

int main() {
    // 要计算SHA256哈希值的字符串
    const char *input = "Hello, World!";

    // 存储结果哈希值的缓冲区
    unsigned char hash[SHA256_DIGEST_LENGTH];

    // 调用OpenSSL的SHA256函数计算哈希值
    SHA256_CTX sha256;
    SHA256_Init(&sha256);                // 初始化SHA256上下文
    SHA256_Update(&sha256, input, strlen(input)); // 更新输入数据
    SHA256_Final(hash, &sha256);         // 计算最终的哈希值

    // 输出结果
    printf("SHA256 hash of '%s': ", input);
    print_sha256(hash);

    return 0;
}
