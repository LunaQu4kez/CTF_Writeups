#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include "sdf_cryptoapi.h"

void *devHandle = NULL;
void *sessionHandle = NULL;
void *keyHandle = NULL;

const unsigned char encrypt_key_hex[] = "FE61D7ED4A6376AAF13E7D78CB42E645";

int open_session() {
    int ret = 0;

    //打开设备
    ret = SDF_OpenDeviceWithPath("./sdt_hsmcrypt.conf", &devHandle);
    if (ret) {
        printf("SDF_OpenDeviceWithPath error, ret=%08x\n", ret);
        return ret;
    }

    //打开会话
    ret = SDF_OpenSession(devHandle, &sessionHandle);
    if (ret) {
        printf("SDF_OpenSession error, ret=%08x\n", ret);
        SDF_CloseDevice(devHandle);
        return ret;
    }
    return ret;
}

int hex_string_to_char_array(const char *hex, unsigned char *out) {
    size_t hex_len = strlen(hex);
    if (hex_len % 2 != 0) return -1; // 奇数长度报错

    for (size_t i = 0; i < hex_len; i += 2) {
        unsigned int byte;
        if (sscanf(hex + i, "%2X", &byte) != 1) return -1; // 解析失败
        out[i / 2] = (unsigned char) byte;
    }
    return hex_len / 2; // 返回转换后的字节数
}

int import_key() {
    int ret = 0;

    unsigned char encrypt_key[128] = {'\0'};
    const unsigned int key_len = 16;
    const int inner_key_index = 1;
    ret = hex_string_to_char_array(encrypt_key_hex, encrypt_key);
    if (ret < 0) {
        printf("hex_string_to_char_array error, ret=%08x\n", ret);
        return ret;
    }

    ret = SDF_ImportKeyWithKEK(sessionHandle, SGD_SM4, inner_key_index, encrypt_key, key_len, &keyHandle);
    if (ret) {
        printf("SDF_ImportKeyWithKEK error, ret=%08x\n", ret);
        return ret;
    }
    return 0;
}

int init() {
    int ret = 0;
    ret = open_session();
    if (ret) {
        printf("open_session error, ret=%08x\n", ret);
        return ret;
    }
    ret = import_key();
    if (ret) {
        printf("import_key error, ret=%08x\n", ret);
        return ret;
    }
    return 0;
}

int close_session() {
    //关闭会话
    int ret = 0;
    ret = SDF_CloseSession(sessionHandle);
    if (ret) {
        printf("SDF_CloseSession error, ret=%08x\n", ret);
        SDF_CloseDevice(devHandle);
        return ret;
    }

    //关闭设备
    ret = SDF_CloseDevice(devHandle);
    if (ret) {
        printf("SDF_CloseDevice error, ret=%08x\n", ret);
        return ret;
    }
    return ret;
}

int destroy() {
    int ret = 0;

    //销毁密钥句柄
    ret = SDF_DestroyKey(sessionHandle, keyHandle);
    if (ret) {
        printf("[ts_symm] SDF_DestroyKey error, ret=%08x\n", ret);
        return ret;
    }

    ret = close_session();
    if (ret) {
        printf("[ts_symm] close_session error, ret=%08x\n", ret);
        return ret;
    }
    return 0;
}

int encrypt_with_sm4_cfb(unsigned char *iv, unsigned char *plaintext, unsigned int plaintext_len,
                         unsigned char *ciphertext,
                         unsigned int *ciphertext_len) {
    // TODO 此处代码已省略
    return 0;
}

unsigned char *transform(const unsigned char *input, size_t in_len) {
    if (in_len < 16) {
        return NULL;
    }

    unsigned char *output = malloc(in_len + 1);
    if (output == NULL) {
        return NULL;
    }
    memcpy(output, input, 8);
    memcpy(output + 8, input + in_len - 8, 8);
    memcpy(output + 8 * 2, input + 8, in_len - 8 * 2);
    output[in_len] = '\0';
    return output;
}

unsigned char *pkcs7_padding(const unsigned char *input, size_t in_len, size_t block_size, size_t *out_len) {
    // TODO 此处代码已省略
    return NULL;
}

const char hex_table[] = "0123456789ABCDEF";

void char_array_to_hex_string(const unsigned char *src, size_t len, char *dst) {
    for (size_t i = 0; i < len; i++) {
        dst[2 * i] = hex_table[(src[i] >> 4) & 0x0F];
        dst[2 * i + 1] = hex_table[src[i] & 0x0F];
    }
    dst[2 * len] = '\0';
}

// 加密地理位置经纬度
int encrypt_geo_location(unsigned char *iv, const unsigned char *location, unsigned int location_len,
                         char *ciphertext_hex,
                         unsigned int *ciphertext_hex_len) {
    int ret = 0;
    unsigned char buffer[1024] = {0};
    // 1. 转换格式
    unsigned char *transformed_location = transform(location, location_len);

    // 2. 填充
    size_t padded_plaintext_len = 0;
    unsigned char *padded_plaintext = pkcs7_padding(transformed_location, location_len, 16, &padded_plaintext_len);
    if (padded_plaintext == NULL) {
        ret = -1;
        printf("pkcs7_padding failed!");
        free(transformed_location);
        return ret;
    }

    // 3. 加密
    unsigned int ciphertext_len = 0;
    ret = encrypt_with_sm4_cfb(iv, padded_plaintext, padded_plaintext_len, buffer, &ciphertext_len);
    if (ret) {
        printf("encrypt error, ret=%08x\n", ret);
        free(transformed_location);
        free(padded_plaintext);
        free(iv);
        return ret;
    }
    char_array_to_hex_string(buffer, ciphertext_len, ciphertext_hex);
    *ciphertext_hex_len = 2 * ciphertext_len;

    // 4. 清理
    free(transformed_location);
    free(padded_plaintext);
    return ret;
}

int main(int argc, char *argv[]) {
    int ret = 0;
    const unsigned char location[] = "xxxxxxxxxxxxxxxxxxxx";
    const unsigned int location_len = sizeof(location) - 1;

    ret = init();
    if (ret) {
        printf("init error, ret=%08x\n", ret);
        return ret;
    }

    char ciphertext_hex[1024] = {0};
    unsigned int ciphertext_hex_len = 0;
    unsigned char iv[] = {'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x', 'x'};

    ret = encrypt_geo_location(iv, location, location_len, ciphertext_hex, &ciphertext_hex_len);
    if (ret) {
        printf("encrypt error, ret=%08x\n", ret);
        return ret;
    }
    printf("encrypt ok\n");
    printf("ciphertext_hex: %s\n", (char *) ciphertext_hex);

    ret = destroy();
    if (ret) {
        printf("destroy error, ret=%08x\n", ret);
    }
    return 0;
}
