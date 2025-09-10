# 第二届熵密杯 Writeup

共 152 队参赛，排名 32 / 152，获得优胜奖（好歹是有个奖）

题目包含的一些文件在 [这里](./file)，文件夹名称就是题目名称



## 初始谜题

一共 3 道初始谜题，难度应该都不算高（毕竟分值少），我们做出来了第 1 和第 3 题

### 初始谜题 1

首先看给出的加密代码 `encryption.py`，大致是先添加前缀和填充补 0，然后分块进行加密

本题相当于一个已知明文攻击，可以根据第一块明文信息计算出key，解密所有密文

```python
from sympy import Mod, Integer
from sympy.core.numbers import mod_inverse

# 模数
N_HEX = "FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123"
MODULUS = Integer(int(N_HEX, 16))
MSG_PREFIX = "CryptoCup message:"

def decrypt_message(encrypted_message, key):
    num_blocks = len(encrypted_message) // 32
    blocks = [encrypted_message[i * 32:(i + 1) * 32] for i in range(num_blocks)]

    decrypted_blocks = []

    k = key

    # 解密每个分组
    for block in blocks:
        block_int = int.from_bytes(block, byteorder='big')
        key_inv = mod_inverse(k, MODULUS)
        decrypted_block_int = Mod(block_int * key_inv, MODULUS)
        decrypted_blocks.append(decrypted_block_int)
        k += 1  # 密钥自增1

    # 将解密后的分组连接成最终的明文
    decrypted_message = b''.join(
        int(block_int).to_bytes(16, byteorder='big') for block_int in decrypted_blocks
    )

    # 去除前缀
    if decrypted_message.startswith(MSG_PREFIX.encode('utf-8')):
        decrypted_message = decrypted_message[len(MSG_PREFIX):]

    return decrypted_message.rstrip(b'\x00').decode('utf-8')

encrypted_message = bytes.fromhex('9598a369d04acc175afd637e7746ced83618c8c56b863c41275c0369fb29e69f1d751fe52f411adad420c8d76d37eabb94ab1b0826bcc2402582207a52def3e3fd3293c5fd5a7766e0bbac1db3d5a3b5bef16e7159c2a63ed3cef89613a2edbc5f69339870c9c4edeab2c0e14df386adc444a05a71055508c8cf0f37111b3c35')

k = 61424538580175128991556143209860080552006984830458390358109815115146238996445

print(decrypt_message(encrypted_message, k))
```

### 初始谜题 2

这道题目我们并没有做出来，主要原因可能是对国密算法不熟悉，思路猜测应该是哈希长度扩展攻击

### 初始谜题 3

查看给出的加密代码 `lwe.py`，注意到由于变量 `A`, `b` 都已知，且有 `b = (A * s + e) % q`，其中 `e` 为随机噪声。但注意到 `e` 很小且可以取到的值不多，因此可以枚举所有 `e` 反过来计算出对应的 `s`，又由于 `c1`, `c2` 都已知，所以用解密函数 `decrypt(c1, c2, s)` 进行解密

```python
import sympy as sp


n = 16
q = 251

A = sp.Matrix([[195, 74, 182, 66, 212, 23, 117, 224, 148, 141, 188, 29, 121, 151, 23, 222], [60, 188, 243, 44, 14, 217, 24, 52, 46, 20, 248, 0, 47, 119, 183, 69], [210, 35, 212, 103, 2, 78, 176, 11, 24, 98, 208, 226, 144, 229, 175, 117], [47, 55, 18, 211, 58, 227, 40, 221, 57, 134, 125, 66, 96, 249, 157, 124], [110, 183, 51, 172, 205, 249, 99, 34, 7, 161, 25, 19, 108, 246, 159, 54], [63, 168, 98, 51, 233, 164, 98, 2, 24, 111, 104, 103, 174, 195, 199, 162], [146, 227, 105, 203, 92, 195, 182, 84, 108, 8, 52, 149, 205, 37, 123, 228], [46, 248, 85, 196, 123, 208, 109, 188, 185, 234, 74, 143, 1, 235, 187, 154], [246, 130, 238, 59, 113, 208, 220, 28, 163, 42, 37, 150, 59, 28, 249, 97], [241, 1, 204, 17, 194, 172, 117, 250, 126, 145, 124, 20, 116, 21, 141, 198], [111, 95, 146, 7, 157, 178, 131, 192, 40, 247, 173, 199, 123, 181, 224, 234], [132, 32, 70, 61, 232, 6, 77, 156, 160, 92, 39, 165, 232, 230, 31, 216], [186, 38, 162, 131, 83, 100, 168, 29, 75, 2, 223, 83, 32, 205, 3, 27], [82, 121, 177, 37, 169, 27, 172, 21, 132, 156, 205, 146, 175, 240, 10, 121], [208, 208, 38, 182, 159, 134, 237, 136, 124, 210, 48, 236, 162, 239, 185, 37], [184, 72, 43, 48, 111, 95, 230, 203, 101, 40, 241, 196, 236, 196, 5, 36]])
b = sp.Matrix([[22], [40], [247], [189], [49], [133], [139], [51], [60], [236], [170], [170], [149], [61], [210], [84]])
c1 = sp.Matrix([[17, 38, 147, 79, 89, 105, 223, 191, 82, 166, 152, 68, 50, 242, 212, 124], [170, 144, 5, 229, 163, 188, 152, 218, 187, 230, 159, 80, 147, 43, 86, 77], [179, 106, 11, 40, 91, 219, 245, 61, 166, 23, 148, 144, 133, 213, 191, 94], [22, 188, 232, 56, 153, 94, 249, 210, 179, 79, 23, 12, 208, 178, 190, 97], [92, 174, 65, 126, 231, 45, 240, 98, 212, 164, 31, 218, 179, 70, 15, 14], [113, 95, 117, 147, 7, 19, 199, 50, 170, 150, 127, 110, 238, 72, 178, 15], [115, 6, 26, 228, 20, 191, 241, 158, 107, 58, 236, 175, 242, 235, 118, 0], [30, 81, 234, 137, 96, 3, 111, 112, 234, 142, 32, 24, 132, 168, 242, 92], [229, 221, 134, 49, 95, 50, 193, 213, 221, 61, 211, 170, 222, 66, 226, 16], [203, 69, 77, 1, 215, 92, 238, 99, 83, 210, 11, 198, 4, 16, 172, 47], [140, 200, 60, 163, 24, 185, 211, 87, 122, 245, 27, 44, 155, 10, 205, 201], [50, 231, 92, 163, 164, 6, 65, 28, 196, 82, 199, 185, 215, 143, 61, 191], [213, 221, 52, 244, 33, 19, 127, 35, 174, 0, 108, 83, 132, 1, 108, 32], [197, 162, 174, 197, 230, 17, 9, 21, 9, 68, 102, 246, 60, 125, 40, 3], [87, 79, 98, 247, 202, 157, 121, 242, 90, 147, 106, 139, 147, 129, 89, 96], [235, 146, 143, 173, 97, 10, 190, 92, 198, 85, 32, 204, 74, 66, 80, 192]])
c2 = sp.Matrix([[229], [125], [91], [189], [155], [165], [131], [138], [206], [97], [56], [193], [220], [177], [213], [27]])
Temp = A.inv_mod(q)
x = (c1 * Temp) % q


def decrypt(c1, c2, s):
    m_dec = (c2 - c1 * s) % q
    m_rec = m_dec.applyfunc(lambda x: round(2 * x / q) % 2)  # 还原消息
    m_bin = ''.join([str(bit) for bit in m_rec])  # 将SymPy矩阵转换为二进制字符串
    m_rec_int = int(m_bin, 2)  # 将二进制字符串转换为整数
    return m_rec_int


ans = set()
for i in range(0, 65536):
    e_bin = bin(i)[2:].zfill(n)  # 将消息转换为16比特的二进制字符串
    e = sp.Matrix([int(bit) for bit in e_bin])  # 转换为SymPy矩阵
    s = Temp * (b - e) % q
    msg = decrypt(c1, c2, s)
    ans.add(msg)
    print(i)
print(ans)  # {41093}
```

最后发现可能的解集只有 41093，那么就确定 41093 是明文了，转换成十六进制提交到客户端即可获得 flag



## 夺旗闯关

这一部分我们只做出来一道题，感觉还得多练（

### Gitea 密码解密

题目的 Gitea 并不是什么加密方式，只是题目材料是从 Gitea 平台上下载下来的 ...

给出的 `passwordEncryptorV2.c` 是加密过程，并且告诉了最后的密文

观察加密过程，发现这是一个魔改的 AES，其主要加密过程如下

```c
void encrypt(unsigned char* password, unsigned int key, unsigned char* ciphertext) {
    unsigned char roundKeys[16 * ROUND] = {}; //

    // 生成轮密钥
    derive_round_key(key, roundKeys, 16 * ROUND);

    // 初始状态为16字节的口令
    unsigned char state[16]; // 初始状态为16字节的密码
    memcpy(state, password, 16); // 初始状态为密码的初始值

    // 迭代加密过程
    for (int round = 0; round < ROUND; round++)
    {
        reverseBits(state);
        sBoxTransform(state);
        leftShiftBytes(state);
        addRoundKey(state, roundKeys, round);
    }

    memcpy(ciphertext, state, 16);
}
```

每一轮迭代执行 4 个方法。读加密代码可知，`reverseBits(state)` 对所有比特进行左右的翻转；`sBoxTransform(state)` 类似凯撒，对每个十六进制位按一个固定的对应规则进行了一个对应更换；`leftShiftBytes(state)` 将当前的消息左移 11 bits；`addRoundKey(state, roundKeys, round)` 则是进行了一个异或的操作，相当于 AES 的轮密钥加

```c
// 轮密钥加
void addRoundKey(unsigned char* state, unsigned char* roundKey, unsigned int round) {
    for (int i = 0; i < 16; i++) {
        for (int j = 0; j < 8; j++) {
            state[i] ^= ((roundKey[i + round * 16] >> j) & 1) << j;
        }
    }
}
```

既然加密规则已知，只要稍微耐心一些，不难写出这些方法的反推代码。

但根据密文反推过后发现，明文与题目提示的 16 个字符的字符串并且以 `'pwd:'` 这 4 个字符开头不符，其余部分不可能出错，只能是题目代码中的密钥 `key` 并不是真正的密钥，只是一个示例。想到这里好像没有什么好办法，只想到了暴力，但面对 32 bit 的暴力又有些犹豫，一段时间之后主办方发放了本题的提示，就是尝试暴力，于是在 O3 优化和架构优化下使用 4 线程并用高性能的游戏本跑，只花了十多分钟就跑出来了，于是这道题目终于解开，将明文作为密码填入给的压缩包即可打开，里面有 flag1 和后续题目的资料。

flag1: `flag1{4ed63e97-3cc8-d3c7-ad9d-3f8163a433c6}` 

解题代码如下（有点长）：

```c++
#include <stdio.h>
#include <string.h>
// #include <openssl/sha.h>

#define ROUND 16

// 将十六进制字符串转换为 unsigned char 数组
void hex_to_bytes(const char* hex_str, unsigned char* bytes, size_t bytes_len) {
    size_t hex_len = strlen(hex_str);
    if (hex_len % 2 != 0 || hex_len / 2 > bytes_len) {
        fprintf(stderr, "Invalid hex string length.\n");
        return;
    }

    for (size_t i = 0; i < hex_len / 2; i++) {
        sscanf(hex_str + 2 * i, "%2hhx", &bytes[i]);
    }
}


// 派生轮密钥
void derive_round_key(unsigned int key, unsigned char *round_key, int length) {

    unsigned int tmp = key;
    for(int i = 0; i < length / 16; i++)
    {
        memcpy(round_key + i * 16,      &tmp, 4);   tmp++;
        memcpy(round_key + i * 16 + 4,  &tmp, 4);   tmp++;
        memcpy(round_key + i * 16 + 8,  &tmp, 4);   tmp++;
        memcpy(round_key + i * 16 + 12, &tmp, 4);   tmp++;
    }
}


// 比特逆序
void reverseBits(unsigned char* state) {
    unsigned char temp[16];
    for (int i = 0; i < 16; i++) {
        unsigned char byte = 0;
        for (int j = 0; j < 8; j++) {
            byte |= ((state[i] >> j) & 1) << (7 - j);
        }
        temp[15 - i] = byte;
    }
    for (int i = 0; i < 16; i++) {
        state[i] = temp[i];
    }
}

//S-Box 16x16
int sBox[16] =
        {
                2, 10, 4, 12,
                1, 3, 9, 14,
                7, 11, 8, 6,
                5, 0, 15, 13
        };

void sBoxTransform(unsigned char* state) {
    for (int i = 0; i < 16; i++) {
        int lo = sBox[state[i] & 0xF];
        int hi = sBox[state[i] >> 4];
        state[i] = (hi << 4) | lo;
    }
}


void leftShiftBytes(unsigned char* state) {
    unsigned char temp[16];
    for (int i = 0; i < 16; i += 4) {
        temp[i + 0] = state[i + 2] >> 5 | (state[i + 1] << 3);
        temp[i + 1] = state[i + 3] >> 5 | (state[i + 2] << 3);
        temp[i + 2] = state[i + 0] >> 5 | (state[i + 3] << 3);
        temp[i + 3] = state[i + 1] >> 5 | (state[i + 0] << 3);
    }
    for (int i = 0; i < 16; i++)
    {
        state[i] = temp[i];
    }
}

void rightShiftBytes(unsigned char* state) {
    unsigned char temp[16];
    for (int i = 0; i < 16; i += 4) {
        temp[i + 0] = (state[i + 3] >> 3) | ((state[i + 2] & 0x07) << 5);
        temp[i + 1] = (state[i + 0] >> 3) | ((state[i + 3] & 0x07) << 5);
        temp[i + 2] = (state[i + 1] >> 3) | ((state[i + 0] & 0x07) << 5);
        temp[i + 3] = (state[i + 2] >> 3) | ((state[i + 1] & 0x07) << 5);
    }
    for (int i = 0; i < 16; i++)
    {
        state[i] = temp[i];
    }
}

// 轮密钥加
void addRoundKey(unsigned char* state, unsigned char* roundKey, unsigned int round) {
    for (int i = 0; i < 16; i++) {
        for (int j = 0; j < 8; j++) {
            state[i] ^= ((roundKey[i + round * 16] >> j) & 1) << j;
        }
    }
}

// 加密函数
void encrypt(unsigned char* password, unsigned int key, unsigned char* ciphertext) {
    unsigned char roundKeys[16 * ROUND] = {}; //

    // 生成轮密钥
    derive_round_key(key, roundKeys, 16 * ROUND);

    // 初始状态为16字节的口令
    unsigned char state[16]; // 初始状态为16字节的密码
    memcpy(state, password, 16); // 初始状态为密码的初始值

    // 迭代加密过程
    for (int round = 0; round < ROUND; round++)
    {
        reverseBits(state);
        sBoxTransform(state);
        leftShiftBytes(state);
        addRoundKey(state, roundKeys, round);
    }

    memcpy(ciphertext, state, 16);
}

int rev[256] = {34,42,36,44,33,35,41,46,39,43,40,38,37,32,47,45,162,170,164,172,161,163,169,174,167,171,168,166,165,160,175,173,66,74,68,76,65,67,73,78,71,75,72,70,69,64,79,77,194,202,196,204,193,195,201,206,199,203,200,198,197,192,207,205,18,26,20,28,17,19,25,30,23,27,24,22,21,16,31,29,50,58,52,60,49,51,57,62,55,59,56,54,53,48,63,61,146,154,148,156,145,147,153,158,151,155,152,150,149,144,159,157,226,234,228,236,225,227,233,238,231,235,232,230,229,224,239,237,114,122,116,124,113,115,121,126,119,123,120,118,117,112,127,125,178,186,180,188,177,179,185,190,183,187,184,182,181,176,191,189,130,138,132,140,129,131,137,142,135,139,136,134,133,128,143,141,98,106,100,108,97,99,105,110,103,107,104,102,101,96,111,109,82,90,84,92,81,83,89,94,87,91,88,86,85,80,95,93,2,10,4,12,1,3,9,14,7,11,8,6,5,0,15,13,242,250,244,252,241,243,249,254,247,251,248,246,245,240,255,253,210,218,212,220,209,211,217,222,215,219,216,214,213,208,223,221};
int rev_map[256];

void sBoxReverse(unsigned char* state) {
    for (int i = 0; i < 16; i++) {
        state[i] = rev_map[state[i]];
    }
}

// 解密函数
void decrypt(unsigned char* ciphertext, unsigned int key, unsigned char* plaintext) {
    unsigned char roundKeys[16 * ROUND] = {}; //

    // 生成轮密钥
    derive_round_key(key, roundKeys, 16 * ROUND);

    // 初始状态为16字节的密文
    unsigned char state[16]; // 初始状态为16字节的密文
    memcpy(state, ciphertext, 16); // 初始状态为密文

    // 迭代解密过程
    for (int round = ROUND - 1; round >= 0; round--)
    {
        addRoundKey(state, roundKeys, round);
        rightShiftBytes(state);
        sBoxReverse(state);
        reverseBits(state);
    }

    memcpy(plaintext, state, 16);
}

int checkSame(unsigned char a[16], unsigned char b[16]) {
    for (int i = 0; i < 16; i++)
        if (a[i] != b[i]) return 0;
    return 1;
}

int main() {
    unsigned char password[] = "pwd:xxxxxxxxxxxx"; // 口令明文固定以pwd:开头，16字节的口令
    unsigned int key = 0xFAB7C4D9; // 4字节的密钥
    unsigned char byte[] = "99F2980AAB4BE8640D8F322147CBA409";
    unsigned char ciphertext[] = "\x99\xF2\x98\x0A\xAB\x4B\xE8\x64\x0D\x8F\x32\x21\x47\xCB\xA4\x09";
    unsigned char state[] = "\x99\xF2\x98\x0A\xAB\x4B\xE8\x64\x0D\x8F\x32\x21\x47\xCB\xA4\x09";
    leftShiftBytes(state);
    rightShiftBytes(state);
    
    if(checkSame(state, ciphertext) == 1)
        puts("OK");

    for (int i = 0; i <= 255; i++)
        rev_map[rev[i]] = i;

    sBoxTransform(state);
    sBoxReverse(state);

    if(checkSame(state, ciphertext) == 1)
        puts("OK");

    reverseBits(state);
    reverseBits(state);

    if(checkSame(state, ciphertext) == 1)
        puts("OK");

    // printf("%s\n", password);

    encrypt(password, key, state);
    decrypt(state, key, state);

    if(checkSame(state, password) == 1)
        puts("OK");

    // // 输出加密后的结果
    // printf("Decrypted password:\n");
    // decrypt(ciphertext, key, state);
    // for (int i = 0; i < 16; i++) {
    //     printf("%02X", state[i]);
    // }
    // printf("\n");
    unsigned int l, r;
    scanf("%u%u", &l, &r);

    for (unsigned int key = l; key <= r; key++) {
        decrypt(ciphertext, key, password);
        if (password[0] == 'p' && password[1] == 'w' && password[2] == 'd' && password[3] == ':') {
            printf("Password: \n");
            for (int i = 0; i < 16 ; i++)
                printf("%02X", password[i]);
            printf("\n%u\n", key);
            return 0;
        }
        if (key % 1000000 == 0)
            printf("%llu\n", (unsigned long long) key);
    }
    
    return 0;
}
```





