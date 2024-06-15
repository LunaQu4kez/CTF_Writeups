# Crypto

密码学



## 编码

### Base

#### Base16

编码表：`0123456789ABCDEF`

本质就是将每个数据的 ASCII 码转换为 16 进制然后拼接

#### Base32

编码表：`ABCDEFGHIJKLMNOPQRSTUVWXYZ234567`，`=` 是填充符

先把要编码的文本根据 ASCII 转化成每个字符 8 位的二进制串，然后 5 bit 一组每次 8 组进行划分，填充位用 `=` 

比如，文本 abc 进行编码，其二进制为 011000010110001001100011

每 5 bit 一组分组：01100 00101 10001 00110 0011

每次要有 8 组，进行补 0：01100 00101 10001 00110 00110 00000 00000 00000

转化为 10 进制并对应到编码表，但注意，最后 3 组 0 全是填充，因此不对应到 `A` 而是对应到 `=`，结果：MFRGG===

#### Base64

编码表：`ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/` ，`=` 是填充符

加密方式与 Base32 类似，但 6 bit 一组每次 4 组进行划分

#### Base85

也叫做 ASCII85，它用 5 个字符表示 4 字节

先将 4 字节的二进制数转化成 85 进制，然后每一位对应的值加上 32 转为字符

比如，sure 进行编码，二进制为：01110011011101010111001001100101

10 进制是 1937076837，转化为 85 进制：37, 9, 17, 44, 22

再把每一位加上 32 转成字符：F*2M7



### URL

略

### Base64 URLsafe

传统 Base64 中的 + / 会被 URL 转义，因此用 - _ 替代 Base64 中的 + / 两个字符

### XXencode

编码过程和 Base64 一样，但是使用 `+-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz` 为码表，并且填充符就是 `+` 

### Uuencode

和 Base64 编码方式类似，但是每次 4 组每组 6 bit 划分之后，每个数加 32，刚好在 ASCII 可打印字符内，不需要额外码表

### jjencode

将 js 代码转化成只有符号的字符串

### aaencode

将 js 代码转化成颜文字





## 古典密码学

### 单表替换密码

#### 凯撒密码 Caesar Cipher

$$
E_k(x)=(x+k)\mod{26} \\
D_k(x)=(x-k)\mod{26}
$$

当不知道 $k$ 时，可以遍历一边，找到有意义的解密结果

注意，可能有不仅仅基于 26 个英文字母进行移位，而是基于 ASCII 码表进行移位的变异版凯撒

#### Atbash 密码

也是一种单表替换密码

明文：ABCDEFGHIJKLMNOPQRSTUVWXYZ

密文：ZYXWVUTSRQPONMLKJIHGFEDCBA

#### 摩斯密码

<div align="center">
    <img src=".\pic\crypto01.png" alt="" width="400">
</div>

#### 仿射密码

$$
E(x)=(ax+b)\mod{26} \\
D(x)=a^{-1}(x-b)\mod{26}
$$

这里 $a^{-1}$ 是指 $a$ 在模 26 意义下的逆元



### 多表替换密码

 #### 维吉尼亚密码 Viegenere

<div align="center">
    <img src=".\pic\crypto02.png" alt="" width="500">
</div>

例如，明文：there is a cipher，密钥：password

首先将明文和密钥对齐，thereisacipher，passwordpasswo，然后一位一位去密码表上对应，得到密文：ihwjawjdrihzaf

#### 普莱菲尔密码 Playfair

加密对象：字母

该密码的特征时密文的字母数一定是偶数，并且两个同组的字母不会相同，如果出现这种字符一定是乱码或者虚码

首先该密码需要秘钥，然后由秘钥制作相应的密码表。秘钥去重后，将秘钥依次填入 5 x 5 表格(先填纵列)，剩下的格子按 a - z 依次填入，如果前面遇到秘钥中的字母就跳过，将 i 和 j 放在同一个格子。比如：秘钥是 hello，去掉重复字母变成 helo，填成的密码表为：

|      | 1    | 2    | 3    | 4    | 5    |
| ---- | ---- | ---- | ---- | ---- | ---- |
| 1    | h    | b    | i/j  | q    | v    |
| 2    | e    | c    | k    | r    | w    |
| 3    | l    | d    | m    | s    | x    |
| 4    | o    | f    | n    | t    | y    |
| 5    | a    | g    | p    | u    | z    |

在构建好密码表后，将待加密的明文分为两个一组，同时要保证每组的两个字符不相同，如果相同，则在其中间插入一个 x 再进行分组。如果最后还剩一个字母，则添加一个 x

分好组后，依次拿出每个组，根据密码表对其加密，加密规则如下:

- 如果该组的两个字符在密码表的同一行，则密文分别是其紧靠着的右边这个字符。其中第一列被看做是最后一列的右方。

- 如果该组的两个字符在密码表的同一列，则密文分别是其紧靠着的下边这个字符。之中第一行被看做是最后一行的下方。
- 如果该组的两个字符即不再同一行，又不在同一类，则密文是其组成的长方形的另外两个顶点（至于横向替换还是纵向替换，统一即可）

比如明文是 test with playfair cipher，两两分组，te st wi th pl ay fa ir ci ph er，按照上述规则替换之后，得到密文 ortukvoqamzogokqkbaicw

#### 希尔密码 Hill

每个字母当作一个 26 进制数字，一个字符串当作一个 n 维向量，跟一个 n × n 的矩阵相乘，再将结果向量模 26，注意用于加密作用的矩阵必须在 $Z_{26}^n$ 下可逆

例如，明文：act，密钥：$\left[\begin{array}{c}6 & 24 & 1 \\13 & 16 & 10\\20 & 17 & 15\end{array}\right]$

加密：
$$
\left[\begin{array}{c}6 & 24 & 1 \\13 & 16 & 10\\20 & 17 & 15\end{array}\right]
\left[\begin{array}{c}0 \\2\\19\end{array}\right] = 
\left[\begin{array}{c}15 \\14\\17\end{array}\right] (mod\,\,26)
$$
对应的密文是 poh，找到逆矩阵相乘即可解密

#### 自动密钥密码

和维吉尼亚密码类似，但生成密钥的方式不同

比如，明文：test with autokey cipher，密钥：hello，那么生成的密钥是：hello test with autokey c

最后使用和维吉尼亚密码一样的加密：aidekbxztqbhresvwzlct

#### 培根密码

| A = aaaaa | I/J = abaaa | R = baaaa   |
| --------- | ----------- | ----------- |
| B = aaaab | K = abaab   | S = baaab   |
| C = aaaba | L = ababa   | T = baaba   |
| D = aaabb | M = ababb   | U/V = baabb |
| E = aabaa | N = abbaa   | W = babaa   |
| F = aabab | O = abbab   | X = babab   |
| G = aabba | P = abbba   | Y = babba   |
| H = aabbb | Q = abbbb   | Z = babbb   |

#### 栅栏密码

把要加密的明文分为 n 个一组，把每组的第 1 个，第 2 个，... 分别取出来拼在一起

比如，明文为 a test with railfence cipher，去掉空格 atestwithrailfencecipher

如果选择三栏加密，三个分为一组，ate stw ith rai lfe nce cip her

取出每组的第 1 个，第 2 个，第 3 个拼在一起：asirlnch，tttafcie，ewhieepr，拼在一起得到 asirlnchtttafcieewhieepr

#### 曲路密码

略

#### 猪圈密码

<div align="center">
    <img src=".\pic\crypto03.png" alt="" width="400">
</div>

#### 跳舞的小人

<div align="center">
    <img src=".\pic\crypto04.png" alt="" width="400">
</div>

#### 键盘密码

略









