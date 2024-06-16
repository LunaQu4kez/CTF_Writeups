# Crypto

密码学

[TOC]



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





## 现代密码学

概念：非对称加密，公钥，密钥



### RSA

1) 选取不相等的大质数 $p$，$q$，计算 $N=pq$ 
2) 根据欧拉函数求 $r=\phi(N)=(p-1)(q-1)$ 
3) 选择一个小于 $r$ 且和 $r$ 互质的整数 $e$，求 $e$ 关于 $r$ 的模逆元，记为 $d$，即 $ed \equiv 1(mod\,\,r)$ 
4) 销毁 $p$ 和 $q$ 的记录

假设要加密的明文是 $n$，那么密文 $c\equiv n^e(mod\,\,N)$，接收到密文 $c$ 后，解密明文 $n\equiv c^d(mod\,\,N)$ 

RSA 也可以为一个消息进行签名，防止消息在传播过程中被篡改。发消息者可以为消息计算一个 Hash 值加在消息后面，再用 RSA 加密，接收者将密文解密，并将自己计算的 Hash 值做对比，判断有没有被篡改消息。



### RSA 基础攻击

#### 因数分解

$N$ 较小 (一般是小于 512 bit) 时，可以尝试直接分解 $N$ 

可以使用 factordb 或 yafu

```python
from gmpy2 import *

p = ...
q = ...
c = ...
e = ...

d = invert(e, (p-1)*(q-1))
m = powmod(c, d, p*q)

print(m)
```

#### 共享素数

同时生成了多个公钥，如果生成的公钥中有两组 $N$ 使用了相同的素数，即如果能找到两个不互素的 $N$，那么可以求它们的最大公因数得到 $p$, $q$，从而破解 RSA 加密

```python
from gmpy2 import *

e = ...
n1 = ...
n2 = ...
c1 = ...
c2 = ...

p = gcd(n1, n2)
q = n1 // p

d = invert(e, (p-1)*(q-1))
m = powmod(c1, d, n1)

print(m)
```

#### 低指数加密攻击 (小明文攻击)

公钥中 $e$ 获得明文 $m$ 足够小，以至于加密时得到的值 $m^e$ 小于 $N$，这样对 $N$ 取模结果不变，那么可以直接对密文进行开根，得到明文

```python
from gmpy2 import *

e = ...
c = ...

print(iroot(c, e)[0])
```

#### p, q 很接近

这种情况下，枚举 $\sqrt{N}$ 附近的数

```python
from gmpy2 import *

n = ...
c = ...
e = ...
sqr = iroot(n, 2)[0]
for i in range(10000):
	if n % (sqr + i) == 0:
		p = sqr + i
		q = n // p
		break
d = invert(e, (p-1)*(q-1))
print(powmod(c, d, n))
```

#### 共模攻击

两组公钥使用**相同模数 $N$**，不同的私钥对**同一组明文**进行加密时，且两组公钥使用的 $e$ 是互素的，可以通过共模攻击求解明文

若有
$$
\begin{cases}
gcd(e_1,e_2)=1\\
c_1 \equiv m^{e_1}(mod\,\,N)\\
c_2 \equiv m^{e_2}(mod\,\,N)
\end{cases}
$$
那么由 Bezout 定理，方程 $xe_1+ye_2=1$ 有整数解，假设为 $(s_1,s_2)$，那么有
$$
(c_1^{s_1}\cdot c_2^{s_2})mod\,\,N=m\,mod\,\,N
$$
其中，$(s_1,s_2)$ 可以用欧几里得算法求解，这样可以在不知道 $d$ 的情况下求解明文 $m$.

```python
from gmpy2 import *

e1 = ...
e2 = ...
n = ...
c1 = ...
c2 = ...

s = gcdext(e1, e2)
s1 = s[1]
s2 = s[2]
print(powmod(c1, s1, n) * powmod(c2, s2, n) % n)
```

#### 低指数加密广播攻击

多组公钥加密同一消息且公钥中加密指数 $e$ 相同
$$
\begin{cases}
c_1 \equiv m^{e_1}(mod\,\,n_1)\\
c_2 \equiv m^{e_2}(mod\,\,n_2)\\
...\\
c_k \equiv m^{e_k}(mod\,\,n_k)\\
\end{cases}
$$
由中国剩余定理，有通解 $m^e=\sum\limits_{i=1}^{k}c_it_iM_i\ mod\ n$，其中 $N=n_1\cdot n_2\cdot ...\cdot n_k$，$M_i=\frac{N}{n_i}$，$M_it_i\equiv 1(mod \ n_i)$ 

对通解 $m^e$ 开根即可

```python
from gmpy2 import *

e = ...
n_list = [...]
c_list = [...]
N = 1
for n in n_list:
    N *= n
M_list = []
for n in n_list:
    M_list.append(N//n)
t_list = []
for i in range(len(n_list)):
    t_list.append(invert(M_list[i], n_list[i]))
summary = 0
for i in range(len(n_list)):
    summary = (summary + c_list[i] * t_list[i] * M_list[i]) % N
m = iroot(summary, e)[0]
print(m)
```

#### Wiener 攻击 (连分数攻击)

在 $d$ 较小时获得私钥 $d$，因此也被称为低解密指数攻击

在 RSA 中，有
$$
\phi(N)=(p-1)(q-1)=N-(p+q)+1\approx N
$$
因为
$$
ed \equiv 1(mod\ \phi(N))
$$
那么有
$$
ed-1=k\phi(N)
$$
同时除以 $d\phi(N)$ 有
$$
\frac{e}{\phi(N)}-\frac{k}{d}=\frac{1}{d\phi(N)}
$$
用 $N$ 替换 $\phi(N)$
$$
\frac{e}{N}-\frac{k}{d}=\frac{1}{dN}\approx0
$$

$$
\frac{e}{N}\approx\frac{k}{d}
$$

对于等式左边的数，可以将其展开为连分数，再遍历每一组近似解，有可能找到等式右边的值

假设一组解为 $(d,k)$ ，那么有
$$
\phi(N)=\frac{ed-1}{k}
$$
即
$$
p+q=N-\phi(N)+1
$$
这样可以计算出 $p$, $q$ ，验算 $pq=N$ 即可验证 $d$ 是否正确

但是，Wiener 攻击并不是每次都有效，需要满足以下条件：
$$
q<p<2q  \ \ \text{and} \ \ d<\frac{1}{3}N^{\frac{1}{4}}
$$

```python
from gmpy2 import *


class ContinuedFraction():
    def __init__(self, numerator, denumerator):
        self.numberlist = []
        self.fractionlist = []
        self.GenerateNumberlist(numerator, denumerator)
        self.GenerateFractionlist()
        return

    def GenerateNumberlist(self, numerator, denumerator):
        while numerator != 1:
            quotient = numerator // denumerator
            remainder = numerator % denumerator
            self.numberlist.append(quotient)
            numerator = denumerator
            denumerator = remainder
        return

    def GenerateFractionlist(self):
        self.fractionlist.append([self.numberlist[0], 1])
        for i in range(1, len(self.numberlist)):
            numerator = self.numberlist[i]
            denumerator = 1
            for j in range(i):
                temp = numerator
                numerator = denumerator + numerator * self.numberlist[i - j - 1]
                denumerator = temp
            self.fractionlist.append([numerator, denumerator])
        return


n = ...
e = ...
c = ...
a = ContinuedFraction(e, n)
for k, d in a.fractionlist:
    s = powmod(c, d, n)
    try:
        print(s.decode())
    except Exception:
        pass
```

#### Rabin 攻击

Rabin 是一种与 RSA 类似但不是单射的加密方式，一个密文能解出 4 个明文，最终根据哪个有意义来决定明文是什么

取两个大素数 $(p,q)$ 满足 $p\equiv q\equiv 3(mod\ 4)$ 

加密：
$$
c= m^2(mod\ n)
$$
解密：求解
$$
m^2 \equiv c(mod \ n)
$$
由于 $p,q|n$，相当于求解
$$
\begin{cases}
m^2 \equiv c(mod\ p)\\
m^2 \equiv c(mod\ q)
\end{cases}
$$
对于 $m^2 \equiv c(mod\ p)$ 来说，$c$ 是模 $p$ 的二次剩余，即 $c^{\frac{p-1}{2}}\equiv 1(mod\ p)$ 

带入原式
$$
m^2\equiv c \equiv c^{\frac{p-1}{2}}\cdot c\equiv c^{\frac{p+1}{2}}(mod\ p)
$$
开方得
$$
\begin{cases}
m_1 \equiv c^{\frac{p+1}{4}}(mod\ p)\\
m_2 \equiv (p-c^{\frac{p+1}{4}})(mod\ p)
\end{cases}
$$
同理解出另外一式得出 $(m_3, m_4)$ 

当 RSA 使用 $e=2$，同时 $p$, $q$ 满足上述约束时，可以使用 Rabin 算法解密

**注意**：此时已知 $p$, $q$，但不能直接求出 $d$. 因为 $p\equiv q\equiv 3(mod\ 4)$ ，有
$$
\phi(N)=(p-1)(q-1)=(2k_1+2)(2k_2+2)
$$
有 $4|\phi(N)$，所以 $e$ 和 $\phi(N)$ 不互素，无法求出 $d$ 

```python
from gmpy2 import *

p = ...
q = ...
c = ...
n = p * q

c1 = powmod(c, (p+1)//4, p)
c2 = powmod(c, (q+1)//4, q)
cp1 = p - c1
cp2 = q - c2

t1 = invert(p, q)
t2 = invert(q, p)

m1 = (q*c1*c2 + p*c2*t1) % n
m2 = (q*c1*t2 + p*cp2*t1) % n
m3 = (q*cp1*t2 + p*c2*t1) % n
m4 = (q*cp1*t2 + p*cp2*t1) % n

print(m1)
print(m2)
print(m3)
print(m4)
```

#### $d_p$, $d_q$ 泄露攻击

$$
d_p=d\ mod(p-1)\\
d_q=d\ mod(q-1)
$$

上述方程本用于快速解密，但如果泄露，就可能被破解。

已知 $d_p$, $d_q$, $p$, $q$, $c$，在不知道 $e$ 的情况下，也可以求解明文
$$
\begin{cases}
m_1 \equiv c^d(mod\ p)\\
m_2 \equiv c^d(mod\ q)
\end{cases}
$$
根据欧拉降幂，得
$$
\begin{cases}
m_1 \equiv c^{d_pmod(p-1)}(mod\ p)\\
m_2 \equiv c^{d_qmod(q-1)}(mod\ q)
\end{cases}
$$
将 $c^d=kp+m_1$ 带入 $m_2$，得
$$
m_2\equiv (kp+m_1)mod \ q
$$
两边同时减去 $m_1$，得
$$
(m_2-m_1)\equiv kp(mod\ q)\\
(m_2-m_1)p^{-1}\equiv k(mod\ q)
$$
因为明文是小于 $N=pq$ 的，所以 $k$ 一定小于 $q$，所以有 $k=(m_2-m_1)p^{-1}\ mod\ q$，代入之前的 $c^d$ 式子，得
$$
m=c^d=((m_2-m_1)p^{-1}\ mod\ q)p+m_1
$$

```python
from gmpy2 import *

p = ...
q = ...
dp = ...
dq = ...
c = ...

invp = invert(p, q)
m1 = powmod(c, dp, p)
m2 = powmod(c, dq, q)
m = (((m2 - m1) * invp) % q) * p + m1
print(m)
```

#### $d_p$ 泄露攻击

当 $d_p$, $d_q$ 之一发生泄漏，同时知道公钥，也可能从中获得 $d$ 

由 $d_p=d\ mod(p-1)$ 有 $d=k_1(p-1)+d_p$ 
$$
ed=k_1e(p-1)+d_pe\\
ed\equiv 1(mod\ \phi(n))\\
k_1e(p-1)+d_pe=k_2\phi(n)+1
$$
已知，
$$
\phi(n)=(p-1)(q-1)
$$
代入得
$$
ed_p=[k_2(q-1)-k_1e](p-1)+1
$$
已知 $d_p<p-1$，当 $[k_2(q-1)-k_1e](p-1)=e$ 时，等式左边小于右边，所以可以记 $X=[k_2(q-1)-k_1e]$ 

然后遍历 $X\rightarrow [1,e]$，一定存在某个值使得等式成立，同时求得 $N$ 的因子 $p$ 

```python
from gmpy2 import *

dp = ...
e = ...
n = ...
c = ...

for x in range(1, e):
    if (e * dp - 1) % x == 0:
        p = (e * dp - 1) // x + 1
        if n % p == 0:
            q = n // p
            d = invert(e, (p-1)*(q-1))
            m = powmod(c, d, n)
            print(m)
```















