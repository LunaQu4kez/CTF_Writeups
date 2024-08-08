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

m = hex(m)[2:]
flag = ''
for i in range(len(m)//2):
    flag += chr(int(m[i*2:(i+1)*2], 16))
print(flag)
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



### RSA 进阶攻击

#### Schemit Samoa 密码体系

选取大整数 $p$, $q$，计算 $N=p^2q$ 作为公钥，计算 $dN\equiv 1(mod\ \phi(pq))$ 作为私钥

加密过程：对于小于 $N$ 的明文 $m$ 
$$
c=m^N\ mod\ N
$$
解密过程：
$$
m=c^d\ mod\ pq
$$

```python
phi = (p-1)*(q-1)
d = invert(p*p*q, phi)
print(powmod(c, d, p*q))
```

#### p-1 光滑攻击

光滑数是指可以分解为小素数乘积的正整数

当 $p$ 是 $N$ 的因数，并且 $p-1$ 是光滑数时，可以考虑使用 Pollard's $p-1$ 算法来分解 $N$ 

根据费马小定理，若 $a$ 不是 $p$ 的倍数，则
$$
a^{p-1}\equiv1(mod\ p)
$$
则有
$$
a^{t(p-1)}\equiv1^t\equiv1 (mod\ p)
$$
即
$$
a^{t(p-1)}-1=kp
$$
根据 Pollard's $p-1$ 算法，如果 $p$ 是一个 B-smooth number，则存在
$$
M=\prod\limits_{primes\ q\le B}q^{[\log_qB]}
$$
使得 $(p-1)|M$ 成立，则有 $gcd(a^M-1,N)$ ，如果结果不为 $1$ 或 $N$，那么就已成功分解 $N$ 

因为只关心最后的最大公因数，同时 $N$ 只包含两个素因子，所以不需要计算 $M$，考虑 $n=2, 3, ...$，令 $M=n!$ 即可覆盖正确的 $M$ 

具体计算中，代入降幂公式进行快速计算
$$
a^{n!}mod\ N =
\begin{cases}
(a\ mod\ N)^2\ mod \ N & n=2\\
(a^{(n-1)!}mod\ N)mod\ N & n\ge3
\end{cases}
$$

```python
from gmpy2 import *

a = 2
n = 2
N = ...
while True:
    a = powmod(a, n, N)
    res = gcd(a-1, N)
    if res != 1 and res != N:
        q = N // res
        print(res, q, res*q == N)
        break
    n += 1
```



### ElGamal 算法

Elgamal 加密算法可以定义在任何循环群 G 上，它的安全性是基于循环群上的离散对数难题

**公钥和私钥的生成：** 

1. 选取足够大的素数 $p$ 
2. 选取生成元 $g$ 产生一个 $q$ 阶循环群 $G$ 
3. 随机选取满足 $1 \le k \le p-1$ 的整数 $k$，并计算 $g^k\equiv y(mod\ p)$ 

其中私钥为 $(k)$，公钥为 $(G,p,g,y)$ 

**加密：** 

发送消息的明文为 $n$，需要先选取一个随机数 $r\in\{1,...,q-1\}$，将消息 $n$ 映射到循环群 $G$ 上的元素 $m$，加密方式为
$$
y_1\equiv g^r(mod\ p)\\
y_2\equiv my^r(mod\ p)
$$
其中，$(y_1,y_2)$ 为密文

**解密：** 
$$
y_2(y_1^k)^{-1}\equiv m(g^{kr})(g^{rk})^{-1}\equiv m(mod\ p)
$$


### ECC 算法

ECC 全称为椭圆曲线加密，安全性取决于椭圆曲线离散对数问题的困难性，一般使用 $y^2=x^3+ax+b\ \ (4a^2+27b^2\ mod\ p \neq 0)$ 作为 ECC 的椭圆曲线方程

将方程所有解 $(x,y)$ 和一个无穷远点 (O) 组成的集合记为 $E$ 

定义此集合的加法，设点 $P$, $Q$，作 $P$ 的切线交椭圆曲线于点 $R$，过 $R$ 作 y 轴平行线交椭圆曲线于点 $Q$，则有 $P+R=Q$ ，显然此集合及其加法运算形成一个阿贝尔群

定义此集合的乘法，定义 $Q=mP=P+P+...+P$ 

假设 $G$ 为该集合的生成元，则其阶 $n$ 为满足 $nG=O$ 的最小正整数

显然，当知道 $n$ 和 $G$ 时，求出 $nG$ 是很简单的，但是知道 $O$ 和 $G$，求出 $n$ 却很难

**公钥密钥生成：** 

选择椭圆曲线 $E_p(a,b)$，选择一个生成元 $G$，假设为 $n$ 阶，再选择一个正整数 $n_a$ 作为密钥，计算 $P=n_aG$ 

其中，$E_p(a,b)$ 和 $G$ 会被公开，公钥为 $P$，密钥为 $n_a$ 

**加密：**

首先将文本消息 $m$ 编码为椭圆上的一个点 $m$，然后在区间 $(1,q-1)$ 取随机数 $k$，计算 $(x_1,y_1)=kG$，$(x_2,y_2)=kP$，记 $m+(x_2,y_2)$ 为 $C$，最终密文为 $[(x_1,y_1),C]$

**解密：**

计算 $n_a(x_1,y_1)=n_akG=kP=(x_2,y_2)$，此时明文 $m=C-(x_2,y_2)$ 

```python
a = 1234577
b = 3213242
n = 7654319
E = EllipticCurve(GF(n), [0, 0, 0, a, b])
base = E(5234568, 2287747)
pub = E(2366653, 1424308)
c1 = E(5081741, 6744615)
c2 = E(610619, 6218)
X = base
for i in range(1, n):
    if X == pub:
        secret = i
        print("[+] secret:", i)
        break
    else:
        X += base
m = c2 - (c1 * secret)
print("[+] x:", m[0])
print("[+] y:", m[1])
print("[+] x+y:", m[0]+m[1])
```



### AES

AES 为分组密码，分组密码也就是把明文分成一组一组的，每组长度相等，每次加密一组数据，直到加密完整个明文

在 AES 标准规范中，分组长度只能是 128 位，也就是说，每个分组为 16 个字节 (每个字节 8 bit)，密钥的长度可以使用 128 位、192 位或 256 位。密钥的长度不同，推荐加密轮数也不同。

| AES     | 密钥长度 (32 位比特字) | 分组长度 (32 位比特字) | 加密轮数 |
| ------- | ---------------------- | ---------------------- | -------- |
| AES-128 | 4                      | 4                      | 10       |
| AES-192 | 6                      | 4                      | 12       |
| AES-256 | 8                      | 4                      | 14       |

每一轮迭代有 4 个步骤：

1. AddRoundKey：轮密钥加，矩阵中每个字节都会和该密钥做异或运算，每个子密钥由密钥生成方案产生
2. SubBytes：字节替换，通过 S 盒将每个字节替换成对应字节
3. ShiftRows：行置换，将矩阵中的每个横列进行循环式移位
4. MixColumns：列混淆，将每一列进行一个线性运算，最后一轮循环由 AddRoundKey 取代



### 分组模式

#### ECB 电子密码本模式

一个明文分组加密成一个密文分组，最大的缺点是同样的明文块会被加密成相同的密文块，不能很好地保证数据的机密性

加密：用相同的 key 将分好组的明文进行加密函数加密

<div align="center">
    <img src=".\pic\crypto05.png" alt="" width="500">
</div>


解密：使用相同的 key 将明文通过解密函数解密

<div align="center">
    <img src=".\pic\crypto06.png" alt="" width="500">
</div>

#### CBC 密码分组链接模式

每一个分组要先和前一个分组加密后的数据进行**异或操作**，然后再进行加密。为保证每条消息都具有唯一性，第一个数据块加密之前需要用初始化向量 $IV$ 进行异或操作

缺点是，加密是连续的，不能并行化处理，并且与 EBC 一样消息快必须填充到块大小的整数倍

##### CRC 字节翻转攻击

CBC 加密时，若修改 $IV$ 值或某一组密文，其后的那一组明文也将被修改

例：解密时密文第一块的 $c_1$，首先时使用密钥 $key$ 解密得到密文 $c_1'$，然后异或 $IV$ 得到明文 $m_1$，假设 $m_1$ 为 hellocbc，有
$$
D_k(c_1)\oplus IV=m_1=hellocbc
$$
修改 $IV$ 的值，使得
$$
IV'=IV\oplus hellocbc \oplus cbchello
$$
则有
$$
D_k(c_1)\oplus IV'=D_k(c_1)\oplus IV\oplus hellocbc \oplus cbchello = cbchello
$$
这样通过修改 $IV$ 的值，使得到的明文变为 $cbchello$ 

#### CFB 密文反馈模式

在 CFB 模式中，前一个密文分组会被送回到密码算法的输入端。所谓反馈，这里指的就是返回输入端的意思。

在 ECB 模式和 CBC 模式中，明文分组都是通过密码算法进行加密的，但在 CFB 模式中，明文分组并没有通过密码算法来直接进行加密。在 CFB 模式中，明文分组和密文分组之间只有一个 XOR

在生成第一个密文分组时，由于不存在前一个输出的数据，因此需要使用初始化向量 $IV$ 来代替，与 CBC 模式相同。

加密：

<div align="center">
    <img src=".\pic\crypto07.png" alt="" width="500">
</div>

解密：

<div align="center">
    <img src=".\pic\crypto08.png" alt="" width="500">
</div>


### 伪随机数

MT19937 梅森旋转算法，可以在 $[0,2^{k-1}]$ 的区间生成离散型均匀分布的随机数，一些语言 (R、Python、Ruby、PHP) 默认的伪随机数生成器，Python 代码如下

```python
def _int32(x):
    return int(0xFFFFFFFF & x)


class MT19937:
    # 根据seed初始化624的state
    def _init_(self, seed):
        self.mt = [0] * 624
        self.mt[0] = seed
        self.mti = 0
        for i in range(1, 624):
            self.mt[i] = _int32(1812433253 * (self.mt[i - 1] ^ self.mt[i - 1] >> 30) + i)

    # 提取伪随机数
    def extract_number(self):
        if self.mti == 0:
            self.twist()
        y = self.mt[self.mti]
        y = y ^ y >> 11
        y = y ^ y << 7 & 2636928640
        y = y ^ y << 15 & 4022730752
        y = y ^ y >> 18
        self.mti = (self.mti + 1) % 624
        return _int32(y)
    
    def twist(self):
        for i in range(0, 624):
            y = _int32((self.mt[i] & 0x80000000) + (self.mt[(i + 1) % 624] & 0x7fffffff))
            self.mt[i] = (y >> 1) ^ self.mt[(i + 397) % 624]
            if y % 2 == 0:
                self.mt[i] = self.mt[i] ^ 0x9908b0df
```

`MT19937(seed).extract_number()` 会返回随机数，Python 的 Random 类采用的就是这个方法。当获取足够多的随机数时，就可以对这个算法进行逆向，从而能够向前恢复随机数或向后预测随机数

```python
from random import Random


def inverse_right(res, shift, bits=32):
    tmp = res
    for i in range(bits // shift):
        tmp = res ^ tmp >> shift
    return tmp


def inverse_left_mask(res, shift, mask, bits=32):
    tmp = res
    for i in range(bits // shift):
        tmp = res ^ tmp << shift & mask
    return tmp


def inv_extract_number(y):
    y = inverse_right(y, 18)
    y = inverse_left_mask(y, 15, 4022730752)
    y = inverse_left_mask(y, 7, 2636928640)
    y = inverse_right(y, 11)
    return y


def recover_mt(record):
    """
    恢复624个state，即可预测后面的随机数
    :param record: 624个随机数
    :return: 
    """
    state = [inv_extract_number(i) for i in record][:624]
    gen = Random()
    gen.setstate((3, tuple(state + [0]), None))
    return gen
```



### LCG

LCG (Linear Congruential Generators, 线性同余生成器) 是一种产生伪随机数的方法，根据递推公式产生随机数
$$
S_{i+1}=(aS_i+b)\mod m
$$
其中，$a,b,m$ 是生成器设定的常数。这一类 LCG 题目，通常是给出部分常数或者连续的随机数，需要对之后的随机数做预测或是恢复种子。



### 哈希函数

哈希函数是一种从任何一种数据中创建小的数字指纹的方法，哈希函数把消息压缩成摘要，使得数据量变小。现在常用哈希函数来记录用户的密码、判断文件是否受损等。

常见的哈希函数有 MD2、MD4、MD5、SHA1、SHA256 等

一个良好的哈希函数应该具备以下特点：

- 数据长度可以变，可以应用于任意长度的数据
- 输出长度固定，哈希函数的输出长度应该固定
- 效率高，对于消息 $m$，能够快速计算出 $H(m)$ 
- 单向性，对于哈希值 $h$，很难找到 $m$ 使得 $H(m)=h$ 
- 抗弱碰撞性，对于任意消息 $x$，很难找到另一消息 $y$ 使得 $H(x)=H(y)$ 
- 抗强碰撞性，很难找到任意一对满足 $H(x)=H(y)$ 
- 伪随机性，哈希函数的输出应满足伪随机性测试标准

#### 哈希长度扩展攻击

略



### 国密算法

略

