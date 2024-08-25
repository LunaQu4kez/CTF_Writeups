# SekaiCTF 2024

这个比赛感觉难度也比较大，有一些标注低难度的题目实际上并不那么好做，而且出现了较为少见的编程能力题 (PPC) 和区块链题目 (Blockchains)。题目包含的一些文件在[这里](./file)，文件夹名称就是题目名称。

<div align="center">
    <img src=".\pic\01.png" alt="" height="200">
    <img src=".\pic\02.png" alt="" height="200">
</div>



## Misc

### Sanity Check

Welcome to SekaiCTF! Flags will be in format `SEKAI{[\x20-\x7e]+}`.

Please read the [rules](https://ctf.sekai.team/rules). Join our [Discord](https://discord.gg/6gk7jhCgGX) for admin support and challenge updates. Flag is in `#announcement` channel topic.

**Solve:** 

签到题，去官方 Discord 的 `#announcement` 频道的标题就可以看到 flag

<div align="center">
    <img src=".\pic\misc01.png" alt="" width="600">
</div>

flag: `SEKAI{I'm_thinking_Miku,_Miku_(oo-ee-oo)}` 

### Survey

Thank you for playing SekaiCTF. We would love to hear constructive feedback in preparation for next year!

https://forms.gle/oS1UusxGwdyRdC8M9

**Solve:** 

这是个调查问卷，填写完即可获得 flag

<div align="center">
    <img src=".\pic\misc02.png" alt="" width="600">
</div>

flag: `SEKAI{hope_you_enjoyed_&_see_you_next_year!}` 



## PPC (Professional Programming & Coding)

### Miku vs. Machine

Time limit is 2 seconds for this challenge.

**Solve:** 

题意是要给 n 个人安排 m 场演出，每场演出时间相同，每个人的总演出时间也相同，每场演出只可以换一次人。考虑给每个人 m 分钟演出，每场演出 n 分钟，然后贪心的依次安排每个人的演出，代码如下

```python
if __name__ == '__main__':
    t = int(input())
    for _ in range(t):
        n, m = map(int, input().split())  # n people, m shows, n <= m
        print(n)
        rem = m
        for i in range(1, n + 1):
            for _ in range(rem // n):
                print(f"{n} {i} {0} {i}")
            rem = rem % n
            if rem > 0:
                l1 = rem
                l2 = n - rem
                p1 = i
                p2 = i + 1
                rem = m - l2
                print(f"{l1} {p1} {l2} {p2}")
            else:
                rem = m
```



## Crypto

### Some Trick

Bob and Alice found a futuristic version of opunssl and replaced all their needs for doofy wellmen.

```shell
ncat --ssl sometrick.chals.sekai.team 1337
```

**Solve:** 

```python
CIPHER_SUITE = randbelow(2**256)
print(f"oPUN_SASS_SASS_l version 4.0.{CIPHER_SUITE}")
random.seed(CIPHER_SUITE)
```

首先，我们可以通过打印出的第一个信息得到变量 `CIPHER_SUITE` 的值，从而获取随机数的种子

```python
def gen(n):
    p, i = [0] * n, 0
    for j in random.sample(range(1, n), n - 1):
        p[i], i = j, j
    return tuple(p)

G = [gen(GSIZE) for i in range(GNUM)]
```

由于随机数种子确定了，因此 `G` 也是给定的，这里 `G` 是 79 个元组组成的数组，每个元组都是 0 到 8208 的一个随机的排列

```python
FLAG = int.from_bytes(FLAG, 'big')
left_pad = randbits(randbelow(LIM.bit_length() - FLAG.bit_length()))
FLAG = (FLAG << left_pad.bit_length()) + left_pad
FLAG = (randbits(randbelow(LIM.bit_length() - FLAG.bit_length()))
        << FLAG.bit_length()) + FLAG
```

这几行代码对 `FLAG` 进行了混淆，在 `FLAG` 的前面和后面各填充了一些随机的 bit。但是我们只要能够还原出混淆后的 `FLAG`，真正的 `FLAG` 就是混淆后的其中的一段，很容易提取出来

```python
bob_key = randbelow(LIM)
bob_encr = enc(FLAG, bob_key, G)
print("bob says", bob_encr)

alice_key = randbelow(LIM)
alice_encr = enc(bob_encr, alice_key, G)
print("alice says", alice_encr)

bob_decr = enc(alice_encr, bob_key, [inverse(i) for i in G])
print("bob says", bob_decr)
```

紧接着，bob 和 alice 分别生成了随机的密钥，然后连续进行了 3 次加密，最后的 `[inverse(i) for i in G]` 只是改变了下 `G` 中每个 0 到 8208 随机排列元组的排列顺序，并不是本题的关键

```python
def enc(k, m, G):
    if not G:
        return m
    mod = len(G[0])  # 8209
    return gexp(G[0], k % mod)[m % mod] + enc(k // mod, m // mod, G[1:]) * mod
```

加密函数 `enc(k, m, G)` 采用递归的方式进行加密，从最后的 `* mod` 和大量的取模操作可以联想到，这个加密函数可能和进制有关。`gexp(g, e)` 函数也是对 0 到 8208 的排列元组进行一个排序的变化，也不是本题的关键。

注意到变量 `mod` 恒为 8209，假设将要加密的数字 `num` (在函数 `enc(k, m, G)` 中为 `k`) 按照 8209 进制展开为
$$
num=n_0+n_1*mod+n_2*mod^2+...n_{78}*mod^{78}
$$
同样的展开密钥 `key` (在函数 `enc(k, m, G)` 中为 `m`)
$$
key=k_0+k_1*mod+k_2*mod^2+...k_{78}*mod^{78}
$$
假设将递归展开，可以得到以下结论：
$$
num\_enc=\text{gexp}(G[0],n_0)[k_0]+\text{gexp}(G[1],n_1)[k_1]*mod+...+\text{gexp}(G[78],n_{78})[k_{78}]*mod^{78}+mod^{79}
$$
那么我们如果已知 `num_enc` 和 `num`，想要还原 `key`，只需要按照 8209 进制一位一位的还原即可。已知 `num_enc` 和 `key` 还原 `num` 的情况同理。那么连接服务器获取数据，解题代码如下：

```python
import random
from Crypto.Util.number import long_to_bytes

CIPHER_SUITE = 89847518489015284155920560217111058054584374887225341947037035261975012119225
random.seed(CIPHER_SUITE)

GSIZE = 8209
GNUM = 79
LIM = GSIZE ** GNUM


def gen(n):
    p, i = [0] * n, 0
    for j in random.sample(range(1, n), n - 1):
        p[i], i = j, j
    return tuple(p)


def gexp(g, e):
    res = tuple(g)
    while e:
        if e & 1:
            res = tuple(res[i] for i in g)
        e >>= 1
        g = tuple(g[i] for i in g)
    return res


def inverse(perm):
    res = list(perm)
    for i, v in enumerate(perm):
        res[v] = i
    return res


def dec_key(num, num_enc, G):
    key = 0
    mod = GSIZE
    for i in range(GNUM):
        temp = gexp(G[i], num % mod)
        for j in range(GSIZE):
            if temp[j] == num_enc % mod:
                key += j * pow(mod, i)
        num //= mod
        num_enc //= mod
    return key


def dec_msg(num_enc, key, G):
    msg = 0
    mod = GSIZE
    for i in range(GNUM):
        for j in range(GSIZE):
            if gexp(G[i], j)[key % mod] == num_enc % mod:
                msg += j * pow(mod, i)
        key //= mod
        num_enc //= mod
        print("i", i)
    return msg


bob_encr = 1359308786653079220637741867305512960860865752589453065090149063173831306975085023343353274532559811099711160934909093832512825710835214621985885992319293564133133175073479274124359297159480500750949866415871720292698583897629950526217250851117664791827499849088344226528816108827450807834776634432006839298881
alice_encr = 1451205510061878676132089275217519536164088350043137546411531127412638001200494391551168801586487689145572670611564565929899562931029251981015810566035198220943447679316416042779111081749666800888609246165801270127438484964798387351604811367871747631430379269252292500506875398568872708490984654458497738336180
bob_decr = 1169621884875399266973182284517472944010810112581493536960710316600379925761828655760029000300770132563326562191642283273160357878159039606369809410454934703892324558482045884035438513905830275060869074566273580057603086839738891462751594111519384833995386267388214116539214601298657333284621331129280220205997

G = [gen(GSIZE) for i in range(GNUM)]
G_inv = [inverse(i) for i in G]

bob_key = dec_key(alice_encr, bob_decr, G_inv)
print("bob_key", bob_key)
alice_key = dec_key(bob_encr, alice_encr, G)
print("alice_key", alice_key)
FLAG = dec_msg(bob_encr, bob_key, G)
print("flag", long_to_bytes(FLAG))
```

flag: `SEKAI{7c124c1b2aebfd9e439ca1c742d26b9577924b5a1823378028c3ed59d7ad92d1}` 

