# SekaiCTF 2024

The contest also felt more difficult, with some questions labeled as low difficulty that weren't actually that good, and the appearance of the rarer Programming Proficiency Questions (PPCs) and Blockchains questions (Blockchains). Some of the files included in the questions are located [here](. /file), and the name of the folder is the name of the topic.

<div align="center">
    <img src=".\pic\01.png" alt="" height="200">
    <img src=".\pic\02.png" alt="" height="200">
</div>



## Misc

### Sanity Check

Welcome to SekaiCTF! Flags will be in format `SEKAI{[\x20-\x7e]+}`.

Please read the [rules](https://ctf.sekai.team/rules). Join our [Discord](https://discord.gg/6gk7jhCgGX) for admin support and challenge updates. Flag is in `#announcement` channel topic.

**Solve:** 

For sign-in questions, go to the title of the official Discord's `#announcement` channel and you'll see the flag

<div align="center">
    <img src=".\pic\misc01.png" alt="" width="600">
</div>

flag: `SEKAI{I'm_thinking_Miku,_Miku_(oo-ee-oo)}` 

### Survey

Thank you for playing SekaiCTF. We would love to hear constructive feedback in preparation for next year!

https://forms.gle/oS1UusxGwdyRdC8M9

**Solve:** 

This is a questionnaire, fill it out and get flag

<div align="center">
    <img src=".\pic\misc02.png" alt="" width="600">
</div>

flag: `SEKAI{hope_you_enjoyed_&_see_you_next_year!}` 



## PPC (Professional Programming & Coding)

### Miku vs. Machine

Time limit is 2 seconds for this challenge.

**Solve:** 

The problem is to schedule m performances for n people, where each performance has the same duration, each person has the same total performance time, and each person can be replaced only once. Consider giving each person m minutes to perform, n minutes per performance, and then greedily scheduling each person's performance in turn, as follows

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

First, we can get the value of the variable `CIPHER_SUITE` by printing out the first message to get the seed of the random number

```python
def gen(n):
    p, i = [0] * n, 0
    for j in random.sample(range(1, n), n - 1):
        p[i], i = j, j
    return tuple(p)

G = [gen(GSIZE) for i in range(GNUM)]
```

Since the random number seed is determined, `G` is also given, where `G` is an array of 79 tuples, each of which is a random permutation of 0 to 8208.

```python
FLAG = int.from_bytes(FLAG, 'big')
left_pad = randbits(randbelow(LIM.bit_length() - FLAG.bit_length()))
FLAG = (FLAG << left_pad.bit_length()) + left_pad
FLAG = (randbits(randbelow(LIM.bit_length() - FLAG.bit_length()))
        << FLAG.bit_length()) + FLAG
```

These lines of code obfuscate the `FLAG` by filling it with random bits before and after the `FLAG`, but if we can restore the obfuscated `FLAG`, the real `FLAG` is one of the obfuscated bits, and it's easy to extract it.

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

Immediately after that, bob and alice each generate a random key, and then encrypt three times in a row. The final `[inverse(i) for i in G]` just changes the order of each of the tuples of random permutations from 0 to 8208 in `G`, and is not the key to the problem.

```python
def enc(k, m, G):
    if not G:
        return m
    mod = len(G[0])  # 8209
    return gexp(G[0], k % mod)[m % mod] + enc(k // mod, m // mod, G[1:]) * mod
```

The encryption function `enc(k, m, G)` encrypts the tuple recursively, which is probably related to the modulus, as evidenced by the `* mod` at the end and the large number of modulo operations. The `gexp(g, e)` function is also a sorted variation of the 0 to 8208 permutation tuple, and is not the key to the question.

Noting that the variable `mod` is constant 8209, suppose that the number to be encrypted, `num` (`k` in the function `enc(k, m, G)`), is expanded according to the 8209 expansion as follows
$$
num=n_0+n_1*mod+n_2*mod^2+...n_{78}*mod^{78}
$$
The same expansion key `key` (`m` in the function `enc(k, m, G)`)
$$
key=k_0+k_1*mod+k_2*mod^2+...k_{78}*mod^{78}
$$
Assuming that the recursion is expanded, the following conclusion can be obtained:
$$
num\_enc=\text{gexp}(G[0],n_0)[k_0]+\text{gexp}(G[1],n_1)[k_1]*mod+...+\text{gexp}(G[78],n_{78})[k_{78}]*mod^{78}+mod^{79}
$$
So if we know `num_enc` and `num`, and want to restore `key`, we just need to do it one by one according to 8209. If we know `num_enc` and `key`, we can restore `num` by 8209, and then we can do the same for `num_enc` and `key`. Then connect to the server to get the data, the solution code is as follows:

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

