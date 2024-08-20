# idekCTF 2024

这个比赛感觉难度好高，恰好周末没太多时间，签到题之外只做了一个密码题



## sanity/Welcome to idekCTF 2024!

Welcome to idekCTF 2024! Please join our [discord](https://discord.gg/c7w4gKMnAX) for any announcements and updates on challenges.

**Solve:** 

<div align="center">
    <img src=".\pic\01.png" alt="" height="350">
</div>

加入官方 Discord 频道查看公告即可，flag: `idek{our_hack_fortress_team_is_looking_for_mvm_players}` 

## crypto/Golden Ticket

Can you help Charles - who doesn't have any knowledge about cryptography, get the golden ticket and have a trip to Willy Wonka's factory ?

**Solve:** 

```python
def chocolate_generator(m: int) -> int:
    p = ...
    return (pow(13, m, p) + pow(37, m, p)) % p
```

先观察 `chocolate_generator(int)` 这个函数，使用质数 `p` 给输入的 `m` 进行加密

```python
for i in range(golden_ticket):
    chocolate_bag.append(chocolate_generator(i))
chocolate_bag.append(flag_chocolate)
remain = chocolate_bag[-2:]
```

这一段的意思是，已知 `chocolate_bag` 的最后两个元素，即
$$
(13^{m-1}+37^{m-1})\ \text{mod}\ p=a\\
(13^{m}+37^{m})\ \text{mod}\ p=b
$$
其中 $a$, $b$ 已知

对第一个等式进行变形
$$
(13^m+13\cdot 37^{m-1})\ \text{mod}\ p=13a\ \text{mod}\ p
$$
两式相减得
$$
24\cdot 37^{m-1}\ \text{mod}\ p=(b-13a)\ \text{mod}\ p
$$
两边同时乘 24 的模逆元
$$
37^{m-1}\ \text{mod}\ p=\text{invert(24, p)}*(b-13a)\ \text{mod}\ p
$$
使用 python 直接计算，得到一个标准形式的离散对数问题 (DLP)

```python
p = 396430433566694153228963024068183195900644000015629930982017434859080008533624204265038366113052353086248115602503012179807206251960510130759852727353283868788493357310003786807
a = 88952575866827947965983024351948428571644045481852955585307229868427303211803239917835211249629755846575548754617810635567272526061976590304647326424871380247801316189016325247
b = 67077340815509559968966395605991498895734870241569147039932716484176494534953008553337442440573747593113271897771706973941604973691227887232994456813209749283078720189994152242
print(f"37^(m-1) mod p = {invert(24, p)*(b-13*a) % p}")
```

使用 SageMath 即可解出 `m-1` 

```
sage: R = Integers(3964304335666941532289630240681831959006440000156299309820174348590800085336242042650383661130523530862481156025030121798072062519605101307
....: 59852727353283868788493357310003786807)
sage: a = R(37)
sage: b = R(20238126491863160561856801833555874441558426163383040371505001046170090336607808139987729949546550907838970300522022297536146482976221600727793208
....: 8482880826578710915390951613589)
sage: b.log(a)
57629776445896163024735745086814515288454966100802334039751672315837361336412607584713634047210889596
```

最后得到 flag

```python
m = 57629776445896163024735745086814515288454966100802334039751672315837361336412607584713634047210889596 + 1
print(long_to_bytes(m))
```

flag: `idek{charles_and_the_chocolate_factory!!!}`

