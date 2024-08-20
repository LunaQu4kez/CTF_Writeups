# idekCTF 2024

This tournament felt so difficult that I didn't have much time over the weekend, so I only did one cryptic question in addition to the sign-in question



## sanity/Welcome to idekCTF 2024!

Welcome to idekCTF 2024! Please join our [discord](https://discord.gg/c7w4gKMnAX) for any announcements and updates on challenges.

**Solve:** 

<div align="center">
    <img src=".\pic\01.png" alt="" height="350">
</div>

Just join the official Discord channel to see the announcement，flag: `idek{our_hack_fortress_team_is_looking_for_mvm_players}` 

## crypto/Golden Ticket

Can you help Charles - who doesn't have any knowledge about cryptography, get the golden ticket and have a trip to Willy Wonka's factory ?

**Solve:** 

```python
def chocolate_generator(m: int) -> int:
    p = ...
    return (pow(13, m, p) + pow(37, m, p)) % p
```

Let's look at the function `chocolate_generator(int)`, which encrypts the input `m` with the prime `p`.

```python
for i in range(golden_ticket):
    chocolate_bag.append(chocolate_generator(i))
chocolate_bag.append(flag_chocolate)
remain = chocolate_bag[-2:]
```

What this means is that the last two elements of `chocolate_bag` are known, namely
$$
(13^{m-1}+37^{m-1})\ \text{mod}\ p=a\\
(13^{m}+37^{m})\ \text{mod}\ p=b
$$
Where $a$, $b$ are known

Transform the first equation
$$
(13^m+13\cdot 37^{m-1})\ \text{mod}\ p=13a\ \text{mod}\ p
$$
Subtracting the two equations gives
$$
24\cdot 37^{m-1}\ \text{mod}\ p=(b-13a)\ \text{mod}\ p
$$
Multiply both sides simultaneously by the modular inverse of 24
$$
37^{m-1}\ \text{mod}\ p=\text{invert(24, p)}*(b-13a)\ \text{mod}\ p
$$
Direct computation using python to get a standard form of the discrete logarithm problem (DLP)

```python
p = 396430433566694153228963024068183195900644000015629930982017434859080008533624204265038366113052353086248115602503012179807206251960510130759852727353283868788493357310003786807
a = 88952575866827947965983024351948428571644045481852955585307229868427303211803239917835211249629755846575548754617810635567272526061976590304647326424871380247801316189016325247
b = 67077340815509559968966395605991498895734870241569147039932716484176494534953008553337442440573747593113271897771706973941604973691227887232994456813209749283078720189994152242
print(f"37^(m-1) mod p = {invert(24, p)*(b-13*a) % p}")
```

Use SageMath to solve for `m-1`. 

```
sage: R = Integers(3964304335666941532289630240681831959006440000156299309820174348590800085336242042650383661130523530862481156025030121798072062519605101307
....: 59852727353283868788493357310003786807)
sage: a = R(37)
sage: b = R(20238126491863160561856801833555874441558426163383040371505001046170090336607808139987729949546550907838970300522022297536146482976221600727793208
....: 8482880826578710915390951613589)
sage: b.log(a)
57629776445896163024735745086814515288454966100802334039751672315837361336412607584713634047210889596
```

Finally, we get the flag

```python
m = 57629776445896163024735745086814515288454966100802334039751672315837361336412607584713634047210889596 + 1
print(long_to_bytes(m))
```

flag: `idek{charles_and_the_chocolate_factory!!!}`

