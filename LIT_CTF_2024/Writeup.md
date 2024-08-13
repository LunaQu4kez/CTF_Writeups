# LIT CTF 2024

This tournament was mainly about Misc and Crypto, and the overall difficulty of the tournament didn't feel too high, most of the questions were relatively easy. I was the only one whose team got 181 / 1296, which was quite satisfactory.

<div align="center">
    <img src=".\pic\01.png" alt="" height="250">
    <img src=".\pic\02.png" alt="" height="250">
</div>



## MISC

### welcome

Please join the Discord for the latest announcements and read [the contest rules](https://lit.lhsmathcs.org/logistics)! Good luck!

**Solve:** 

The question asks to join the Discord channel and see the latest announcements, go to the #announcement channel and see the first half of the flag

<div align="center">
    <img src=".\pic\misc01.png" alt="" width="600">
</div>

Read the rules of the game again and see the second half of the flag

<div align="center">
    <img src=".\pic\misc02.png" alt="" width="600">
</div>

Together is  flag: `LITCTF{we_4re_happy_1it2024_is_h4pp3n1ng_and_h0p3_u_r_2}`

### geoguessr1

Where is this? Flag format: Use three decimal points of precision and round. The last digit of the first coordinate is ODD, and the last digit of the second coordinate is EVEN. Example: LITCTF{80.439,-23.498} (no spaces)

<div align="center">
    <img src=".\pic\g1.jpg" alt="" width="200">
</div>

**Solve:** 

I used a map-reading website to identify a very similar image, copied the link and clicked on it to find that it was a tourist photo of Daxi Zhongzheng Park, located in Taoyuan County, Taiwan, China. Using a latitude/longitude search site (e.g. Google Maps) to look up the location of this park, I found a bridge called Daxi Bridge at the approximate location of (24.884,121.284). The hint said that the last digit of the first coordinate is odd, and the last digit of the second coordinate is even, so I guessed (24.885,121.284) or (24.883,121.284), and after some attempts, the final answer was (24.885,121.284).

flag: `LITCTF{24.885,121.284}` 

### geoguessr2

Our history class recently took a walk on a field trip here. Where is this? Flag format: Use three decimal points of precision and round. The last digit of the first coordinate is EVEN, and the last digit of the second coordinate is ODD. Example: LITCTF{80.438,-23.497} (no spaces)

<div align="center">
    <img src=".\pic\g2.jpg" alt="" width="200">
</div>

**Solve:** 

At first glance, the image is judged to be probably in a cemetery, a person's tombstone. Bing searches for the text on the tombstone and finds an image very similar to the one given in the question:

<div align="center">
    <img src=".\pic\misc03.png" alt="" width="300">
</div>

As well as the website this image came from: https://freedomsway.org/story/captain-john-parker/

The website concludes by saying that the man is buried in [Lexington’s Old Burying Ground](https://freedomsway.org/place/lexingtons-old-burying-ground/) 

Google Maps search for this location to be able to know the latitude and longitude to get flag

flag: `LITCTF{42.450,-71.233}` 

### pokemon

I love pokemon! Win to get the flag

**Solve:** 

Open `index.html` and you'll see that it's a Pokémon battle, and it's almost impossible to win, but after the battle some flag-carrying villains will appear in order. Looking at `script.js`, you can see that the order is from `1.png` to `15.png`, and these flag-raising figures are semaphore codes.

<div align="center">
    <img src=".\pic\misc04.png" alt="" width="450">
</div>

Translated, it's the string `litctf pokeaaag`, so the flag is `LITCTF{pokeaaag}` 

### endless

Whoops! I deleted the file ending of this file, and now I can't seem to figure out what type of file it was. Can you help me?

**Solve:** 

Although the title says the file is missing the suffix, it downloaded as an mp3 file and opened it to listen to it. The flag I heard was `LITCTF{f0udao4rtbsp6}`. 

### a little bit of tomcroppery

Once you crop an image, the cropped part is gone... right???

**Solve:** 

What you get is an image with a title suggesting that the image has been cropped and it looks like there may be something missing underneath. Use the Image Repair Tool [Acropalypse-Multi-Tool](https://github.com/frankthetank-music/Acropalypse-Multi-Tool) to recover a cropped image or gif.

<div align="center">
    <img src=".\pic\misc05.png" alt="" width="600">
</div>

flag: `LITCTF{4cr0p41yp5e_15_k1nd_0f_c001_j9g0s}` 



## Crypto

### simple otp

We all know OTP is unbreakable...

**Solve:** 

```python
import random

encoded_with_xor = b'\x81Nx\x9b\xea)\xe4\x11\xc5 e\xbb\xcdR\xb7\x8f:\xf8\x8bJ\x15\x0e.n\\-/4\x91\xdcN\x8a'

random.seed(0)
key = random.randbytes(32)
```

The string encrypted by the xor is given, along with the encrypted `key`. Since the random seed is fixed, the `key` is also fixed, so it's straightforward to xor back to get the flag

```python
flag = bytes([b1 ^ b2 for b1, b2 in zip(key, encoded_with_xor)])
print(flag)
```

flag: `LITCTF{sillyOTPlol!!!!sdfsgvkhf}`

### privatekey

something's smaller

**Solve:** 

The question gives `n`, `e` and `c`, which are of the same order of magnitude, and the question suggests that something is very small, so the guess is that `d` is very small, so the Wiener chain score attack is used. The tool https://github.com/pablocelayes/rsa-wiener-attack is used here

The solution code is as follows

```python
from RSAwienerHacker import *
from gmpy2 import *

n = 91222155440553152389498614260050699731763350575147080767270489977917091931170943138928885120658877746247611632809405330094823541534217244038578699660880006339704989092479659053257803665271330929925869501196563443668981397902668090043639708667461870466802555861441754587186218972034248949207279990970777750209
e = 89367874380527493290104721678355794851752244712307964470391711606074727267038562743027846335233189217972523295913276633530423913558009009304519822798850828058341163149186400703842247356763254163467344158854476953789177826969005741218604103441014310747381924897883873667049874536894418991242502458035490144319
c = 71713040895862900826227958162735654909383845445237320223905265447935484166586100020297922365470898490364132661022898730819952219842679884422062319998678974747389086806470313146322055888525887658138813737156642494577963249790227961555514310838370972597205191372072037773173143170516757649991406773514836843206
d = hack_RSA(e, n)
m = powmod(c, d, n)
print(bytes.fromhex(hex(m)[2:]))
```

flag: `LITCTF{w13n3r_15_4n_unf0rtun4t3_n4m3}` 

### pope shuffle

it's like caesar cipher but better. Encoded: ࠴࠱࠼ࠫ࠼࠮ࡣࡋࡍࠨ࡛ࡍ࡚ࡇ࡛ࠩࡔࡉࡌࡥ

**Solve:** 

The given encrypted strings are all non-printable characters, which are first converted to their numeric counterparts by the `ord()` function. The question suggests a more advanced Caesar cipher, considering that the first letter is L, the offset is `ord(char1) - 'L'`, and all the characters can be subtracted from the offset to get flag

```python
s = '࠴࠱࠼ࠫ࠼࠮ࡣࡋࡍࠨ࡛ࡍ࡚ࡇ࡛ࠩࡔࡉࡌࡥ'
chr_val = [ord(char) for char in s]
shift = chr_val[0] - ord('L')
chr_val = [val - shift for val in chr_val]
flag = ''
for c in chr_val:
    flag += chr(c)
print(flag)
```

flag: `LITCTF{ce@ser_sAlad}` 

### Symmetric RSA

Who needs public keys? Connect at `nc litctf.org 31783`.

```python
from Crypto.Util.number import long_to_bytes as ltb, bytes_to_long as btl, getPrime

p = getPrime(1024)
q = getPrime(1024)

n = p * q

e = p

with open("flag.txt", "rb") as f:
    PT = btl(f.read())

CT = pow(PT, e, n)
print(f"{CT = }")

for _ in range(4):
    CT = pow(int(input("Plaintext: ")), e, n)
    print(f"{CT = }")
```

**Solve:** 

The question agrees on $e = p$ and tells the encrypted flag. there are 4 chances to ask any $m$ and will get the corresponding $c$ based on $c=m^e \ \text{mod} \ n$.

Preferably, if $m=-1$ and $c_{-1}=(-1)^p+kn=-1+kn\in[0,n-1]$ 

Due to the range restriction, $k$ can only be $1$, so we get $n=c_{-1}+1$, and use 1 query to get $n$ first. 

If we take $m=2$, we have $c_2=2^p\ \text{mod}\ pq$, i.e., $c_2\equiv 2^p(\text{mod}\ pq)$, and then we have $c_2\equiv 2^p(\text{mod}\ p)$.

By Fermat's small definition, $p$ is prime, so $2^p\equiv 2(\text{mod}\ p)$ 

So by using $2^p$ as a bridge, one is able to get $c_2\equiv 2(\text{mod}\ p)$, i.e. $p|c_2-2$ 

Similarly, taking $m=3$ and $m=5$ yields $p|c_3-3$ and $p|c_5-5$, and since $n=pq$, then $p=\gcd(n,c_2-2,c_3-3,c_5-5)=\gcd(c_{-1}+1,c_2-2,c_3-3,c_5-5)$ 

Once $p$ is decrypted, the flag can be recovered by RSA decryption based on the encrypted flag.

The solution code is as follows, where `c`, `c_1`, `c2`, `c3`, `c5` are all asked by the server, and since $p$, $q$ are randomized at the beginning, the values are likely to be different each time, but the decryption result will be the same at the end.

```python
from gmpy2 import *
from Crypto.Util.number import long_to_bytes

c = 31346124426018515038976328012361377000685648856132717988943179632205386821443435476738801813773879687378288088885641705507663418441498975352296782542262606594808782635351613213139473996976256109491984261469612757147896032024424145357819819738055980578810333559447191776265732262021193880318821001204165927918650868181519498902911363088580037677355326336793125961003966637492989788662900257193485941734232598281191320322397469526044085539301205986972554633822648875529580140357314455852706301331359138741692599184142892267022898041592065611032406526409059757051991254300026462650104003853564887341133245713975070697
c_1 = 20951210022833165378178482343265538432796837324363253568165019447795787493483808549947756630513661303838814655327595444348448770968748092942072141479706947100177172605612552573623794410576175604883337154763368764983890513124498344681825929470084046247282759720770078903084706039239519576586164087425851891087430905411669354055771528457976313690414066026862669343266540064856277835938041068293692397980560922592129697905836734404902839121707943857609679483769327449302888652139161390671769563641765282329724119965425082085551886851831338951940919964549667247501679549201761143536329305878412752045073880875535830296228
c2 = 9880349538919895313079403033368037610597729492031536686879907029293384315123073070023304606836125623136617475654808139413321679425411136687822554834097577931447487406111522414216066747795326498278464690437765648177204184667579951917373030982144978439925407267105070738549497547150165018776041091479278566015858156117405760306106190664731882313346287136280855677569912909160782939999998184362813143539241354733581702096372621230803005727085811834233761873309388248283781814930621657944809669489236151009473218833308395057651748550528497618621734211279173138702769877440163656509533796416690297847128505141795740979412
c3 = 8938731607365251044975801185729210370277097050247775569160760595138020403989708067103543945197821851938078799236918667043188615215897173705908365022435463391379177354229961968544618500363544345025287949169106914003500241476995003718742249977050514338024994515711471009788399783358642565874327502111298411554589540400655246405598699833135063768337615594435353512190661641216279437375571413375753108709982321335690000546767116128641358602275206654447008088925389126047431254688164541573114174205158257311230469885536028624404903659002061306385633679003644744096316607057197817046866562489153063040673271857342687950757
c5 = 728210194500651831511187431850474824011025572504090017897764156882000527436400021210826739508758339492751878669733949603501218570326352626073696530452941333907695125593461595449326081302014132625517948158324705244371105824671431310796364873904760462716699465734240619497528201834413790088022813101483435861857165947997617508475971834434789511095775332643264048913223852577655149676463824817330040334667955530425422048927481466046551091912946007824572426510033234303166854465814959490228784589412726992041613796228525265983809810256493316729096432250409646377296752601557074315700254834194927946831199514981663101019
n = c_1 + 1
p = gcd(gcd(gcd(n, c2-2), c3-3), c5-5)
q = n // p
r = (p-1)*(q-1)
d = invert(p, r)
m = powmod(c, d, n)
print(long_to_bytes(m))
```

flag: `LITCTF{ju57_u53_e=65537_00a144ca}` 

### Truly Symmetric RSA

I just realized that it doesn't make sense for people without the key to be able to encrypt messages, so I fixed that.

```python
from Crypto.Util.number import long_to_bytes as ltb, bytes_to_long as btl, getPrime

p = getPrime(1536)
q = getPrime(1024)
n = p * q
e = p

with open("flag.txt", "rb") as f:
    PT = f.read()

CT = pow(btl(PT), e, n)
print(f"{len(PT) = }")  # 62
print(f"{CT = }")
# 155493050716775929746785618157278421579720146882532893558466000717535926046092909584621507923553076649095497514130410050189555400358836998046081044415327506184740691954567311107014762610207180244423796639730694535767800541494145360577247063247119137256320461545818441676395182342388510060086729252654537845527572702464327741896730162340787947095811174459024431128743731633252208758986678350296534304083983866503070491947276444303695911718996791195956784045648557648959632902090924578632023471001254664039074367122198667591056089131284405036814647516681592384332538556252346304161289579455924108267311841638064619876494634608529368113300787897715026001565834469335741541960401988282636487460784948272367823992564019029521793367540589624327395326260393508859657691047658164
print(f"{n = }")
# 237028545680596368677333357016590396778603231329606312133319254098208733503417614163018471600330539852278535558781335757092454348478277895444998391420951836414083931929543660193620339231857954511774305801482082186060819705746991373929339870834618962559270938577414515824433025347138433034154976346514196324140384652533471142168980983566738172498838845701175448130178229109792689495258819665948424614638218965001369917045965392087331282821560168428430483072251150471592683310976699404275393436993044069660277993965385069016086918288886820961158988512818677400870731542293709336997391721506341477144186272759517750420810063402971894683733280622802221309851227693291273838240078935620506525062275632158136289150493496782922917552121218970809807935684534511493363951811373931
```

**Solve:** 

This question mainly uses the coppersmith attack, see ctf-wiki at https://ctf-wiki.org/crypto/asymmetric/rsa/rsa_coppersmith_attack/ 

```python
from Crypto.Util.number import long_to_bytes

CT = 155493050716775929746785618157278421579720146882532893558466000717535926046092909584621507923553076649095497514130410050189555400358836998046081044415327506184740691954567311107014762610207180244423796639730694535767800541494145360577247063247119137256320461545818441676395182342388510060086729252654537845527572702464327741896730162340787947095811174459024431128743731633252208758986678350296534304083983866503070491947276444303695911718996791195956784045648557648959632902090924578632023471001254664039074367122198667591056089131284405036814647516681592384332538556252346304161289579455924108267311841638064619876494634608529368113300787897715026001565834469335741541960401988282636487460784948272367823992564019029521793367540589624327395326260393508859657691047658164
n = 237028545680596368677333357016590396778603231329606312133319254098208733503417614163018471600330539852278535558781335757092454348478277895444998391420951836414083931929543660193620339231857954511774305801482082186060819705746991373929339870834618962559270938577414515824433025347138433034154976346514196324140384652533471142168980983566738172498838845701175448130178229109792689495258819665948424614638218965001369917045965392087331282821560168428430483072251150471592683310976699404275393436993044069660277993965385069016086918288886820961158988512818677400870731542293709336997391721506341477144186272759517750420810063402971894683733280622802221309851227693291273838240078935620506525062275632158136289150493496782922917552121218970809807935684534511493363951811373931
PR.<x> = PolynomialRing(Zmod(n))
flag = (x-CT).small_roots(X=256**62, beta=0.5)[0]
print(long_to_bytes(int(flag)))
```

flag: `LITCTF{I_thought_the_bigger_the_prime_the_better_:(_72afea90}` 



## Reverse

### forgotten message

I made a cool program to show the flag, but i forgot to output it! Now that I lost the source, I can't seem to remember the flag. Can you help me find it?

**Solve:** 

Actually, there is no need to reverse this question...

Open the file in hexadecimal mode and you'll see the flag directly.

<div align="center">
    <img src=".\pic\rev01.png" alt="" width="600">
</div>

flag: `LITCTF{y0u_found_Me_3932cc3}` 

### Burger Reviewer

Try to sneak a pizza into the burger reviewer!

**Solve:** 

Given is a java file, the input flag to do various tests, if the test all pass, then the flag is correct, so the question according to the logic of the test code to restore the flag can be

```java
if (input.length() > 42) {
	System.out.println("This burger iz too big :(");
} else if (input.length() < 42) {
	System.out.println("This burger iz too small :(");
} else {
    // code...
}
```

Let's look at the `main()` function, which first determines the length of the flag, which should be 42. It then passes through the functions `bun(input)`, `cheese(input)`, `meat(input)`, `pizzaSauce(input)`, `veggies(input)`, in order. Test.

The `bun()` function restricts the format that the flag follows, `cheese()` specifies that certain bits must be `'_'`, and each of the remaining three functions checks that certain positions of the character match. The rest of the three functions each check that certain positions match the requirements. The reduction is not difficult, as you only need to read the code, and you end up with the flag: `LITCTF{bur9r5_c4n_b_pi22a5_if_th3y_w4n7_2}`.



## Web

### anti-inspect

can you find the answer? **WARNING: do not open the link your computer will not enjoy it much.** URL: http://litctf.org:31779/ Hint: If your flag does not work, think about how to style the output of console.log

**Solve:** 

Computer is stuck after opening... The web code could be some kind of dead loop.

But when you open the console, you can see the flag directly.

<div align="center">
    <img src=".\pic\web01.png" alt="" width="600">
</div>

`LITCTF{your_fOund_teh_fI@g_94932}` 

