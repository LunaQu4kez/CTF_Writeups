# TFC CTF 2024

It was my first time to participate in CTF, and I felt that the training effect of the competition was really good. I did 8 questions, scored 755 points, and ranked 104 / 1471. Unfortunately, the game ended at 7:00, and I didn't get the flag for one of the reverse questions until 7:01, so I couldn't make it in time to submit it, otherwise I would have been in the top 100 :cry: 

<div align="center">
    <img src=".\pic\01.png" alt="" height="250">
    <img src=".\pic\02.png" alt="" height="250">
</div>
Incidentally, some of the files included in the title are [here](./file), and the folder name is the title name



## MISC

### Rules

<div align="center">
    <img src=".\pic\misc01.png" alt="" width="600">
</div>

Easy question, just read the rules!

<div align="center">
    <img src=".\pic\misc02.png" alt="" width="600">
</div>

`TFCCTF{M4ny_ch4ng3s...m0r3_3ff0rt}` 

### Discord Shinanigans V4

<div align="center">
    <img src=".\pic\misc03.png" alt="" width="600">
</div>

The question asks to go to the #bot-commands partition of the TFC CTF community on Discord to find the flag

<div align="center">
    <img src=".\pic\misc04.png" alt="" width="600">
</div>

I noticed that bot was repeating a few sentences, and at first I thought it was some kind of cryptic writing, but when I looked at the 5 sentences together, I didn't see anything.

After that, copy the sentence directly (right-click on the sentence -> Copy Text), paste it into a hypertext editor (just paste it into VSCode), and you'll see the following text, which presumably hides the message with non-printable characters

`It's not here... Oh wait, it actually is |||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||||| _ _ _ _ _ _  add this to the format: zoo_wee_mama`

Finally, we get the flag: `TFCCTF{zoo_wee_mama}` 

### Secret Message

<div align="center">
    <img src=".\pic\misc05.png" alt="" width="600">
</div>

Open `main.py` and find that we are given 6 different numbers as seeds, then call the encryption function `hide(string, seed, shuffle)` to encrypt them, if the result after 6 encryptions is the same as before the encryption, we can get the flag

```python
def hide(string, seed, shuffle):
    random.seed(seed)
    byts = []
    for _ in range(len(string)):
        byts.append(random.randint(0, 255))
    random.seed(shuffle)
    for i in range(100):
        random.shuffle(byts)
    return bytes([a^b for a, b in zip(string, byts)])
```

Looking at the function, the `shuffle` used for 6 of the encryptions is the same, and it's a random number. I didn't fully understand the principle, but I guessed that if I encrypted once with `x` and then again with `-x`, the message would not be encrypted.

Connect the container, enter 6 seeds: 1-1 2-2 3-3, and get flag: `TFCCTF{random_is_not_secur3}` 



## Crypto

### CCCCC

<div align="center">
    <img src=".\pic\cryp01.png" alt="" width="600">
</div>

Easy question. Open `ccccc.txt` and you'll find a string of text.

`5c4c4c6c4c3c4c3c5c4c4c6c7cbc6c3c7c3c6c8c6cfc7c5c7c4c5cfc6c3c6cfc7c5c7c4c5cfc6c3c7c4c3c0c5cfc6c3c6cdc7c9c5cfc6c3c6c2c3c0c7c9c5cfc6c3c3c4c6cec6c4c5cfc6c3c6cdc7c9c5cfc6c3c6c4c6cfc6c7c5cfc6c3c6c1c6cec6c4c5cfc6c3c6cdc7c9c5cfc6c3c6c3c3c4c3c7c7cdc0ca`

Observe the characteristics and find that each hexadecimal character is followed by a `c`, combined with the title called CCCCC, try to remove these `c` to get a hexadecimal string, and then according to the ASCII code to the string, get flag: `TFCCTF{cshout_cout_ct0_cmy_cb0y_c4nd_cmy_cdog_cand_cmy_cc47}` 

The code is as follows

```python
flag = '5c4c4c6c4c3c4c3c5c4c4c6c7cbc6c3c7c3c6c8c6cfc7c5c7c4c5cfc6c3c6cfc7c5c7c4c5cfc6c3c7c4c3c0c5cfc6c3c6cdc7c9c5cfc6c3c6c2c3c0c7c9c5cfc6c3c3c4c6cec6c4c5cfc6c3c6cdc7c9c5cfc6c3c6c4c6cfc6c7c5cfc6c3c6c1c6cec6c4c5cfc6c3c6cdc7c9c5cfc6c3c6c3c3c4c3c7c7cdc0ca'
flag = flag.replace('c', '')
flag = ''.join(chr(int(flag[i:i+2], 16)) for i in range(0, len(flag), 2))
print(flag)
```

### Genetics

<div align="center">
    <img src=".\pic\cryp02.png" alt="" width="600">
</div>

Another easy question. This is nucleobase encryption, A T C G corresponds to 00 01 10 11, 4 letters or 8 bit corresponds to a character in ASCII code, but we need to try which letter corresponds to which. The following is the solution code:

```python
s = 'CCCA CACG CAAT CAAT CCCA CACG CTGT ATAC CCTT CTCT ATAC CGTA CGTA CCTT CGCT ATAT CTCA CCTT CTCA CGGA ATAC CTAT CCTT ATCA CTAT CCTT ATCA CCTT CTCA ATCA CTCA CTCA ATAA ATAA CCTT CCCG ATAT CTAG CTGC CCTT CTAT ATAA ATAA CGTG CTTC'
flag = ''
for i in range(len(s)):
    if s[i] == 'C':
        flag += '01'
    elif s[i] == 'A':
        flag += '00'
    elif s[i] == 'T':
        flag += '11'
    elif s[i] == 'G':
        flag += '10'
    else:
        flag += s[i]

flag = flag.replace(" ", "")
res = ""
for i in range(0, len(flag), 8):
    char = flag[i:i+8]
    decimal_value = int(char, 2)
    res += chr(decimal_value)
print(res)
```

Finally, we get the flag: `TFCCTF{1_w1ll_g3t_th1s_4s_4_t4tt00_V3ry_s00n}`

### Conway

<div align="center">
    <img src=".\pic\cryp03.png" alt="" width="600">
</div>

Get two files, `main.py` is the encrypted code and `output.txt` is the output.

First look at `main.py`, `initial` is a string of numbers containing only 1 2 3, which is encrypted by the function `generate_next_key(initial)`, and then output, which is the first part of the problem.

```python
initial = 11131221131211131231121113112221121321132132211331222113112211
initial = generate_next_key(initial)
print(initial)   # 311311222113111231131112132112311321322112111312211312111322212311322113212221
```

Observe that this function gives a description of the appearance of the series, and then the encrypted string of numbers. For example, 111221 would be described as, 3 1's, 2 2's, 1 1's, and encrypted to 312211. Based on this pattern, you can reduce `generate_next_key(initial)`, or you can refer to the topic [Count and say](https://leetcode.cn/problems /count-and-say/description/), the reduced function is as follows:

```python
def generate_next_key(prev):
    prev = str(prev)
    curr = ""
    start = 0
    pos = 0
    while pos < len(prev):
        while pos < len(prev) and prev[pos] == prev[start]:
            pos += 1
        curr += str(pos - start) + prev[start]
        start = pos
    return curr
```

```python
initial = generate_next_key(initial)
h = hashlib.sha256()
h.update(str(initial).encode())
key = h.digest()

cipher = AES.new(key, AES.MODE_ECB)
print(cipher.encrypt(pad(flag.encode(), 16)).hex())
# f143845f3c4d9ad024ac8f76592352127651ff4d8c35e48ca9337422a0d7f20ec0c2baf530695c150efff20bbc17ca4c
```

The `initial` is then encrypted with the `generate_next_key(initial)` function, the `key` is hashed with SHA256, and the `flag` is encrypted with the `key` key using AES symmetric encryption in ECB mode. 

Reduce the `generate_next_key(initial)` function first, then run and print `key`, getting `609fd95c2155dfc76de2212c06b09f4ffa3b911d023b871f45a4eab530b393f3` 

Decrypting it with [AES decryption site](https://the-x.cn/cryptography/Aes.aspx) (also python, some specific external libraries are needed) can get the flag: `TFCCTF{c0nway's_g4me_0f_sequences?}`

### Rotator Cuffs

<div align="center">
    <img src=".\pic\cryp04.png" alt="" width="600">
</div>

Medium difficulty, with a total of 38 solutions, should be the hardest problem I've ever done. The material given is `main.sage` which is the encrypted code (sage works as python), and `output.txt` which is the output from running `main.sage`.

```python
sumyum = -142226769181911294109604985414279966698269380324397182385943224688881786967396493297107323123238846393606215646973028804858833605857511769169835160302020010947120438688346678912969985151307036771093126928042899151991372646137181873186360733201445140152322209451057973604096364822332301687504248777277418181289153882723092865473163310211285730079965167100462695990655758205214602292622245102893445811728006653275203674798325843446182682402905466862314043187136542260285271179956030761086907321077282094937573562503816663264662117783270594824413962461600402415572179393223815743833171899844403295401923754406401502029098878225426758204788
assert sumyum == 2 * x1 ** 2 - SECRET * y1 ** 2 + 2 * x2 ** 2 - SECRET * y2 ** 2
```

Look first at `main.sage`, which defines a very large integer, `sumyum`, and then restricts the relationship between several variables
$$
2(x_1^2+x_2^2)-\text{SECRET}(y_1^2+y_2^2)=\text{sumyum}
$$

```python
F = RealField(3456)
x = vector(F, [x1, x2])
y = vector(F, [y1, y2])

for _ in range(10000):
    theta = F.random_element(min=-5 * pi, max=5 * pi)
    R = matrix(F, [[cos(theta), -sin(theta)], [sin(theta), cos(theta)]])
    x = R * x
    y = R * y

print("resulting_x =", x)
print("resulting_y =", y)
```

Then the points `x = (x1, x2)` and `y = (y1, y2)` were rotated 10000 times, each time randomly rotating $[-5\pi,5\pi]$, and finally outputting the coordinates of the two points. Observing the above equation, we can see that $x_1^2+x_2^2$ is the modulus of the point $x$, so the rotations have no effect, and simplifying the above equation we have
$$
\text{SECRET}=\frac{2\|x\|^2-\text{sumyum}}{\|y\|^2}
$$
Based on the coordinates of the last printed point, the module length can be calculated, which in turn can be used to calculate SECRET, and the solution code is as follows:

```python
import mpmath

mpmath.mp.dps = 10000000
x1 = mpmath.mpf('3.3634809129087361339072596725006530600959848462815297766832600914180365498172745779530909095267862889993244875375870115862675521807203899602656875152466204714275847395081849947663071267678766620524700684572851632968584152642766533856599351512856580709762480161587856072790441655306539706390277559619708164477066112096159734609814163507781608041425939822535707080207842507025990454423454350866271037975269822168384397403714076341093853588894719723841956801405249658560486108807190027518922407932998209533025998785987344569930974892824749931597842343369782141668038797305601028366704322107431479213165353278773002704707347001056980736352878716736155054293350509670339144379602697176068785416128203382284653052813910539052285224499161723972390574800570738938264516350981139157860135237512937090793549860152173756751719627025142858529263243314917653507237003568510016357713402278753999645732592631577726849749929789275649985363293274521704758513276997442425705172979362522303209937874019044195572717894784790824040985970678829869212168596332338e228')
x2 = mpmath.mpf('4.3493076236586169242233212405270398931813271488805260703904730395387317512159124699671617536806847379014763743850012966440449858042327139796085868934120939346500622666309663813415016921760622643752056516232426324399548704613192843351795229042500735885925583510203795565452553753954474949980588780332651769544235511465216034600990329267883327087177217125655503845919331440817328958054102807738186874040636118222352351053320953917165679774298608790659071127811941909136888169274293065733698380573486079052876249484455409206182001827225690775874445171478338344209529207109172368590360722150559332665968826925103060717742483611155201852629766859356827518117986215929527812137774656124580645282319815982553388185475874607903050755710964732279490338614504903256117014312989278124177060468718045944298976827788272885547066724342578660563396148909159051946415261351324693896674313199869788279492452177771905587881622085592044441472137286330359635594402564357596784568377870545793505212074411425362120275312322293627143588322908897500139505746513232e228')
y1 = mpmath.mpf('3.0086123485184949854819528432444522887263618452152977201477700454454717599185922285792607291484161348863603668674724666302028473336653202339259214779198337146709052083562504123644969759313504022148939497579033947489964578987257010705347661159352495880621564046451129149321751369899157697461990748527068553919767557375414807745137776378672423131583632676118768803623661016450513713378889178790819115525404124475586398119768281556573742250499881136366816528002891506377591473809774876327335425713426558761290418087432306668623923825516541279687269109753438014462223886767964900168026643719447209474190574704192551865457553267219179816090151816092471203713238427208397671093453024024773606469951052196613699816481289760243547361942029869165939022611782658000517871759272476768999453412473058498224382162775678590320117678687959374599497850317809926761224934950410879753727042047871292717229649696383856159211062622325024918849176324424823611459590717866478574927162324917352318674258311617781845396479605897293293787546058229588461669469113001e228')
y2 = mpmath.mpf('4.1955438730064492244518395125687091233417321001179084616477593364143186962035096742717340249485256810878365124925979444527539802357032735868877910266504910589105346718553503670072791148806000734099122372428956062737130602189826489676949800396857262364104813055382317498461363421406914514918460816121876800728600531432610837129788010503804927836206596876591613685011706833895602299866191433190745884295362337967940063679204541643670409168084686978205876941245671248753306754892761206974604980311577415661960800437927228624982030061751022139301406066860249918396002252864930009083759551916555623475795108943840654272107400479044754688171126386094896825019962082090350188892677712358612478027143147182776057102433244569971150928964257290752485837202929975257858813456753394801152212850446322739077604336730800210171231609831225616780923301071587159265696870229784689201181607735865814975046649574472138172333744474559659785291954987787639082881571990180182337133038177924408020273887276582566592470019342076814034084107444178243083855840959209e228')
sumyum = mpmath.mpf('-142226769181911294109604985414279966698269380324397182385943224688881786967396493297107323123238846393606215646973028804858833605857511769169835160302020010947120438688346678912969985151307036771093126928042899151991372646137181873186360733201445140152322209451057973604096364822332301687504248777277418181289153882723092865473163310211285730079965167100462695990655758205214602292622245102893445811728006653275203674798325843446182682402905466862314043187136542260285271179956030761086907321077282094937573562503816663264662117783270594824413962461600402415572179393223815743833171899844403295401923754406401502029098878225426758204788')

flag = (2 * (x1 * x1 + x2 * x2) - sumyum) / (y1 * y1 + y2 * y2)
flag = int(flag)
hex_flag = hex(flag)[2:]
str_flag = ''
for i in range(0, len(hex_flag), 2):
    ascii_character = chr(int(hex_flag[i:i+2], 16))
    str_flag += ascii_character
print(str_flag)
```

The `mpmath` package is used here for high-precision calculations, but of course you can use other alternatives, or even just `sage`.

Finally, we get the flag: `TFCCTF{r0t4t3_and__g0_furth3r...s4me_th1ng...schr0d1ng3r's_r0tat1on...not}`



## Reverse

I didn't know how to reverse, but I learned it in the afternoon of the second day of the tournament, and did two easy problems, the last of which I haven't had a chance to submit yet. :crying_cat_face: 

### Signal

<div align="center">
    <img src=".\pic\rev01.png" alt="" width="600">
</div>

A file `signal` is given, checking it with the command `$ file signal` reveals that it's an elf file, and it's thrown straight into the IDA for reversal.

<div align="center">
    <img src=".\pic\rev02.png" alt="" width="600">
</div>

There are 6 functions that compare the ASCII code of the user input character by character, and output `Nope` and exit if there is any inconsistency. The question suggests that flag is 32 bytes, and the total number of characters compared by the 6 functions here is also 32, so this is probably the ASCII code of flag, and we get flag after conversion. `TFCCTF{b11e807f65b27dcf82e70c4bad63a3eb}` 

### License

<div align="center">
    <img src=".\pic\rev03.png" alt="" width="600">
</div>

A file `license` was given, and it was found to be an elf file, so I threw it straight into IDA to reverse it. After reversing, I looked at the main function：

```c++
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  puts("Please enter your license key to use this program!");
  fgets(src, 18, stdin);
  if ( strlen(src) != 17 )
    exit(0);
  if ( src[16] == 10 )
    src[16] = 0;
  strncpy(dest, src, 8uLL);
  byte_4088 = 0;
  if ( (unsigned int)sub_1209(dest) == 1 )
  {
    puts("Nope");
    exit(0);
  }
  // other code
}
```

Roughly, it reads a string of length 17, then copies the first 8 characters, then calls the function `sub_1209(string)` to make a judgment call and expects a 0.

```c++
if ( byte_4068 != 45 )
  exit(0);
```

Then determine if the ASCII value of the 9th character is 45, i.e., `-`

```c++
if ( byte_4068 != 45 )
  exit(0);
strncpy(byte_4090, byte_4069, 8uLL);
if ( (unsigned int)sub_1345(byte_4090) == 1 )
{
  puts("Nope");
  exit(0);
}
puts("Congrats! Get the flag on remote.");
return 0LL;
```

Then the last 8 characters are copied and `sub_1345(string)` is called to make a judgment and expects to return 0. If all the judgments succeed, it means that the input 17-bit string is valid and you can get the flag.

```c++
__int64 __fastcall sub_1209(__int64 a1)
{
  int v1; // eax
  int i; // [rsp+18h] [rbp-18h]
  int j; // [rsp+1Ch] [rbp-14h]
  char v5[8]; // [rsp+20h] [rbp-10h]
  unsigned __int64 v6; // [rsp+28h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  for ( i = 0; i <= 7; ++i )
  {
    v1 = i % 3;
    if ( i % 3 == 2 )
    {
      v5[i] = *(_BYTE *)(i + a1) - 37;
    }
    else if ( v1 <= 2 )
    {
      if ( v1 )
      {
        if ( v1 == 1 )
          v5[i] = *(_BYTE *)(i + a1) + 16;
      }
      else
      {
        v5[i] = *(_BYTE *)(i + a1) ^ 0x5A;
      }
    }
    v5[i] ^= 0x33u;
  }
  for ( j = 0; j <= 7; ++j )
  {
    if ( (unsigned __int8)v5[j] != aXsl3bdxp[j] )
      return 1LL;
  }
  return 0LL;
}
```

First look at the function `sub_1209(string)`, the input length of the string of 8 to perform some operations, and finally compared with the standard, compared with the success of the return 0. You can see that the variable `aXsl3bdxp ` is a length of 8 strings `'Xsl3BDxP'`, the string will be simplified by the operation:

```c++
for ( i = 0; i <= 7; ++i )
{
  if ( i % 3 == 2 ) v5[i] = *(_BYTE *)(i + a1) - 37;
  else if ( i % 3 == 1 ) v5[i] = *(_BYTE *)(i + a1) + 16;
  else v5[i] = *(_BYTE *)(i + a1) ^ 0x5A;
  v5[i] ^= 0x33u;
}
```

Now that the end result and the procedure are known, the string can be reduced to `'10\x84Za\x9c\x11S'`, which has non-printable characters.

```c++
__int64 __fastcall sub_1345(__int64 a1)
{
  int i; // [rsp+18h] [rbp-8h]
  int j; // [rsp+1Ch] [rbp-4h]

  for ( i = 0; i <= 7; ++i )
  {
    if ( ((*__ctype_b_loc())[*(char *)(i + a1)] & 0x200) != 0 )
    {
      *(_BYTE *)(i + a1) = (*(char *)(i + a1) - 92) % 26 + 97;
    }
    else if ( ((*__ctype_b_loc())[*(char *)(i + a1)] & 0x100) != 0 )
    {
      *(_BYTE *)(i + a1) = (*(char *)(i + a1) - 48) % 26 + 65;
    }
  }
  for ( j = 0; j <= 7; ++j )
  {
    if ( *(_BYTE *)(j + a1) != aMzxaplzr[j] )
      return 1LL;
  }
  return 0LL;
}
```

Then you see the function `sub_1345(string)`, which does `(chr - 92) % 26 + 97` if it's a lowercase letter (as determined by & 0x200), and `(chr - 48) % 26 + 65` if it's an uppercase letter, and finally compares it to the variable `aMzxaplzr`, which is also known as `'mzXaPLzR'`. Based on this logic, the string can be reduced to `huGvYUuA` 

Finally, splicing the two parts together is the string to get the flag, `10\x84Za\x9c\x11S-huGvYUuA`.

Notice that you can't type non-printable characters in a linux terminal, so you use python's pwn package to connect to the server and type in the contents, and finally get the flag

`TFCCTF{ac1da9096a8ad2fcb839565621bf09e892a470a6a7a0498b6259e09525096b9d}`

(I don't know why this question is Warm-up and the previous question is Easy, I feel that this question is a bit more difficult)