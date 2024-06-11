# MISC

OS: Kali Linux

[TOC]

## 文件

### 文件格式

#### 1. 命令行

```shell
$ file img    
img: PNG image data, 280 x 280, 1-bit colormap, non-interlaced
```

文件头部损坏或残缺，只会返回 `data` ，可使用 WinHex 添加或修改或补全文件头

以下命令能替代 WinHex 查看文件格式

```shell
$ hexdump -C filename
```

#### 2. WinHex

十六进制文件头

| 文件类型         | 后缀 | 文件头               |
| ---------------- | ---- | -------------------- |
| JPEG             | jpg  | FF D8 FF E1          |
| PNG              | png  | 89 50 4E 47          |
| GIF              | gif  | 47 49 46 38          |
| TIFF             | tif  | 49 49 2A 00          |
| Windows Bitmap   | bmp  | 42 4D C0 01          |
| ZIP Archive      | zip  | 50 4B 03 04          |
| RAR Archive      | rar  | 52 61 72 21          |
| Adobe Photoshop  | psd  | 38 42 50 53          |
| Rich Text Format | rtf  | 7B 5C 72 74 66       |
| XML              | xml  | 3C 3F 78 6D 6C       |
| HTML             | html | 68 74 6D 6C 3E       |
| Adobe Acrobat    | pdf  | 25 50 44 46 2D 31 2E |
| Wave             | wav  | 57 41 56 45          |
| pcap             | pcap | 4D 3C 2B 1A          |



### 文件拆分

Kali 自带的 Binwalk 工具

先进行文件分析

```shell
$ binwalk filename
```

发现文件由多个文件合成，因此需要文件分离，采用如下命令

```shell
$ binwalk -e filename 
```

会在同一个目录下得到文件夹，名称为 `_filename.extracted`



### 文件合并

`cat` 命令进行文件合并，可以使用通配符 `*` 

```shell
$ cat d1.txt d2.txt d3.txt > doc.txt 
```

合并后，如果题目给出了正确合并结果 md5，可以使用以下命令计算自己合并出来的 md5 做对比

```shell
$ md5sum filename
```





## 图片

### GIF 图片隐写

gif 图片可能隐藏信息，可以使用 firework 查看图层和帧

也可以使用命令 `convert` 分离每一帧

```shell
$ convert cake.gif cake.png
$ ls
cake-0.png  cake-1.png  cake-2.png  cake-3.png  cake.gif
```

此外，`identify` 命令也可用于分析 gif



### Exif 信息

图片可能含有 Exif 信息，即 Exif 按照 JPEG 的规格在图片中插入了信息数据，可以右键 -> 属性 -> 详细信息查看，GPS 那一栏显示的经纬度可能有用



### 图片对比

对于两张视觉上没有差异的图片，可以使用 StegSolve.jar 对两张图片进行 add，sub，xor 操作



### LSB 隐写

1. 可以使用 StegSolve 手动枚举 LSB 隐写

2. 在 linux 中使用 zsteg 工具检测图片的 LSB 隐写

   ```shell
   $ zsteg filename
   ```

3. 使用 python 脚本 (好处是便于根据情况的不同而修改)  **处理 .bmp** 

   ```python
   import PIL.Image
   
   def func():
   	im = PIL.Image.open('pic.bmp')
   	im2 = im.copy
   	pix = im2.load()
   	wid, hei = im2.size()
   	
   	for x in range(0, wid):
   		for y in range(0, hei):
   			if pix[x, y] & 1 == 0:
   				pix[x, y] = 0
   			else:
   				pix[x, y] = 255
   	im2.show()
   	return
   
   if __name__ == '__main__':
   	func()
   ```



### CRC 校验错误 (png)

如果打开图片提示错误，导致打不开，可能是 CRC 校验错误

使用 tweakpng 工具打开，会提示正确的 CRC 值，可以返回 WinHex 修改 (文件头的各部分意义如下图)

<div align="center">
    <img src=".\pic\misc01.png" alt="" width="550">
</div>

但是，可能出现，CRC 原本正确，高度或宽度被人为修改导致 CRC 验证不通过，此时可以用以下 python 脚本计算对应当前 CRC 的宽度和高度

```python
import binascii
import struct

crcbp = open("pic.png", "rb").read() # filename
crc_val = 0x08ec7edb                 # true crc

for i in range(1024):
	for j in range(1024):
		data = crcbp[12:16] + struct.pack('>i', i) + struct.pack('>i', j) + crcbp[24:29]
		crc32 = binascii.crc32(data) & 0xffffffff
		if crc32 == crc_val:
			print(i + " " + j)
			print("hex " + hex(i) + " " + hex(j))
```



### 隐写软件 F5

[链接](https://github.com/matthewgao/F5-steganography) 



### Stegdetect 探测 jpg 加密

可以检测到通过 JSteg、JPHide、OutGuess、Invisible Secrets、F5、appendX 和 Camouflage 等这些隐写工具隐藏的信息，并且还具有基于字典暴力破解密码方法提取通过 Jphide、outguess 和 jsteg-shell 方式嵌入的隐藏信息

```shell
$ stegdetect xxx.jpg
```

还有一些可选参数

```
-q 仅显示可能包含隐藏内容的图像。
-n 启用检查JPEG文件头功能，以降低误报率。如果启用，所有带有批注区域的文件将被视为没有被嵌入信息。如果JPEG文件的JFIF标识符中的版本号不是1.1，则禁用OutGuess检测。
-s 修改检测算法的敏感度，该值的默认值为1。检测结果的匹配度与检测算法的敏感度成正比，算法敏感度的值越大，检测出的可疑文件包含敏感信息的可能性越大。
-d 打印带行号的调试信息。
-t 设置要检测哪些隐写工具（默认检测jopi），可设置的选项如下：
j 检测图像中的信息是否是用jsteg嵌入的。
o 检测图像中的信息是否是用outguess嵌入的。
p 检测图像中的信息是否是用jphide嵌入的。
i 检测图像中的信息是否是用invisible secrets嵌入的。
```





## 压缩包

### 密码爆破

#### zip2john

使用 zip2john 工具进行 john 暴力破解

假设有压缩包 ctf.zip，先创建一个文件 pw.txt (文件名和后缀随意，仅用于临时储存 hash)，然后使用如下命令

```shell
$ zip2john ctf.zip > pw.txt
$ john pw.txt
```

对于已破解的 hash，john 会储存，可以用以下指令查询

```shell
$ john --show pw.txt
```

#### 例. 二维码

[题目链接](https://buuoj.cn/challenges#%E4%BA%8C%E7%BB%B4%E7%A0%81)

拿到图片，是个二维码，扫描后发现没用

查看文件类型

```shell
$ file QR_code.png    
QR_code.png: PNG image data, 280 x 280, 1-bit colormap, non-interlaced
```

是 .png 格式没问题，然后进行文件分析，发现由多个文件组合而成，于是拆分

```shell
$ binwalk -e QR_code.png      

DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             PNG image, 280 x 280, 1-bit colormap, non-interlaced
WARNING: Extractor.execute failed to run external extractor 'jar xvf '%e'': [Errno 2] No such file or directory: 'jar', 'jar xvf '%e'' might not be installed correctly
471           0x1D7           Zip archive data, encrypted at least v2.0 to extract, compressed size: 29, uncompressed size: 15, name: 4number.txt
650           0x28A           End of Zip archive, footer length: 22
```

拆分后得到了压缩包，但是解压需要密码，采用 john 暴力破解

```shell
$ touch hash

$ zip2john 1D7.zip > hash
ver 2.0 1D7.zip/4number.txt PKZIP Encr: TS_chk, cmplen=29, decmplen=15, crc=AE4C3446 ts=508B cs=508b type=8

$ john hash
Using default input encoding: UTF-8
Loaded 1 password hash (PKZIP [32/64])
Will run 4 OpenMP threads
Proceeding with single, rules:Single
Press 'q' or Ctrl-C to abort, almost any other key for status
Almost done: Processing the remaining buffered candidate passwords, if any.
Proceeding with wordlist:/usr/share/john/password.lst
Proceeding with incremental:ASCII
7639             (1D7.zip/4number.txt)     
1g 0:00:00:06 DONE 3/3 (2024-06-10 05:45) 0.1636g/s 9452Kp/s 9452Kc/s 9452KC/s 08r..7kjr
Use the "--show" option to display all of the cracked passwords reliably
Session completed. 
```

可以看到破解出的 zip 密码是 7639，打开压缩包，拿到 flag

#### ARCHPR

工具 ARCHPR 同样在密码爆破时很好用！



### CRC32

文件内内容很少而密码很长时，不去爆破压缩包的密码，而是直接去爆破源文件的内容 (一般都是可见的字符串)，从而获取想要的信息。

`CRC` 本身是「冗余校验码」的意思，`CRC32` 则表示会产生一个 `32 bit` ( `8` 位十六进制数) 的校验值。由于 `CRC32` 产生校验值时源数据块的每一个 `bit` (位) 都参与了计算，所以数据块中即使只有一位发生了变化，也会得到不同的 `CRC32` 值。

 在爆破时我们所枚举的所有可能字符串的 `CRC32` 值是要与压缩源文件数据区中的 `CRC32` 值所对应

```python
import binascii
import base64
import string
import itertools
import struct

alph = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789+/='

crcdict = {}
print "computing all possible CRCs..."
for x in itertools.product(list(alph), repeat=4):
    st = ''.join(x)
    testcrc = binascii.crc32(st)
    crcdict[struct.pack('<i', testcrc)] = st
print "Done!"

f = open('flag.zip')
data = f.read()
f.close()
crc = ''.join(data[14:18])
if crc in crcdict:
    print crcdict[crc]
else:
    print "FAILED!"
```



### 压缩文件加密

<div align="center">
    <img src=".\pic\misc02.png" alt="" width="550">
</div>

zip 加密是在文件头的**加密标记位**做修改，进而再打开文件时识被别为加密压缩包

| 加密方式 | 文件头中的全局方式位标记 | 目录中源文件的全局方式位标记 |
| -------- | ------------------------ | ---------------------------- |
| 未加密   | 00 00                    | 00 00                        |
| 伪加密   | 00 00                    | 09 00                        |
| 真加密   | 09 00                    | 09 00                        |

- 注1：不一定是 09 00 或 00 00，只要是奇数都视为加密，而偶数则视为未加密
- 注2：伪加密可能人为把两项都改为 09 00，伪装成真加密



### 明文攻击

对于已知压缩包里某个文件的部分连续内容 (至少 12 字节) 的含密码压缩包，可以使用 ARCHPR 的 Plain-text (明文攻击) 破解

**[例]** 有明文的 readme.txt 和一个压缩包 quetion.zip，而压缩包中包含这个明文的 readme.txt

```
Filename   		|CRC32		|Others  
readme.txt		 3C945494
quetion.zip
├── readme.txt 	 3C945494
└── flag.txt	 D57BCC52
```

发现两个 readme.txt 的 CRC32 相同，判断是同一文件，满足了压缩包内某文件的部分连续内容一致，尝试明文攻击。

现在需要将明文 readme.txt 以同样的打包方式打包成压缩包。打包完成后，需要确认二者采用的压缩算法相同。一个简单的判断方法是用 `WinRAR` 打开文件，同一个文件压缩后的体积是否相同。如果相同，基本可以说明你用的压缩算法是正确的。如果不同，就尝试另一种压缩算法。

使用 ARCHPR 进行明文攻击

<div align="center">
    <img src=".\pic\misc03.png" alt="" width="400">
</div>





## 总结

通用：

1. 检查文件类型，如果有问题，修改或补全
2. 打开十六进制看看有无线索 (文件内容隐写)
3. 分析组成，若可拆分尝试拆分

图片：

1. 检查图片显示的大小和实际占用存储空间，若相差过大，可能有隐藏信息，可修改图片显示区域大小
2. 右键属性 -> 详细信息，可查看包括位置信息等 (Exif)
3. 如果给出的是两张看似一样的图片，可以通过工具 (如 StegSolve) 分析细微差异
4. 检查 LSB 隐写 !!! (更常见于 png 格式)
5. 如果发生错误打不开或宽高明显不对，检查 CRC 校验
6. 检查加密 (常见于 jpg)

压缩包：

1. 压缩包密码可考虑 john 或 ARCHPR 暴力破解
2. 文件内内容很少 (4 字节左右) 而密码很长，考虑枚举 CRC32 直接破解文件内容
3. 压缩文件是加密的，可以考虑伪加密
4. 给出一个文件，压缩包内还有一个文件，两个文件 CRC 相同，考虑明文攻击











