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



### 检测 jpg 加密

#### Stegdetect 

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

#### Steghide

有时候 Stegdetect 检测不出来的，可以用 Steghide 检测

```shell
$ steghide extract -sf test.jpg -p password
```

没有 password 的加密直接回车即可



### 二维码

如果拿到了一串二进制，而数量正好是整数的平方，可以考虑转二维码

在线二维码修复网站：https://merricx.github.io/qrazybox/

碰到下面这种是 Aztec Code，可用这个[在线网站](https://products.aspose.app/barcode/recognize/aztec#result)扫描

<div align="center">
    <img src=".\pic\misc05.png" alt="" width="200">
</div>





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



### RAR 文件格式

| 结构名称   | 大小   | 内容                                         |
| ---------- | ------ | -------------------------------------------- |
| HEAD_CRC   | 2 byte | 所有块或块部分的 CRC                         |
| HEAD_TYPE  | 1 byte | 块类型                                       |
| HEAD_FLAGS | 2 byte | 块标记 (块标记第一位被置 1，还存在 ADD_SIZE) |
| HEAD_SIZE  | 2 byte | 块大小                                       |
| ADD_SIZE   | 4 byte | 增加块大小 (可选)                            |

文件块的第 3 个字节是块类型，也叫头类型。

| 头类型 | 含义         |
| ------ | ------------ |
| 0x72   | 标记块       |
| 0x73   | 压缩文件头块 |
| 0x74   | 文件头块     |
| 0x75   | 注释头       |

有时给出的 RAR 文件头部各个字块可能被人为修改，导致无法识别。需识别并修复。

<div align="center">
    <img src=".\pic\misc04.png" alt="" width="600">
</div>



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




## 流量提取

PCAP 文件，可能需要先进行修复和重构传输文件，再进行分析。总体大概分为

- 流量包修复
- 协议分析
- 数据提取





## 音频分析

### Audacity 检查波形和频谱隐写

工具 Audacity



### MP3 隐写

MP3Stego 进行解密，其中 `pass` 是文件加密的密码

```shell
$ decode -X -P pass file.mp3
```

可以用以下命令加密，hidden_text.txt 是要加密进 mp3 文件的文本，file.wav 是参与加密的音频，最终产物是 out.mp3

```shell
$ encode -E hidden_text.txt -P pass file.wav out.mp3
```

命令大全

```
-X               提取隐藏数据
-P <text>        用密码用于嵌入
-A               编写AIFF输出PCM声音文件
-s <sb>          仅在此SB（仅调试）
   inputBS       编码音频的输入位
   outPCM        输出PCM声音文件（DFLT输入+.AIF | .pcm）
   outhidden     输出隐藏的文本文件（dflt inputbs+.txt）
```



### 音频 LSB 隐写

使用工具 Silenteye 检验和破译





## 内存、磁盘取证

内存中储存的数据比硬盘更实时和动态，包括临时缓存、解密密钥等

常见的内存镜像文件后缀有：

- .raw  内存取证工具 dumplt 的
- .vmem  虚拟机的虚拟内存文件
- .img  mac 系统的文件镜像副本
- .dmp
- .data

常见的磁盘



### Volatility 工具

**获取内存镜像详细信息**

imageinfo 是 Volatility 中用于获取内存镜像信息的命令。它可以用于确定内存镜像的操作系统类型、版本、架构等信息，以及确定应该使用哪个插件进行内存分析

```shell
python2 vol.py -f Challenge.raw imageinfo  # -f：指定分析的内存镜像文件名
```

```
Suggested Profile(s) 显示了 Volatility 推荐的几个内存镜像分析配置文件，可以根据这些配置文件来选择合适的插件进行内存分析
AS Layer2 显示了使用的内存镜像文件路径
KDBG 显示了内存镜像中的 KDBG 结构地址
Number of Processors 显示了处理器数量
Image Type 显示了操作系统服务包版本
Image date and time 显示了内存镜像文件的创建日期和时间
```

**获取正在运行的程序**

这里我们用 Win7SP1x64 配置文件进行分析，Volatility 的 pslist 插件可以遍历内存镜像中的进程列表，显示每个进程的进程 ID、名称、父进程 ID、创建时间、退出时间和路径等信息

```shell
python2 vol.py -f Challenge.raw --profile=Win7SP1x64 pslist
# --profile 用于指定操作系统
```

**提取正在运行的程序**

Volatility 的 procdump 插件可以根据进程 ID 或进程名称提取进程的内存映像，并保存为一个单独的文件

比如这里提取 iexplore.exe 这个程序，它的进程 pid 号为 2728

```shell
python2 vol.py -f Challenge.raw --profile=Win7SP1x64 procdump -p 2728 -D ./
# p：pid进程号
# D：提取程序后保存的地址，./指的是当前shell正在运行的文件夹地址，输入pwd命令可以查看shell当前的地址，简单来说就是保存到当前文件夹
```

成功导出，导出后文件名为 executable.2728.exe

**查看在终端里执行过的命令**

Volatility 的 cmdscan 插件可以扫描内存镜像中的进程对象，提取已执行的 cmd 命令，并将其显示在终端中

```shell
python2 vol.py -f Challenge.raw --profile=Win7SP1x64 cmdscan
```

移动到了 Documents 目录下，echo 一次字符串，然后创建了一个名为 hint.txt 的文件

**查看进程在终端里运行的命令**

Volatility中的cmdline插件可以用于提取进程执行的命令行参数和参数值

```shell
python2 vol.py -f Challenge.raw --profile=Win7SP1x64 cmdline
```

**查找内存中的文件**

Volatility 的 filescan 插件可以在内存中搜索已经打开的文件句柄，从而获取文件名、路径、文件大小等信息

找到 hint.txt 文件，可以使用以下命令

```shell
python2 vol.py -f Challenge.raw --profile=Win7SP1x64 filescan | grep hint.txt
```

**提取内存中的文件**

Volatility 的 dumpfiles 插件可以用来提取系统内存中的文件

这里我要提取 hint.txt 文件，hint.txt 的内存位置为 0x000000011fd0ca70

```shell
python2 vol.py -f Challenge.raw --profile=Win7SP1x64 dumpfiles -Q 0x000000011fd0ca70 -D ./
# Q：内存位置
# D：提取程序后保存的地址，./指的是当前shell正在运行的文件夹地址，输入pwd命令可以查看shell当前的地址，简单来说就是保存到当前文件夹
```

提取出来的文件名是包含内存地址的，更改一下后缀名即可运行

**查看浏览器历史记录**

Volatility 中的 iehistory 插件可以用于提取 Internet Explorer 浏览器历史记录

```shell
python2 vol.py -f Challenge.raw --profile=Win7SP1x64 iehistory
```

**提取用户密码hash值并爆破**

Volatility 中的 Hashdump 插件可以用于提取系统内存中的密码哈希值

```shell
python2 vol.py -f Challenge.raw --profile=Win7SP1x64 hashdump
```

提取到的密码 hash 值，复制粘贴到本地本文 txt 里，可以使用这个[在线网站](https://crackstation.net/)，将 hash 值粘贴上去，就可以得到用户密码明文

**使用 mimikatz 提取密码**

mimikatz 是一个开源的用于从 Windows 操作系统中提取明文密码，哈希值以及其他安全凭据的工具

```shell
python2 vol.py -f Challenge.raw --profile=Win7SP1x64 mimikatz
```

**查看剪切板里的内容**

Volatility 中的 clipboard 插件可以用于从内存转储中提取剪贴板数据

```shell
python2 vol.py -f Challenge.raw --profile=Win7SP1x64 clipboard
```

**查看正在运行的服务**

svcscan 是 Volatility 中的一个插件，用于扫描进程中所有的服务

执行了 svcscan 之后，每列代表服务的一些信息，包括服务名、PID、服务状态、服务类型、路径等等

```shell
svcscan
```

**查看网络连接状态**

Volatility 中的 netscan 插件可以在内存转储中查找打开的网络连接和套接字，该命令将显示所有当前打开的网络连接和套接字。输出包括本地和远程地址、端口、进程 ID 和进程名称等信息

```shell
python2 vol.py -f Challenge.raw --profile=Win7SP1x64 netscan
```

**查看注册表信息**

printkey 是 Volatility 工具中用于查看注册表的插件之一。它可以帮助分析人员查看和解析注册表中的键值，并提供有关键值的详细信息，如名称、数据类型、大小和值等

```shell
python2 vol.py -f Challenge.raw --profile=Win7SP1x64 printkey
```

然后使用 hivelist 插件来确定注册表的地址

```shell
python2 vol.py -f Challenge.raw --profile=Win7SP1x64 hivelist
```

查看注册表 software 项

hivedump 是一个 Volatility 插件，用于从内存中提取 Windows 注册表的内容，这里选择第一个来演示

```shell
python2 vol.py -f Challenge.raw --profile=Win7SP1x64 hivedump -o 0xfffff8a00127d010
# o：hivelist列出的Virtual值
```

根据名称查看具体子项的内容，以 SAM\Domains\Account\Users\Names 做演示，这个是 Windows 系统中存储本地用户账户信息的注册表路径，它包含了每个本地用户账户的名称和对应的 SID 信息

```shell
python2 vol.py -f Challenge.raw --profile=Win7SP1x64 printkey -K "SAM\Domains\Account\Users\Names"
```

如果要提取全部的注册表，可以用这个命令

```shell
python2 vol.py -f Challenge.raw --profile=Win7SP1x64 dumpregistry -D ./
```



### BitLocker

BitLocker 是 Windows 自带的驱动器加密技术，支持 FAT 和 NTFS 两种格式，可以加密电脑的整个系统分区，也可以加密便携储存设备 (U盘, 移动硬盘)

BitLocker 使用 AES 128 位或 256 位加密，这种加密方式只要密码比较复杂，一般很难被破解

BitLocker 的破解方式有几种：

- 输入密码
- 用恢复密钥解密
- 通过内存镜像破解，前提是内存中有密钥痕迹，即计算机解密过 BitLocker，可以使用 EFDD 工具解密



### TrueCrypt

TrueCrypt，是一款免费开源的加密软件，同时支持 Windows Vista,7/XP, Mac OS X, Linux 等操作系统。TrueCrypt 不需要生成任何文件即可在硬盘上建立虚拟磁盘，用户可以按照盘符进行访问，所有虚拟磁盘上的文件都被自动加密，需要通过密码来进行访问。TrueCrypt 提供多种加密算法。但由于已经停止维护了，现在被 VeraCrypt 替代。

TrueCrypt 的破解方式和 BitLocker 基本相同。



### 磁盘挂载

常见的磁盘分区格式有以下几种

- Windows: FAT12 -> FAT16 -> FAT32 -> NTFS
- Linux: EXT2 -> EXT3 -> EXT4

对于 fat 文件，使用 VeraCrypt 即可

对于 ext 文件，使用 `mount` 命令，需要 root 权限，其中 `file` 为 ext 文件，`path` 为要挂载的路径

```shell
$ mount file path
```






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
7. 考虑二维码相关

压缩包：

1. 压缩包密码可考虑 john 或 ARCHPR 暴力破解
2. 文件内内容很少 (4 字节左右) 而密码很长，考虑枚举 CRC32 直接破解文件内容
3. 压缩文件是加密的，可以考虑伪加密
4. 给出一个文件，压缩包内还有一个文件，两个文件 CRC 相同，考虑明文攻击

流量包：

1. 

音频：

1. 音频在波形和频谱上的隐写，可使用 Audacity 查看，可能多和摩斯电码相关
2. MP3 文件考虑 MP3 隐写 (MP3Stego)
3. 音频 LSB 隐写 (Silenteye)

内存、磁盘取证：

1. 要先 imageinfo 拿到版本号
2. 关注可疑进程 (比如 notepad)
3. 工具总结：
   - 内存取证：Volatility
   - 镜像挂载：VeraCrypt (挂载 fat 文件)，`mount` (挂载 ext2 等)
   - 密码恢复：EFDD
   - 磁盘加密解密：BitLocker，VeraCrypt







