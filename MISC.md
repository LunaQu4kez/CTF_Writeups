# MISC

OS: Kali Linux

[TOC]

## 文件

### 文件格式

#### 1. 命令行

```shell
┌──(kali㉿kali)-[~/Desktop]
└─$ file img    
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



### [附] zip 压缩包密码破解

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

### CRC 校验错误

如果打开图片提示错误，导致打不开，可能是 CRC 校验错误





## 总结

通用：

1. 检查文件类型，如果有问题，修改或补全
2. 打开十六进制看看有无线索 (文件内容隐写)
3. 分析组成，若可拆分尝试拆分，拆分后的压缩包密码可考虑 john 或 ARCHPR 破解

图片：

1. 如果是图片，检查图片显示的大小和实际占用存储空间，若相差过大，可能有隐藏信息，可修改图片显示区域大小
2. 右键属性，详细信息，可查看包括位置信息等
3. 如果给出的是两张看似一样的图片，可以通过工具 (如 StegSolve) 分析细微差异
4. 检查 LSB 隐写 !!!
5. 如果发生错误打不开，检查 CRC 校验













