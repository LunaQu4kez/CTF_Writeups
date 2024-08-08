# Reverse

[TOC]

## 逆向基础知识

### CTF 逆向题型

- 验证用户输入合法性，合法则输出 flag
- 对用户输入进行加解密处理并校验，校验通过则提示 flag 正确
- 使用加壳、花指令、反调试等技术手段，干扰解题的分析和调试
- 更复杂的加密和防分析手段

### 计算机部件

- CPU
- 内存
- 内存分配机制
  - 虚拟内存，分段和分页
  - 内存映射

### 可执行文件

- PE (Portable Executable)：.exe  .dll  .sys 等
- ELF (Executable and Linking Format)

### 寄存器与汇编

Intel x86



## 基本逆向技术

### 常用工具

- IDA Pro：静态调试
- OllyDbg：动态调试

### 壳

- 软件壳分为压缩壳、加密壳

- 软件壳识别：**PEiD** 工具

- 对于加密壳，IDA 插件 **findcrypt** 能够通过特征判断可能存在的算法

### 多语言逆向

- .NET：**dnspy**

- python 反编译：**pyinstxtractor** 

  `python pyinstxtractor.py [filename]` 

- GO：**IDAGolangHelper** 



## 代码对抗

