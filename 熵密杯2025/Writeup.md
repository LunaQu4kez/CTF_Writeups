# 第三届熵密杯 Writeup

战队：COMPASS

共 205 队参赛，排名 37 / 205，获得优胜奖（好歹是有个奖）

题目包含的一些文件在 [这里](./file)，文件夹名称就是题目名称



## 初始谜题

一共 3 道初始谜题，除了第 3 题难度都不低（做出来的队伍明显较少），我们做出来了第 3 题

### 初始谜题 3

首先观察加密的核心代码

```python
def get_pubkey_from_signature(
        self, digest: bytes, signature: List[bytes]
) -> List[bytes]:
    msg_to_verify = self.get_signature_base_message(digest)

    result = []
    for idx, val in enumerate(msg_to_verify):
        sig_part = signature[idx]
        chained_val = self._chain(sig_part, val, self.w - 1)
        result.append(chained_val)
    return result

def _chain(self, value: bytes, startidx: int, endidx: int) -> bytes:
    for i in range(startidx, endidx):
        value = self.hashfunction(value)  # 每次迭代对当前哈希值进行哈希操作
    return value
```

将签名 `signature` 分成 8 组，第 i 个切片进行 `self.w - digest[i]` 次哈希函数操作进行加密（其中 `self.w` 为常量 16）

题目给出了能够通过验证的 `digest`, `signature` 对（如下），现要伪造一组不同的 `digest`, `signature` 对能够通过验证

```python
digest_hex = "9e8fa15a"
signature_hex = "76d6fed961632702ce28c2cd655febefd1beedcd64d68743ba15c68b4a3b88e8ec4bd33a959f7e73b9dc54de1fbcd9d43a351f6667f00f8f1eb5bb435d680a517bccd5b37a151e67a7633d1d702f7849566962941d7110646cec7e8542da6edcad3f275fecc78a996402f494139cd68074bdc0f919834e5c0ca66ac2d32f923138b67138be09347eaa5fd01231bbc74c65dda093f8377c85e66f23286cd5eccf4181077386c0d7c98ae05b922ef61c9998cbdf0e5c8c16d972f480a5df6b24dc3b52e08371b282a9e3441b39dbe959bd9031a7a4d5dfbf794dd4163e33f140f15f792f89ebf2d4c863927e10f7bae1553d0ae4e77da38885ed19883cbebd4210"
```

最简单的思路就是将 `digest` 的首位加上 1，使得 `signature` 的第 1 个切片在加密时少被哈希函数操作一次，同时将 `signature` 第 1 个切片修改为自己先哈希一次，这样能够保证最终结果一致从而通过验证

```python
class WOTSPLUS:    
    def sol(self, digest: bytes, signature: List[bytes]) -> bytes:
        msg_to_verify = self.get_signature_base_message(digest)
        result = b""
        for idx, val in enumerate(msg_to_verify):
            sig_part = signature[idx]
            if idx == 0:
                sig_part = self.hashfunction(sig_part)
            result += sig_part
        return result

digest_new = "ae8fa15a"
sig_new = wots.sol(bytes.fromhex(digest_new), signature)
print(hex(int.from_bytes(sig_new, "big")))
```



## TSP 服务器登陆

从 `login_service.go` 的函数 `Login` 逻辑可知，需要`username`、`authInfo`和证书才能登陆，首先观察给的 txt 文件（USB 传输抓包文件）

注意每一条指令的第一个字节为标志位，需要忽略不计，然后将传输内容拼在一起即可得到证书，打开证书可以看到 `username` 为 `shangmibeiadmin` 

```cer
-----BEGIN CERTIFICATE-----
MIICXzCCAgWgAwIBAgIIRdOoIoXXdMAwCgYIKoEcz1UBg3UwNjELMAkGA1UEBhMC
Q04xEzARBgNVBAoTClNoYW5nTWlCZWkxEjAQBgNVBAMTCVNoYW5nTWlDQTAeFw0y
NTA2MDkwMjUwNDlaFw00NTEwMTAxMjAxMDFaMFUxEzARBgNVBAoTClNoYW5nTWlC
ZWkxFzAVBgNVBAsTDlNoYW5nTWlCZWkyMDI1MRgwFgYDVQQDEw9zaGFuZ21pYmVp
YWRtaW4xCzAJBgNVBAYTAkNOMFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAE7+t5
4QoxLPHIhxkdATembEfiRb//K8HBn9L4rJqVMb8dGN2Q9Q8ARuUSuV7q3oZPxJ4w
sks9VEvU/Ahk90Cy6aOB3TCB2jAOBgNVHQ8BAf8EBAMCA4gwHQYDVR0lBBYwFAYI
KjYBBQUHAwIGCCsGAQUFBwMBMA8GA1UdDgQIBAYBAgMEBQYwDwYDVR0jBAgwBoAE
AQIDBDAuBgNVHREEJzAlgQtnaXRAZ2l0LmNvbYcEfwAAAYcQIAFIYAAAIAEAAAAA
AAAAaDBXBgNVHR8EUDBOMCWgI6Ahhh9odHRwOi8vY3JsMS5leGFtcGxlLmNvbS9j
YTEuY3JsMCWgI6Ahhh9odHRwOi8vY3JsMi5leGFtcGxlLmNvbS9jYTEuY3JsMAoG
CCqBHM9VAYN1A0gAMEUCIAd+mmPuM/Cy+/D1Cs8bWGV1e9mvrcM6RZ9NHxWGHPlt
AiEAjv414wEmlZd3PU7AkYaO5Dz6GbVoXxwj0ROR9OH+Dvw=
-----END CERTIFICATE-----
```

根据给出的资料 GM-T 0017-2023《智能密码钥匙密码应用接口数据格式规范》中定义的 Digest 接口规范和 ECCSignData 规范可以在抓包文件中对应到 Digest 和 ECCSignData 的数据，再根据以下代码可以得知，鉴别信息有以上两项拼接而成，据此即可伪造出鉴别信息登入系统获取 flag1

```go
randomStr := authInfo[0:128]
signature := authInfo[128:]

_, err = ValidateSignature(randomStr, signature, &sm2PubKey)
if err != nil {
	return "", err
}
```



