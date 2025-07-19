from typing import List, Callable
from hashlib import sha256

def hex_to_32byte_chunks(hex_str):
    # 确保十六进制字符串长度是64的倍数（因为32字节 = 64个十六进制字符）
    if len(hex_str) % 64 != 0:
        raise ValueError("十六进制字符串长度必须是64的倍数")

    # 每64个字符分割一次，并转换为字节
    return [bytes.fromhex(hex_str[i:i + 64]) for i in range(0, len(hex_str), 64)]

def openssl_sha256(message: bytes) -> bytes:
    return sha256(message).digest()

class WOTSPLUS:
    def __init__(
        self,
        w: int = 16,  # Winternitz 参数，控制空间与时间的复杂度
        hashfunction: Callable = openssl_sha256,  # 哈希函数
        digestsize: int = 256,  # 摘要大小，单位为比特
        pubkey: List[bytes] = None,
    ) -> None:
        self.w = w
        if not (2 <= w <= (1 << digestsize)):
            raise ValueError("规则错误:2 <= w <= 2^digestsize")
        # 消息摘要所需的密钥数量（默认8个）
        self.msg_key_count = 8
        # 校验和密钥数量
        self.cs_key_count = 0
        # 总密钥数量 = 消息密钥 + 校验和密钥
        self.key_count = self.msg_key_count + self.cs_key_count
        self.hashfunction = hashfunction
        self.digestsize = digestsize
        self.pubkey = pubkey

    @staticmethod
    def number_to_base(num: int, base: int) -> List[int]:
        if num == 0:
            return [0]  # 如果数字是 0，直接返回 0

        digits = []  # 存储转换后的数字位
        while num:
            digits.append(int(num % base))  # 获取当前数字在目标进制下的个位，并添加到结果列表
            num //= base  # 对数字进行整除，处理下一位

        return digits[::-1]  # 返回按顺序排列的结果

    def _chain(self, value: bytes, startidx: int, endidx: int) -> bytes:
        for i in range(startidx, endidx):
            value = self.hashfunction(value)  # 每次迭代对当前哈希值进行哈希操作

        return value

    def get_signature_base_message(self, msghash: bytes) -> List[int]:
        # 将消息哈希从字节转换为整数
        msgnum = int.from_bytes(msghash, "big")

        # 将消息的数字表示转换为特定进制下的比特组表示
        msg_to_sign = self.number_to_base(msgnum, self.w)

        # 校验消息比特组的数量是否符合预期
        if len(msg_to_sign) > self.msg_key_count:
            err = (
                "The fingerprint of the message could not be split into the"
                + " expected amount of bitgroups. This is most likely "
                + "because the digestsize specified does not match to the "
                + " real digestsize of the specified hashfunction Excepted:"
                + " {} bitgroups\nGot: {} bitgroups"
            )
            raise IndexError(err.format(self.msg_key_count, len(msg_to_sign)))

        return msg_to_sign

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
    
    def verify(self, digest: bytes, signature: List[bytes]) -> bool:
        pubkey = self.get_pubkey_from_signature(digest, signature)
        return True if pubkey == self.pubkey else False

if __name__ == "__main__":
    pubkey_hex = "5057432973dc856a7a00272d83ea1c14de52b5eb3ba8b70b373db8204eb2f902450e38dbade5e9b8c2c3f8258edc4b7e8101e94ac86e4b3cba92ddf3d5de2a2b454c067a995060d1664669b45974b15b3423cec342024fe9ccd4936670ec3abaae4f6b97279bd8eb26463a8cb3112e6dcbf6301e4142b9cdc4adfb644c7b114af4f0cf8f80e22c3975ba477dc4769c3ef67ffdf2090735d81d07bc2e6235af1ee41ef332215422d31208c2bc2163d6690bd32f4926b2858ca41c12eec88c0a300571901a3f674288e4a623220fb6b70e558d9819d2f23da6d897278f4056c346d7f729f5f70805ad4e5bd25cfa502c0625ac02185e014cf36db4ebcdb3ed1a38"
    pubkey_list_bytes = hex_to_32byte_chunks(pubkey_hex)
    wots = WOTSPLUS(pubkey = pubkey_list_bytes)
    digest_hex = "84ffb82e"
    signature_hex = "25d5a0e650d683506bfe9d2eca6a3a99b547a4b99398622f6666ce10131e971b6bd36841c9074fe9b4de2900ebe3fadb3202a173be486da6cf8f3d8c699c95c3454c067a995060d1664669b45974b15b3423cec342024fe9ccd4936670ec3abaae4f6b97279bd8eb26463a8cb3112e6dcbf6301e4142b9cdc4adfb644c7b114a4966398a789b56bdb09ea195925e7e8cde372305d244604c48db08f08a6e8a38951030deb25a7aaf1c07152a302ebc07d5d0893b5e9a5953f3b8500179d138b9aa90c0aaacea0c23d22a25a86c0b747c561b480175b548fcb1f4ad1153413bc74d9c049d43ffe18ceee31e5be8bdb9968103ef32fb4054a4a23c400bbfe0d89f"
    digest_bytes = bytes.fromhex(digest_hex)
    signature = hex_to_32byte_chunks(signature_hex)
    valid = wots.verify(digest_bytes,signature)
    print(valid)
