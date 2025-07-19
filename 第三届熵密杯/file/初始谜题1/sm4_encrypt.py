import binascii
from pyasn1.codec.der.decoder import decode
from pyasn1.type import univ, namedtype
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from gmssl import sm3, func, sm2
from pyasn1.codec.der.encoder import encode


class SM2Cipher(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('xCoordinate', univ.Integer()), # -- x 分量
        namedtype.NamedType('yCoordinate', univ.Integer()),             # -- y 分量
        namedtype.NamedType('hash', univ.OctetString()),                # --哈希值
        namedtype.NamedType('cipherText', univ.OctetString())           # -- SM4密钥密文
    )

class EncryptedData(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('algorithm', univ.ObjectIdentifier('1.2.156.10197.1.104.2')), # -- SM4-CBC OID
        namedtype.NamedType('iv', univ.OctetString()),                                                # -- SM4-CBC加密使用的初始化向量（IV）
        namedtype.NamedType('cipherText', univ.OctetString())                                         # -- SM4加密的密文
    )

class EnvelopedData(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('encryptedKey', SM2Cipher()),                           # -- 使用SM2公钥加密SM4密钥的密文
        namedtype.NamedType('encryptedData', EncryptedData()),                                  #  -- 使用SM4密钥对明文加密的密文
        namedtype.NamedType('digestAlgorithm', univ.ObjectIdentifier('1.2.156.10197.1.401.1')), # -- SM3算法OID
        namedtype.NamedType('digest', univ.OctetString())                                       # -- 对明文计算的摘要值
    )

def sm4_cbc_encrypt(plaintext: bytes, key: bytes, iv: bytes):
    backend = default_backend()
    cipher = Cipher(algorithms.SM4(key), modes.CBC(iv), backend=backend) #填充模式 nopadding
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(plaintext) + encryptor.finalize()
    return ciphertext

def sm2_encrypt(plaintext: bytes,public_key:bytes) -> bytes:
    sm2_crypt = sm2.CryptSM2(private_key="",public_key=public_key.hex())
    ciphertext = sm2_crypt.encrypt(plaintext)
    return ciphertext

def sm3_hash(text:bytes):
    hash_value = sm3.sm3_hash(func.bytes_to_list(text))
    return hash_value

def read_key_from_file(file_path):
    try:
        with open(file_path, 'r') as file:
            key = file.read().strip()
            return key
    except FileNotFoundError:
        print(f"错误: 文件 {file_path} 未找到。")
    except Exception as e:
        print(f"错误: 发生了未知错误 {e}。")
    return None

# 对由abcd组成的字符串加密的方法
def sm4_encrypt(plaintext:str,sm2_public_key: str,sm4_iv:str):
    sm4_key = bytes.fromhex(read_key_from_file("key.txt")) #从文件读取固定的key
    # sm4
    envelope = EnvelopedData()
    plaintext_bytes = plaintext.encode('utf-8')
    ciphertext = sm4_cbc_encrypt(plaintext_bytes,sm4_key,bytes.fromhex(sm4_iv))

    # sm2
    encrypted_key = sm2_encrypt(sm4_key,bytes.fromhex(sm2_public_key))

    # sm3
    digest = sm3_hash(plaintext_bytes)

    envelope['encryptedData'] = EncryptedData()
    envelope['encryptedData']['iv'] = univ.OctetString(bytes.fromhex(sm4_iv))
    envelope['encryptedData']['cipherText'] = univ.OctetString(ciphertext)

    envelope['encryptedKey'] = SM2Cipher()
    envelope['encryptedKey']['xCoordinate'] = univ.Integer(int.from_bytes(encrypted_key[:32], 'big'))
    envelope['encryptedKey']['yCoordinate'] = univ.Integer(int.from_bytes(encrypted_key[32:64], 'big'))
    envelope['encryptedKey']['hash'] = univ.OctetString(encrypted_key[64:96])
    envelope['encryptedKey']['cipherText'] = univ.OctetString(encrypted_key[96:])

    envelope['digest'] = univ.OctetString(bytes.fromhex(digest))
    return encode(envelope).hex()

# 从asn1格式的16进制字符串提取参数
def asn1_parse(asn1_hex_str:str,asn1_spec):
    # 将16进制字符串转换为字节
    der_bytes = binascii.unhexlify(asn1_hex_str)
    # 解码为ASN.1对象
    enveloped_data, _ = decode(der_bytes, asn1Spec=asn1_spec)
    # sm2
    sm2_x = hex(int(enveloped_data['encryptedKey']['xCoordinate']))[2:]
    sm2_y = hex(int(enveloped_data['encryptedKey']['yCoordinate']))[2:]
    sm2_hash = enveloped_data['encryptedKey']['hash'].asOctets().hex()
    sm2_ciphertext = enveloped_data['encryptedKey']['cipherText'].asOctets().hex()

    # sm4
    sm4_algorithm = str(enveloped_data['encryptedData']['algorithm'])
    sm4_iv = enveloped_data['encryptedData']['iv'].asOctets().hex()
    sm4_cipherText = enveloped_data['encryptedData']['cipherText'].asOctets().hex()

    # sm3
    digestAlgorithm = str(enveloped_data['digestAlgorithm'])
    digest = enveloped_data['digest'].asOctets().hex()

    # 输出提取的值
    print("asn1格式的16进制字符串:")
    print(f"  asn1: {asn1_hex_str}")
    print("SM2参数:")
    print(f"  xCoordinate: {sm2_x}")
    print(f"  yCoordinate: {sm2_y}")
    print(f"  hash: {sm2_hash}")
    print(f"  cipherText: {sm2_ciphertext}")

    print("SM4参数:")
    print(f"  algorithm: {sm4_algorithm}")
    print(f"  iv: {sm4_iv}")
    print(f"  cipherText: {sm4_cipherText}")

    print("SM3参数:")
    print(f"  digestAlgorithm: {digestAlgorithm}")
    print(f"  digest: {digest}")


if __name__ == "__main__":
    plaintext = "6163616263626161626461646464636361626263626464626361616164636462636462646461646461626462646361636264616364646462646462626261636261646163626463636262616462646462616362616363646463646361616263646261636164636263646163646161636164646364646261626463636462636162636162646261626163636161616463616261646264616162646162626162626462616363616161636362616461626463616462646261626264626464626262636363636162616261626163616164616462626163636164646161646361626363646462626261636261636164646262646362616263636363626461636164646261636361646463616161626164626461636163636461646164616161616163616164636164646261646163626163636164616162636263616461636261646264626263626264636164646263616164626463626461646364616362626261616262616264616361626264636264616461646163626364626462636161636262636163616261616262626362636463616263616364616363626163636363636262646363616464626461616363646361626162636261636364646362626462616364626462626161616264636162626263626462626264646162626462616261616264626161616363636364616263626461636162616462616363616461646363636261636363616162646164626361616464646463646263646363636164626164646463646361636364616261626261646461646463626161616361626161626362626262636164626463636163626163616163636262646463646162616363616364636164646364626464626164626162636161616263646164636461626161636262646463636462646161636462626264626463646364636362626264616362646462636263616361626262616464636263616464616363646163616262616162626261626261616461636361636164636162626461646264636162646363636263616363646161636464626161616462636464646164616361646264616361626263646264616162636164636462616164646163616461646362626464"
    sm2_key = "044f66804d1d30f4499377b96dc8e18faab8300ebddf3eb0fa2065214c260d64c08c6dfe7d9923d6d5baa3a0512a2ede03357c723230ebf77906f82dc1b0fccc1e"
    iv = "43d4192f9f74e90543d4192f9f74e905"
    asn1_hex_str = sm4_encrypt(bytes.fromhex(plaintext).decode('utf-8'),sm2_key,iv)
    asn1_parse(asn1_hex_str,EnvelopedData())




