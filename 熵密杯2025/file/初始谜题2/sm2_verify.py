import binascii
from datetime import datetime
from pyasn1.type import univ, namedtype
from pyasn1.codec.der.encoder import encode
from pyasn1.codec.der.decoder import decode
from gmssl import sm2
from pyasn1.codec.der import decoder, encoder
from pyasn1_modules import rfc2459
from gmssl.sm2 import CryptSM2
from pyasn1.type.useful import GeneralizedTime
from pyasn1.type.univ import Sequence
from pyasn1.type import useful


class ECPrimeFieldConfig(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('fieldType', univ.ObjectIdentifier('1.2.840.10045.1.1')),  # Prime field OID
        namedtype.NamedType('prime', univ.Integer()),  # Prime number p
    )


class ECCurveParameters(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('coefficientA', univ.OctetString()),  # Curve coefficient a
        namedtype.NamedType('coefficientB', univ.OctetString()),  # Curve coefficient b
    )


class ECDomainParameters(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('version', univ.Integer(1)),  # Version number (1)
        namedtype.NamedType('fieldParameters', ECPrimeFieldConfig()),  # Field parameters 包含参数oid，p
        namedtype.NamedType('curveParameters', ECCurveParameters()),  # Curve parameters 包含参数a，b
        namedtype.NamedType('basePoint', univ.OctetString()),  # Base point G 基点
        namedtype.NamedType('order', univ.Integer()),  # Order n of base point 参数n
        namedtype.NamedType('cofactor', univ.Integer(1)),  # Cofactor 余因子 固定值为1
    )


class SM2SignatureValue(univ.Sequence):
    componentType = namedtype.NamedTypes(
        namedtype.NamedType('r', univ.Integer()),  # First part of signature
        namedtype.NamedType('s', univ.Integer()),  # Second part of signature
    )


class SM2SignedData(univ.Sequence):
    componentType = namedtype.NamedTypes(
        # version
        namedtype.NamedType('version', univ.Integer()),
        # 哈希算法 OID（SM3）
        namedtype.NamedType('digestAlgorithms', univ.ObjectIdentifier()),
        # 签名值 r, s
        namedtype.NamedType('sm2Signature', SM2SignatureValue()),
        # 曲线参数
        namedtype.NamedType('ecDomainParameters', ECDomainParameters()),
        # 证书
        namedtype.NamedType('certificate', univ.OctetString()),
        # 签名时间
        namedtype.NamedType('timestamp', GeneralizedTime()),
    )


# 输入值全部为16进制字符串,g为x，y坐标的16进制字符串进行拼接
# p,a,b,n,g对应曲线参数;r,s为签名值的两部分
def asn1_package(version, oid, signature, curve_params, cert_hex, time_stamp):
    sm2_signed_data = SM2SignedData()
    # version
    sm2_signed_data['version'] = version
    # 哈希算法 OID（SM3）
    sm2_signed_data['digestAlgorithms'] = oid
    # 签名值 r, s
    sm2_signed_data["sm2Signature"] = SM2SignatureValue()
    sm2_signed_data["sm2Signature"]['r'] = int(signature[:64], 16)
    sm2_signed_data["sm2Signature"]['s'] = int(signature[64:], 16)
    # 曲线参数
    sm2_signed_data["ecDomainParameters"] = ECDomainParameters()
    sm2_signed_data["ecDomainParameters"]["fieldParameters"] = ECPrimeFieldConfig()
    sm2_signed_data["ecDomainParameters"]["fieldParameters"]["prime"] = int(curve_params['p'], 16)
    sm2_signed_data["ecDomainParameters"]["curveParameters"] = ECCurveParameters()
    sm2_signed_data["ecDomainParameters"]["curveParameters"]["coefficientA"] = univ.OctetString(
        bytes.fromhex(curve_params['a']))
    sm2_signed_data["ecDomainParameters"]["curveParameters"]["coefficientB"] = univ.OctetString(
        bytes.fromhex(curve_params['b']))
    sm2_signed_data["ecDomainParameters"]['basePoint'] = univ.OctetString(bytes.fromhex('04' + curve_params['g']))
    sm2_signed_data["ecDomainParameters"]['order'] = int(curve_params['n'], 16)
    # 证书
    sm2_signed_data["certificate"] = univ.OctetString(bytes.fromhex(cert_hex))
    # 时间
    dt = datetime.strptime(time_stamp, "%Y-%m-%d %H:%M:%S")
    asn1_time_str = dt.strftime("%Y%m%d%H%M%SZ")
    sm2_signed_data["timestamp"] = GeneralizedTime(asn1_time_str)
    return encode(sm2_signed_data).hex()


class Sm2CertVerifier:
    def __init__(self, cert_hex: str):
        ca_pubkey = "8E1860588D9900C16BD19A0FE0A5ACC600224DBD794FFD34179E03698D52421F46E6D8C6E8AADE512C7B543395AC39C76384726C7F8BA537ABCA0C129ECD9882"
        self.sm2_crypt = sm2.CryptSM2(public_key=ca_pubkey, private_key=None)
        self.cert_tbs, self.signature_bytes, self.cert = self.parse_cert(bytes.fromhex(cert_hex))

    @staticmethod
    def parse_cert(cert_der_bytes: bytes):
        cert, _ = decoder.decode(cert_der_bytes, asn1Spec=rfc2459.Certificate())
        tbs = cert.getComponentByName('tbsCertificate')
        signature_bytes = cert.getComponentByName('signatureValue').asOctets()
        return tbs, signature_bytes, cert

    # 获取签名值
    def decode_rs_from_der(self, signature: bytes) -> bytes:
        seq, _ = decode(signature, asn1Spec=Sequence())
        r = int(seq[0])
        s = int(seq[1])
        r_bytes = r.to_bytes(32, byteorder='big')
        s_bytes = s.to_bytes(32, byteorder='big')
        return r_bytes + s_bytes

    def verify_signature(self, signature: bytes, tbs: str):
        inter_cert_tbs_der = encoder.encode(tbs)
        inter_signature = self.decode_rs_from_der(signature)
        # 验证签名（tbs_der必须完整，签名必须64字节）
        return self.sm2_crypt.verify_with_sm3(inter_signature.hex(), inter_cert_tbs_der)

    def verify_certificate_expiration_date(self, tbs):
        validity = tbs.getComponentByName('validity')
        not_before = validity.getComponentByName('notBefore').getComponent()
        not_after = validity.getComponentByName('notAfter').getComponent()

        # 处理 UTCTime 和 GeneralizedTime 两种类型
        if isinstance(not_before, useful.UTCTime):
            not_before_time = datetime.strptime(str(not_before), "%y%m%d%H%M%SZ")
        elif isinstance(not_before, useful.GeneralizedTime):
            not_before_time = datetime.strptime(str(not_before), "%Y%m%d%H%M%SZ")
        else:
            raise ValueError("Unsupported notBefore time format")

        if isinstance(not_after, useful.UTCTime):
            not_after_time = datetime.strptime(str(not_after), "%y%m%d%H%M%SZ")
        elif isinstance(not_after, useful.GeneralizedTime):
            not_after_time = datetime.strptime(str(not_after), "%Y%m%d%H%M%SZ")
        else:
            raise ValueError("Unsupported notAfter time format")

        now = datetime.now()
        return not_before_time <= now <= not_after_time

    def verify(self):
        # 验证中间证书有效期
        if not self.verify_certificate_expiration_date(self.cert_tbs):
            print("证书已过期或尚未生效")
            return False
        # 验证中间证书签名
        if not self.verify_signature(self.signature_bytes, self.cert_tbs):
            print("证书验证未通过")
            return False
        return True


class SM2Config:
    # sm2参数初始化
    def __init__(self, asn1_str):
        self.sm2_signed_data,asn1_acess = self.hex_to_asn1(asn1_str, SM2SignedData())
        if len(asn1_acess) != 0:
            raise ValueError("asn1长度有问题")
        cert_hex = self.get_hex_value(self.sm2_signed_data['certificate'])
        sm2_cert_verifier = Sm2CertVerifier(cert_hex)
        valid = sm2_cert_verifier.verify()
        if not valid:
            raise TypeError("证书验证不通过")
        g = self.get_hex_value(self.sm2_signed_data['ecDomainParameters']['basePoint'])
        g = g[2:] if g.startswith("04") else g
        self.ecc_table = {
            'n': self.get_hex_value(self.sm2_signed_data['ecDomainParameters']['order']),
            'p': self.get_hex_value(self.sm2_signed_data['ecDomainParameters']['fieldParameters']['prime']),
            'g': g,
            'a': self.get_hex_value(self.sm2_signed_data['ecDomainParameters']['curveParameters']['coefficientA']),
            'b': self.get_hex_value(self.sm2_signed_data['ecDomainParameters']['curveParameters']['coefficientB']),
        }
        public_key = self.extract_public_key(sm2_cert_verifier.cert_tbs)
        self.sm2_crypt = CryptSM2(
            private_key="",
            public_key=public_key,
            ecc_table=self.ecc_table
        )
        self.sign = (int(self.sm2_signed_data['sm2Signature']['r']).to_bytes(32, 'big').hex().upper() +
                     int(self.sm2_signed_data['sm2Signature']['s']).to_bytes(32, 'big').hex().upper())

    @staticmethod
    def hex_to_asn1(hex_str, asn1_spec):
        """
        将16进制字符串转换回ASN.1对象
        :param hex_str: 16进制字符串
        :param asn1_spec: ASN.1结构定义
        :return: ASN.1对象
        """
        # 将16进制字符串转换为字节
        der_bytes = binascii.unhexlify(hex_str)

        # 解码为ASN.1对象
        asn1_object, excess = decode(der_bytes, asn1Spec=asn1_spec)

        return asn1_object,excess

    @staticmethod
    def get_hex_value(value):
        """通用转换函数：将 ASN.1 值转换为 16 进制字符串（大写，无前缀）"""
        if isinstance(value, univ.Integer):
            return format(int(value), 'X')  # Integer -> 直接转十六进制
        elif isinstance(value, univ.OctetString):
            return value.asOctets().hex().upper()  # OctetString -> 字节转十六进制
        else:
            raise TypeError(f"Unsupported type: {type(value)}")

    @staticmethod
    def extract_public_key(tbs):
        spki = tbs.getComponentByName('subjectPublicKeyInfo')
        public_key_bitstring = spki.getComponentByName('subjectPublicKey')
        # 提取位串内容（包含开头的 0x04）
        pubkey_bytes = bytearray(public_key_bitstring.asOctets())
        # 转成十六进制字符串
        return pubkey_bytes.hex()

    def verify_misc(self):
        if (int(self.sm2_signed_data['version']) != 1 or
                str(self.sm2_signed_data['digestAlgorithms']) != '1.2.156.10197.1.401.1' or
                str(self.sm2_signed_data['timestamp']) != "20250520101000Z"):
            return False
        return True

    # sm2验签
    def verify(self, data):
        valid = self.verify_misc()
        if not valid:
            return valid
        valid = self.sm2_crypt.verify_with_sm3(self.sign, data)
        return valid


# 通过该函数可以产生一个合法的SM2SignedData
def generateSM2SignedDataExample():
    # 版本
    version = 1
    # 哈希算法oid
    oid = '1.2.156.10197.1.401.1'
    # 签名值r, s
    signature = '6f8eaff551d0f3fa6de74b75b33e1e58f9fdb4dc58e61c82e11e717ffcf168c4db3d5a90ff3625d12b8b658f8dbab34340c278b412b3aff25489e7feb1c75598'
    r = signature[:64]
    s = signature[64:]
    # 曲线参数
    curve_params = {
        "n": 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123',
        "p": 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF',
        "g": '32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0',
        "a": 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC',
        "b": '28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93',
    }
    # 证书
    cert_hex = '3082017C30820122A003020102020D00947C8427D3E849B48A7E5136300A06082A811CCF550183753036310B300906035504061302434E31133011060355040A130A5368616E674D6942656931123010060355040313095368616E674D694341301E170D3235303532303035353330365A170D3330303531393035353330365A304D310B300906035504061302434E3110300E060355040A1307496E746572434131173015060355040B130E5368616E674D6942656932303235311330110603550403130A7368616E676D696265693059301306072A8648CE3D020106082A811CCF5501822D03420004CECC0005AED684A1E7E39C316E7F3F39BDD0490936BC0E1AFDDC1B9627A05B4418809E5327746EE1977913F036EF0A9A255C27D73C00E45D0BB205B34D2C80D4300A06082A811CCF5501837503480030450220360779CBF5AA6E5E9CC073D95E22C52C09E81CFC06A3916559063A3C8C1DFDE6022100ED0E5E5E51F3894A3EAC11F247739D9F6A88C961D89F68337972BC3CC6BB6706'  # 证书16进制格式
    # 时间
    time_stamp = '2025-05-20 10:10:00'

    # asn1封装
    asn1_package_hex = asn1_package(version, oid, signature, curve_params, cert_hex, time_stamp)
    return(asn1_package_hex)


if __name__ == '__main__':
    # 验签
    data = b"Hello, CryptoCup!"
    asn1_package_hex = generateSM2SignedDataExample()
    sm2_config = SM2Config(asn1_package_hex)
    result = sm2_config.verify(data)
    print(result)
