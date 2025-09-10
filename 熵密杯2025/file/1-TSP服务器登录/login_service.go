package service

import (
	"crypto/ecdsa"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/tjfoc/gmsm/sm2"
	"math/big"
)

func (s *LoginService) Login(username, authInfo, certStr string) (token string, err error) {
	// 读取用户证书
	cert, err := s.CertService.LoadCertificate(certStr)
	if err != nil {
		return "", err
	}

	if err := s.CertService.ValidateCertificate(cert, RootCert); err != nil {
		return "", err
	}

	// 校验用户名
	if cert.Subject.CommonName != username {
		err = errors.New("username is not valid")
	}

	// 判断是否挑战成功（随机字符串的签名能否用证书中的公钥验签过）
	ecdsaPubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return "", errors.New("public key in cert is not sm2")
	}
	sm2PubKey := sm2.PublicKey{
		Curve: ecdsaPubKey.Curve,
		X:     ecdsaPubKey.X,
		Y:     ecdsaPubKey.Y,
	}

	// 从 authInfo 中提取 randomStr 和 signature
	if len(authInfo) != 256 {
		return "", errors.New("鉴别信息格式有误")
	}
	randomStr := authInfo[0:128]
	signature := authInfo[128:]

	_, err = ValidateSignature(randomStr, signature, &sm2PubKey)
	if err != nil {
		return "", err
	}
	return s.generateToken(username)
}

// 验证签名
func ValidateSignature(messageHex, signatureHex string, publicKey *sm2.PublicKey) (bool, error) {
	msg, err := hex.DecodeString(messageHex)
	if err != nil {
		return false, errors.New("挑战值格式有误")
	}

	if len(signatureHex) != 128 {
		return false, errors.New("签名值格式有误")
	}

	r, ok := big.NewInt(0).SetString(signatureHex[:64], 16)
	if !ok {
		return false, errors.New("签名值格式有误")
	}
	s, ok := big.NewInt(0).SetString(signatureHex[64:], 16)
	if !ok {
		return false, errors.New("签名值格式有误")
	}

	signature, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		return false, errors.New("签名值格式有误")
	}

	isValid := publicKey.Verify(msg, signature)
	if isValid {
		return true, nil
	} else {
		return false, fmt.Errorf("签名无效")
	}
}
