package sign_package

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"github.com/tjfoc/gmsm/sm2"
	"io/ioutil"
	"math/big"
)

// LoadHexFromFile 从文件加载十六进制密钥
func LoadHexFromFile(filename string) (string, error) {
	data, err := ioutil.ReadFile(filename)
	if err != nil {
		return "", fmt.Errorf("文件读取失败: %v", err)
	}
	return string(data), nil
}

// HexToSM2Key 十六进制字符串转密钥对象
func HexToSM2Key(privateHex, publicHex string) (*sm2.PrivateKey, *sm2.PublicKey, error) {
	// 解析私钥
	privateBytes, err := hex.DecodeString(privateHex)
	if err != nil {
		return nil, nil, fmt.Errorf("私钥解码失败: %v", err)
	}
	privateKey := new(sm2.PrivateKey)
	privateKey.D = new(big.Int).SetBytes(privateBytes)

	// 解析公钥
	publicBytes, err := hex.DecodeString(publicHex)
	if err != nil {
		return nil, nil, fmt.Errorf("公钥解码失败: %v", err)
	}

	// 根据曲线参数重建公钥
	curve := sm2.P256Sm2()
	x := new(big.Int).SetBytes(publicBytes[:32])
	y := new(big.Int).SetBytes(publicBytes[32:])
	privateKey.PublicKey = sm2.PublicKey{
		Curve: curve,
		X:     x,
		Y:     y,
	}

	return privateKey, &privateKey.PublicKey, nil
}

func signMessage(message []byte, priv *sm2.PrivateKey) (string, error) {
	// 生成 SM2 签名
	r, s, err := sm2.Sm2Sign(priv, message, nil, rand.Reader)
	if err != nil {
		return "", err
	}

	// 裸签名
	// 将 r 和 s 转换为字节切片
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	// 确保 r 和 s 为 32 字节
	var rPadded [32]byte
	var sPadded [32]byte
	copy(rPadded[32-len(rBytes):], rBytes)
	copy(sPadded[32-len(sBytes):], sBytes)
	rHex := hex.EncodeToString(rPadded[:])
	sHex := hex.EncodeToString(sPadded[:])

	rawSignature := rHex + sHex
	return rawSignature, nil
}

// 对 OTA 升级包进行签名
func signPackage(filename string) string {
	// 1. 读取文件内容
	content, err := ioutil.ReadFile(filename)
	if err != nil {
		panic("读取文件内容失败: " + err.Error())
	}

	// 2. 加载私钥
	privateHex, _ := LoadHexFromFile("sign_private_key.hex")
	publicHex, _ := LoadHexFromFile("sign_public_key.hex")

	// 转换为密钥对象
	privateKey, _, err := HexToSM2Key(privateHex, publicHex[2:])
	if err != nil {
		panic("密钥加载失败: " + err.Error())
	}

	// 3. 签名并输出结果
	sigHex, err := signMessage(content, privateKey)
	if err != nil {
		panic(err)
	}
	return sigHex
}
