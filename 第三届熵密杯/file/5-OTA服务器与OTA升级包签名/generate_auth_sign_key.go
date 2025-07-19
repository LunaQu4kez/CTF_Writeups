package key_generator

import (
	"crypto/cipher"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/tjfoc/gmsm/sm4"
	"math/big"
)

var key []byte // SM4/GCM
var nonce []byte
var one = new(big.Int).SetInt64(1)
var two = new(big.Int).SetInt64(2)

func init() {
	var err error

	key, err = hex.DecodeString("6c87d37a658ab6b00fee969d4b107ef0")
	if err != nil || len(key) != 16 {
		panic(fmt.Errorf("key 配置有误"))
	}
	nonce, err = hex.DecodeString("17d77a33826174759e01273c")
	if err != nil || len(nonce) != 12 {
		panic(fmt.Errorf("nonce 配置有误"))
	}
}

func hash(data []byte) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	// func (AEAD) Seal(dst []byte, nonce []byte, plaintext []byte, additionalData []byte) []byte
	authTag := gcm.Seal(nil, nonce, []byte(""), data)
	return authTag, nil
}

// 生成对 OTA 升级包签名的私钥
func generateSignKey(masterKey []byte) ([]byte, error) {
	if len(masterKey) != 16 {
		return nil, errors.New("masterKey must be 16 bytes")
	}

	// 将 masterKey 转为整数
	masterKeyInt := new(big.Int).SetBytes(masterKey)

	// 计算 DSign 的高 128 bit
	signKeyHighBytes, err := hash(masterKey)
	if err != nil {
		return nil, err
	}

	// masterKey + 1
	masterKeyInt.Add(masterKeyInt, one)
	// 计算 DSign 的低 128 bit
	signKeyLowBytes, err := hash(masterKeyInt.Bytes())
	if err != nil {
		return nil, err
	}

	// signKeyBytes
	signKeyBytes := append(signKeyHighBytes, signKeyLowBytes...)
	return signKeyBytes, nil
}

// 生成 APP 控制端鉴别 OTA 服务器身份的私钥
func generateAuthKey(masterKey []byte) ([]byte, error) {
	if len(masterKey) != 16 {
		return nil, errors.New("masterKey must be 16 bytes")
	}

	// 将 masterKey 转为整数
	masterKeyInt := new(big.Int).SetBytes(masterKey)

	// masterKey + 2
	masterKeyInt.Add(masterKeyInt, two)
	// 计算 DAuth 的高 128 bit
	authKeyHighBytes, err := hash(masterKeyInt.Bytes())
	if err != nil {
		return nil, err
	}

	// masterKey + 3
	masterKeyInt.Add(masterKeyInt, one)
	// 计算 DAuth 的低 128 bit
	authKeyLowBytes, err := hash(masterKeyInt.Bytes())
	if err != nil {
		return nil, err
	}

	// authKeyBytes
	authKeyBytes := append(authKeyHighBytes, authKeyLowBytes...)
	return authKeyBytes, nil
}
