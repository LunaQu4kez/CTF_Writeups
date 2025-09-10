package main

import (
	"crypto/cipher"
	"errors"
	"github.com/tjfoc/gmsm/sm4"
)

func encrypt(key, nonce, plaintext, additionalData []byte) ([]byte, error) {
	block, err := sm4.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, additionalData)
	// 最终结果为：12字节nonce + 密文 + 16字节认证tag
	return append(nonce, ciphertext...), nil
}

func EncryptOTAPackage(plaintextFilePath string, key, nonce []byte) (ciphertextFilePath string, err error) {
	if len(key) != 16 {
		return "", errors.New("invalid key")
	}
	if len(nonce) != 12 {
		return "", errors.New("invalid nonce")
	}

	// 读取明文 OTA 升级包内容
	// TODO 此处代码已省略

	ciphertextContent, err := encrypt(key, nonce, plaintextContent, nil)
	if err != nil {
		return "", err
	}

	// 以字节流形式将加密后的升级包文件内容写到文件中
	// TODO 此处代码已省略

	return
}

func main() {
	plainFilePath := "./files/firm-v1.0-plain.bin"
	expectedCipherFilePath := "./files/firm-v1.0.bin"
	key := []byte("xxxxxxxxxxxxxxxx")
	nonce := []byte("xxxxxxxxxxxx")
	cipherFilePath, err := EncryptOTAPackage(plainFilePath, key, nonce)
	if err != nil {
		panic(err)
	}
	if cipherFilePath != expectedCipherFilePath {
		panic("invalid cipherFilePath")
	}
}
