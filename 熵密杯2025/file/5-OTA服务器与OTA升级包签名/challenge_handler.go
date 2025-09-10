package handlers

import (
	"crypto/cipher"
	"crypto/elliptic"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/sm4"
	"math/big"
	"net/http"
)

//go:embed auth_private_key.hex
var gPrivateHex string

//go:embed auth_public_key.hex
var gPublicHex string

var errZeroParam = errors.New("zero parameter")
var one = new(big.Int).SetInt64(1)
var key []byte // SM4/GCM
var nonce []byte
var gPrivateKey *sm2.PrivateKey

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

	// 转换为密钥对象
	gPrivateKey, _, err = HexToSM2Key(gPrivateHex, gPublicHex[2:])
	if err != nil {
		panic("密钥加载失败: " + err.Error())
	}
}

// HexToSM2Key  十六进制字符串转密钥对象
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

// ChallengeHandler 对 APP 控制端发来的挑战值用私钥进行签名并返回给 APP 控制端，APP 控制端对签名值进行验签从而确认 OTA 服务器的身份。
func ChallengeHandler(c *gin.Context) {
	var req struct {
		Challenge string `json:"challenge" binding:"required,min=1,max=2048"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数不合法"})
		return
	}

	// 补 0
	challengeHex := req.Challenge
	if len(challengeHex)%2 == 1 {
		challengeHex = "0" + challengeHex
	}

	challenge, err := hex.DecodeString(challengeHex)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "参数不合法"})
		return
	}

	// 签名
	sigHex, err := signMessage(challenge, gPrivateKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"signature": sigHex})
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

func myRandFieldElement(c elliptic.Curve, msg, d []byte) (k *big.Int, err error) {
	params := c.Params()
	b := make([]byte, params.BitSize/8+8)

	h, err := hash(append(msg, d...))
	if err != nil {
		return
	}
	copy(b, h)
	k = new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, one)
	k.Mod(k, n)
	k.Add(k, one)
	return
}

func mySm2Sign(priv *sm2.PrivateKey, msg, uid []byte) (r, s *big.Int, err error) {
	digest, err := priv.PublicKey.Sm3Digest(msg, uid)
	if err != nil {
		return nil, nil, err
	}
	e := new(big.Int).SetBytes(digest)
	c := priv.PublicKey.Curve
	N := c.Params().N
	if N.Sign() == 0 {
		return nil, nil, errZeroParam
	}
	var k *big.Int
	for {
		for {
			k, err = myRandFieldElement(c, msg, priv.D.Bytes())
			if err != nil {
				r = nil
				return
			}
			r, _ = priv.Curve.ScalarBaseMult(k.Bytes())
			r.Add(r, e)
			r.Mod(r, N)
			if r.Sign() != 0 {
				if t := new(big.Int).Add(r, k); t.Cmp(N) != 0 {
					break
				}
			}

		}
		rD := new(big.Int).Mul(priv.D, r)
		s = new(big.Int).Sub(k, rD)
		d1 := new(big.Int).Add(priv.D, one)
		d1Inv := new(big.Int).ModInverse(d1, N)
		s.Mul(s, d1Inv)
		s.Mod(s, N)
		if s.Sign() != 0 {
			break
		}
	}
	return
}

func signMessage(message []byte, priv *sm2.PrivateKey) (string, error) {
	// 生成 SM2 签名
	r, s, err := mySm2Sign(priv, message, nil)
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
