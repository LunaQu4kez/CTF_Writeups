package client

/*
* 日期：2025/5/21
* 用途：TSP 服务器鉴别 APP 控制端身份
* 作者：X
 */

import (
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"github.com/tjfoc/gmsm/sm2"
	"io"
	"math/big"
)

var errZeroParam = errors.New("zero parameter")
var one = new(big.Int).SetInt64(1)

type Point struct {
	X, Y *big.Int
}

func randFieldElement(c elliptic.Curve, random io.Reader) (k *big.Int, err error) {
	if random == nil {
		random = rand.Reader //If there is no external trusted random source,please use rand.Reader to instead of it.
	}
	params := c.Params()
	b := make([]byte, params.BitSize/8+8)
	_, err = io.ReadFull(random, b)
	if err != nil {
		return
	}
	k = new(big.Int).SetBytes(b)
	n := new(big.Int).Sub(params.N, one)
	k.Mod(k, n)
	k.Add(k, one)
	return
}

type AuthClient struct {
	c               elliptic.Curve
	N               *big.Int
	commonPublicKey *sm2.PublicKey
	D1              *big.Int
	random          io.Reader

	k1 *big.Int
}

// passwd 为 APP 控制端的登录口令
func ComputeD1(passwd string) (*big.Int, error) {
	d1Bytes, err := base64.StdEncoding.DecodeString(passwd)
	if err != nil {
		return nil, err
	}
	return new(big.Int).SetBytes(d1Bytes), nil
}

func NewAuthClient(commonPublicKey *sm2.PublicKey, D1 *big.Int, random io.Reader) (*AuthClient, error) {
	c := sm2.P256Sm2()
	N := c.Params().N
	if N.Sign() == 0 {
		return nil, errZeroParam
	}
	return &AuthClient{c: c, N: N, commonPublicKey: commonPublicKey, D1: D1, random: random}, nil
}

func (signer *AuthClient) GenerateQ1E(msg, uid []byte) (Q1 *Point, e *big.Int, err error) {
	digest, err := signer.commonPublicKey.Sm3Digest(msg, uid)
	if err != nil {
		return nil, nil, err
	}
	e = new(big.Int).SetBytes(digest)

	var k1 *big.Int
	k1, err = randFieldElement(signer.c, signer.random)
	if err != nil {
		return nil, nil, err
	}
	signer.k1 = k1
	x1, y1 := signer.c.ScalarBaseMult(k1.Bytes())
	Q1 = &Point{X: x1, Y: y1}

	return Q1, e, nil
}

func (signer *AuthClient) GenerateS(r, s2, s3 *big.Int) (s *big.Int, err error) {
	t1 := new(big.Int).Mul(signer.D1, signer.k1)
	t1.Mul(t1, s2)
	t2 := new(big.Int).Mul(signer.D1, s3)
	t3 := t1.Add(t1, t2)
	s = t3.Sub(t3, r)
	s.Mod(s, signer.N)

	nMinusR := new(big.Int).Sub(signer.N, r)
	if s.Sign() != 0 && s.Cmp(nMinusR) != 0 {
		return s, nil
	} else {
		return nil, errors.New("invalid s")
	}
}
