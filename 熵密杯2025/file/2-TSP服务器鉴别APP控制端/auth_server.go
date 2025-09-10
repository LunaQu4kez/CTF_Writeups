package server

/*
* 日期：2025/5/21
* 用途：TSP 服务器鉴别 APP 控制端身份
* 作者：X
 */

import (
	"crypto/elliptic"
	"crypto/rand"
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

type AuthServer struct {
	c               elliptic.Curve
	N               *big.Int
	commonPublicKey *sm2.PublicKey
	D2              *big.Int
	random          io.Reader
}

func NewAuthServer(commonPublicKey *sm2.PublicKey, D2 *big.Int, random io.Reader) (*AuthServer, error) {
	c := sm2.P256Sm2()
	N := c.Params().N
	if N.Sign() == 0 {
		return nil, errZeroParam
	}
	return &AuthServer{c: c, N: N, commonPublicKey: commonPublicKey, D2: D2, random: random}, nil
}

func (signer *AuthServer) GenerateRS2S3(Q1 *Point, e *big.Int) (r, s2, s3 *big.Int, err error) {
	x1, y1 := Q1.X, Q1.Y

	for {
		var k2 *big.Int
		k2, err = randFieldElement(signer.c, signer.random)
		if err != nil {
			return nil, nil, nil, err
		}
		x2, y2 := signer.c.ScalarBaseMult(k2.Bytes()) // k2 * G

		var k3 *big.Int
		k3, err = randFieldElement(signer.c, signer.random)
		if err != nil {
			return nil, nil, nil, err
		}

		tempX, tempY := signer.c.ScalarMult(x1, y1, k3.Bytes())
		x3, _ := signer.c.Add(tempX, tempY, x2, y2)

		r = new(big.Int).Add(x3, e)
		r.Mod(r, signer.N)

		if r.Sign() != 0 {
			s2 = new(big.Int).Mul(signer.D2, k3)
			s2.Mod(s2, signer.N)

			s3 = new(big.Int).Add(r, k2)
			s3.Mul(s3, signer.D2)
			s3.Mod(s3, signer.N)
			break
		}
	}
	return r, s2, s3, nil
}

func (signer *AuthServer) Verify(msg []byte, uid []byte, r *big.Int, s *big.Int) bool {
	return sm2.Sm2Verify(signer.commonPublicKey, msg, uid, r, s)
}
