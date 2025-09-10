package controllers

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	jwtgo "github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"github.com/tjfoc/gmsm/sm2"
	"github.com/tjfoc/gmsm/x509"
	"http_svr/config"
	"http_svr/models"
	"http_svr/utils"
	"math/big"
	"net/http"
	"time"
)

// 加载证书
func loadCertificate(certPEM string) (*x509.Certificate, error) {
	//certPEM := "-----BEGIN CERTIFICATE-----\nMIIBQDCB6KADAgECAgECMAoGCCqBHM9VAYN1MBIxEDAOBgNVBAoTB1Jvb3QgQ0Ew\nHhcNMjQwNzI0MDkyMTI5WhcNMjUwNzI0MDkyMTI5WjAaMRgwFgYDVQQKEw9NeSBP\ncmdhbml6YXRpb24wWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAASlPepwTvt5c4rF\nEsg1Mqs+Tyx/BwRkwyWqDyZd/gBFKp7veuoZnGK11c24xPOqR/eQZNW7ugsZW6eb\nLyXSsE9ooycwJTAOBgNVHQ8BAf8EBAMCBaAwEwYDVR0lBAwwCgYIKwYBBQUHAwEw\nCgYIKoEcz1UBg3UDRwAwRAIgG4/snkgUCW819OotUWUfMOo0BzHX8KeTTUSLpIjy\nEO4CIEq6X7h3nVNeFzdtLWdy5+1MeNwsWawHU5YzITsNtqOe\n-----END CERTIFICATE-----\n"
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("无效的证书格式")
	}

	return x509.ParseCertificate(block.Bytes)
}

// 验证证书
func validateCertificate(cert *x509.Certificate, rootCert *x509.Certificate) error {
	// 检查颁发者
	if cert.Issuer.CommonName != rootCert.Subject.CommonName {
		return fmt.Errorf("证书校验失败")
	}
	// 检查颁发者组织
	if len(cert.Issuer.Organization) != 1 || cert.Issuer.Organization[0] != rootCert.Subject.Organization[0] {
		return fmt.Errorf("证书校验失败")
	}
	// 检查颁发者国家
	if len(cert.Issuer.Country) != 1 || cert.Issuer.Country[0] != rootCert.Subject.Country[0] {
		return fmt.Errorf("证书校验失败")
	}

	// 检查有效日期
	if time.Now().Before(cert.NotBefore) || time.Now().After(cert.NotAfter) {
		return fmt.Errorf("证书校验失败")
	}

	// 检查组织
	if len(cert.Subject.Organization) != 1 || cert.Subject.Organization[0] != "ShangMiBei" {
		return fmt.Errorf("证书校验失败")
	}

	// 检查组织单元
	if len(cert.Subject.OrganizationalUnit) != 1 || cert.Subject.OrganizationalUnit[0] != "ShangMiBei2024" {
		return fmt.Errorf("证书校验失败")
	}

	// 检查国家
	if len(cert.Subject.Country) != 1 || cert.Subject.Country[0] != "CN" {
		return fmt.Errorf("证书校验失败")
	}

	// 创建证书链
	roots := x509.NewCertPool()
	roots.AddCert(rootCert)

	opts := x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: time.Now(),
	}

	// 验证证书链
	if _, err := cert.Verify(opts); err != nil {
		return fmt.Errorf("证书链校验失败: %v", err)
	}

	return nil
}

type SM2Signature struct {
	R, S *big.Int
}

// 验证签名
func validateSignature(message, signature string, publicKey *sm2.PublicKey) (bool, error) {
	//rawSignatureHex, err := base64.StdEncoding.DecodeString(base64EncodedSignature)
	hexSignature, err := hex.DecodeString(signature)
	if err != nil {
		return false, fmt.Errorf("invalid signature format")
	}

	isValid := publicKey.Verify([]byte(message), hexSignature)
	if isValid {
		return true, nil
	} else {
		return false, fmt.Errorf("signature is invalid")
	}
}

// Login 登录
func Login(c *gin.Context, conf config.Config) {
	// 解析请求参数
	var req models.LoginReq
	if err := c.ShouldBind(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 校验用户名是否已注册过
	if _, exists := models.Users[req.Username]; !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "username not exists"})
		return
	}

	// 校验随机字符串是否过期
	randomStr, exists := conf.Cache.Get(req.Username)
	if !exists {
		c.JSON(http.StatusBadRequest, gin.H{"error": "random string has expired"})
		return
	}

	// 校验证书
	cert, err := loadCertificate(req.Cert)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if err := validateCertificate(cert, models.RootCert); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 判断是否挑战成功（随机字符串的签名能否用证书中的公钥验签过）
	ecdsaPubKey, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{"error": "public key in cert is not sm2"})
		return
	}
	sm2PubKey := sm2.PublicKey{
		Curve: ecdsaPubKey.Curve,
		X:     ecdsaPubKey.X,
		Y:     ecdsaPubKey.Y,
	}
	isValid, err := validateSignature(randomStr.(string), req.Signature, &sm2PubKey)
	if isValid {
		//c.JSON(http.StatusOK, gin.H{"msg": "success", "flag3": config.Flag3, "download_url": config.DownloadUrl})
		generateToken2(c, req.Username, conf)
	} else {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
	}
}

// 生成令牌
func generateToken2(c *gin.Context, username string, conf config.Config) {
	j := &utils.JWT{
		SigningKey: []byte(conf.SignKey),
	}
	claims := utils.CustomClaims{
		Name: username,
		StandardClaims: jwtgo.StandardClaims{
			NotBefore: time.Now().Unix() - conf.NotBeforeTime, // 签名生效时间
			ExpiresAt: time.Now().Unix() + conf.ExpiresTime,   // 过期时间
			Issuer:    conf.Issuer,                            // 签名的发行者
		},
	}

	token, err := j.CreateToken(claims)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"code": 5091,
			"msg":  "登录失败，系统有误",
		})
		return
	}

	// 将当前用户对应的缓存中的随机字符串删除
	conf.Cache.Delete(username)

	isAdmin := false
	if username == "shangmibeiadmin" {
		isAdmin = true
	}
	c.JSON(http.StatusOK, gin.H{
		"code":     0,
		"msg":      "登录成功",
		"token":    token,
		"is_admin": isAdmin,
	})
	return
}
