package api

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/bytedance/gopkg/util/logger"
	"github.com/cloudwego/hertz/pkg/app/client"
	"github.com/cloudwego/hertz/pkg/network/standard"
	"github.com/cloudwego/hertz/pkg/protocol"
	"github.com/cloudwego/hertz/pkg/protocol/consts"
	"github.com/goccy/go-json"
	"strings"
	"time"
)

var (
	AccessTokenRequestURl   = "https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal"
	AccessTokenHeaderPrefix = "Bearer "
	ATReqBody               *AccessTokenRequest
	Token                   string
	ExpireTime              int64
)

type AccessTokenRequest struct {
	AppId     string `json:"app_id"`
	AppSecret string `json:"app_secret"`
}

type AccessTokenResponse struct {
	Code              int    `json:"code"`
	Expire            int64  `json:"expire"`
	Msg               string `json:"msg"`
	TenantAccessToken string `json:"tenant_access_token"`
}

// Decrypt 解密
func Decrypt(encrypt string, key string) (string, error) {
	buf, err := base64.StdEncoding.DecodeString(encrypt)
	if err != nil {
		return "", fmt.Errorf("base64StdEncode Error[%v]", err)
	}
	if len(buf) < aes.BlockSize {
		return "", errors.New("cipher too short")
	}
	keyBs := sha256.Sum256([]byte(key))
	block, err := aes.NewCipher(keyBs[:sha256.Size])
	if err != nil {
		return "", fmt.Errorf("AESNewCipher Error[%v]", err)
	}
	iv := buf[:aes.BlockSize]
	buf = buf[aes.BlockSize:]
	// CBC mode always works in whole blocks.
	if len(buf)%aes.BlockSize != 0 {
		return "", errors.New("ciphertext is not a multiple of the block size")
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(buf, buf)
	n := strings.Index(string(buf), "{")
	if n == -1 {
		n = 0
	}
	m := strings.LastIndex(string(buf), "}")
	if m == -1 {
		m = len(buf) - 1
	}
	return string(buf[n : m+1]), nil
}

// GetAccessToken
// 缓存token，如果判断过期则重新获取
func GetAccessToken() (err error) {
	if ExpireTime > time.Now().Unix() && Token != "" {
		return nil
	}
	clientCfg := &tls.Config{
		InsecureSkipVerify: true,
	}
	c, err := client.NewClient(
		client.WithTLSConfig(clientCfg),
		client.WithDialer(standard.NewDialer()),
	)
	if err != nil {
		return
	}
	req, res := protocol.AcquireRequest(), protocol.AcquireResponse()
	defer func() {
		protocol.ReleaseRequest(req)
		protocol.ReleaseResponse(res)
	}()
	req.Header.SetContentTypeBytes([]byte("application/json"))
	req.SetRequestURI(AccessTokenRequestURl)
	req.SetMethod(consts.MethodPost)
	marshal, err := json.Marshal(*ATReqBody)
	if err != nil {
		return err
	}
	req.SetBody(marshal)
	err = c.Do(context.Background(), req, res)
	if err != nil {
		return
	}
	atr := &AccessTokenResponse{}
	err = json.Unmarshal(res.Body(), &atr)
	if err != nil {
		return err
	}
	if atr.Code == 0 {
		Token = atr.TenantAccessToken
		ExpireTime = time.Now().Unix() + atr.Expire
	} else {
		logger.Fatal("get access_token error")
	}
	fmt.Printf("%v\n", string(res.Body()))
	c.CloseIdleConnections()
	return nil
}
