package api

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/cloudwego/hertz/pkg/app/client"
	"github.com/cloudwego/hertz/pkg/protocol"
	"github.com/cloudwego/hertz/pkg/protocol/consts"
	"github.com/goccy/go-json"
	"strings"
)

var (
	AccessTokenRequestURl = "https://open.feishu.cn/open-apis/auth/v3/tenant_access_token/internal"
	ATReqBody             *AccessTokenRequest
	token                 string
)

type AccessTokenRequest struct {
	AppId     string `json:"app_id"`
	AppSecret string `json:"app_secret"`
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
func GetAccessToken() (token string, err error) {
	c, err := client.NewClient()
	if err != nil {
		return
	}
	req, res := protocol.AcquireRequest(), protocol.AcquireResponse()
	defer func() {
		protocol.ReleaseRequest(req)
		protocol.ReleaseResponse(res)
	}()
	req.SetMethod(consts.MethodGet)
	req.Header.SetContentTypeBytes([]byte("application/json"))
	req.SetRequestURI(AccessTokenRequestURl)
	req.SetMethod(consts.MethodPost)
	marshal, err := json.Marshal(*ATReqBody)
	if err != nil {
		return "", err
	}
	fmt.Println(marshal)
	req.SetBody(marshal)
	err = c.Do(context.Background(), req, res)
	if err != nil {
		return
	}
	token = string(res.Body())

	fmt.Printf("%v\n", string(res.Body()))

	return "", nil
}
