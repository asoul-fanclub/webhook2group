package api

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"github.com/bytedance/gopkg/util/logger"
	"github.com/cloudwego/hertz/pkg/app"
	"io"
	"net/http"
	"webhook2group/config"
	"webhook2group/model"
)

var (
	UserIdDir map[string]int
)

type localMsg struct {
	Msg string `json:"message"`
}

func StartCheck(c *app.RequestContext) {
	if c.GetHeader(GiteaHeaderEventType) == nil || len(c.GetHeader(GiteaHeaderEventType)) == 0 {
		c.JSON(http.StatusNotFound, localMsg{"missing header"})
		return
	}

	// get robot-webhook token and chat_key
	token := c.Param("token")
	chat := c.Param("chat")
	if token == "" || chat == "" {
		c.JSON(http.StatusBadRequest, localMsg{"missing path params"})
		return
	}
	// done: get access_token
	token1, err := GetAccessToken()
	if err != nil {
		logger.Warn(err.Error())
	}
	fmt.Println(token1)

	secret := config.Config.Server.Secret
	if secret != "" {
		sigRaw := c.GetHeader(GiteaSignature)
		if len(sigRaw) == 0 {
			c.JSON(http.StatusBadRequest, localMsg{"bad secret header"})
			return
		}
		sig := string(sigRaw)

		var body []byte
		if cb, err := c.Body(); err == nil {
			body = cb
		}
		if body == nil {
			var err error
			body, err = io.ReadAll(bytes.NewReader(c.Request.Body()))
			if err != nil {
				c.JSON(http.StatusInternalServerError, localMsg{err.Error()})
				return
			}
			c.Set(GiteaData, body)
		}

		sig256 := hmac.New(sha256.New, []byte(secret))
		_, err := io.Writer(sig256).Write(body)
		if err != nil {
			c.JSON(http.StatusInternalServerError, localMsg{err.Error()})
			return
		}

		sigExpected := hex.EncodeToString(sig256.Sum(nil))

		if sig != sigExpected {
			c.JSON(http.StatusUnauthorized, localMsg{"bad secret"})
			return
		}

	}

	switch string(c.GetHeader(GiteaHeaderEventType)) {
	case Push:
		// push into repository or branch created
		var h model.RepoHook
		if err := c.BindAndValidate(&h); err != nil {
			c.JSON(http.StatusBadRequest, localMsg{err.Error()})
			return
		}
		fmt.Println(h)
		//go startCheckPush(&h)

	case PullRequest:
		var h model.PRHook

		if err := c.BindAndValidate(&h); err != nil {
			c.JSON(http.StatusBadRequest, localMsg{err.Error()})
			return
		}
		fmt.Println(h.PullRequest, h.Number, h.Repository)
		go startCheckPR(&h)
		c.JSON(http.StatusCreated, localMsg{"created"})
	case PullRequestAssign:
		fmt.Println(PullRequestAssign)
	case IssueComment:
		fmt.Println(IssueComment)
	case Issues:
		fmt.Println(Issues)
	case IssuesAssign:
		fmt.Println(IssuesAssign)
	default:
		c.JSON(404, localMsg{"event not supported"})
	}
}

func startCheckPR(h *model.PRHook) {
	// record all relevant persons
	dir := make(map[string]bool)
	dir[h.Sender.Email] = true
	dir[h.PullRequest.User.Email] = true
	for _, v := range h.PullRequest.Assignees {
		dir[v.Email] = true
	}
	// get user_id

}
