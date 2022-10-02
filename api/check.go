package api

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"github.com/bytedance/gopkg/util/logger"
	"github.com/cloudwego/hertz/pkg/app"
	"github.com/cloudwego/hertz/pkg/app/client"
	"github.com/cloudwego/hertz/pkg/network/standard"
	"github.com/cloudwego/hertz/pkg/protocol"
	"github.com/cloudwego/hertz/pkg/protocol/consts"
	"github.com/go-resty/resty/v2"
	"github.com/goccy/go-json"
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

// StartCheck 根据event_type分发请求
func StartCheck(c *app.RequestContext) {
	// missing event_type
	if c.GetHeader(GiteaHeaderEventType) == nil || len(c.GetHeader(GiteaHeaderEventType)) == 0 {
		c.JSON(http.StatusNotFound, localMsg{"missing header"})
		return
	}

	// get chat_id
	chat := c.Param("chat")
	if chat == "" {
		c.JSON(http.StatusBadRequest, localMsg{"missing path params"})
		return
	}
	// done: get access_token
	if err := GetAccessToken(); err != nil {
		logger.Fatalf("%v", err.Error())
	}

	// todo: verify Secret(Gitea)
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

	// assign request
	switch string(c.GetHeader(GiteaHeaderEventType)) {
	case Push:
		// push into repository or branch created
		var h model.RepoHook
		if err := c.BindAndValidate(&h); err != nil {
			c.JSON(http.StatusBadRequest, localMsg{err.Error()})
			return
		}
		//go startCheckPush(&h)
		c.JSON(http.StatusCreated, localMsg{Push})
	case PullRequest:
		var h model.PRHook

		if err := c.BindAndValidate(&h); err != nil {
			c.JSON(http.StatusBadRequest, localMsg{err.Error()})
			return
		}
		// solve the PR request
		go startCheckPR(&h, chat)
		c.JSON(http.StatusCreated, localMsg{PullRequest})
	case PullRequestAssign:
		var h model.PRHook

		if err := c.BindAndValidate(&h); err != nil {
			c.JSON(http.StatusBadRequest, localMsg{err.Error()})
			return
		}
		go startCheckAssignPR(&h, chat)
		c.JSON(http.StatusCreated, localMsg{PullRequestAssign})
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

// 处理gitea传来的数据，并使用robot-webhook向对应的group发送消息
func startCheckPR(h *model.PRHook, chat string) {
	// record all relevant persons
	dir := make(map[string]bool)
	dir[h.Sender.Email] = true
	dir[h.PullRequest.User.Email] = true
	for _, v := range h.PullRequest.Assignees {
		dir[v.Email] = true
	}
	emails := make([]string, 0)
	for k, _ := range dir {
		emails = append(emails, k)
	}
	// get user_id
	// https://open.feishu.cn/document/ukTMukTMukTM/uUzMyUjL1MjM14SNzITN
	ids := getUserId(emails)
	// solve data
	msg := solvePullRequestData(h, ids)
	msg.ReceiveId = chat
	// send msg
	// https://open.feishu.cn/document/uAjLw4CM/ukTMukTMukTM/reference/im-v1/message/create
	_, _, _ = Send(msg)
}

// 处理gitea传来的数据，并使用robot-webhook向对应的group发送消息
func startCheckAssignPR(h *model.PRHook, chat string) {
	// record all relevant persons
	dir := make(map[string]bool)
	dir[h.Sender.Email] = true
	dir[h.PullRequest.User.Email] = true
	for _, v := range h.PullRequest.Assignees {
		dir[v.Email] = true
	}
	emails := make([]string, 0)
	for k, _ := range dir {
		emails = append(emails, k)
	}
	// get user_id
	// https://open.feishu.cn/document/ukTMukTMukTM/uUzMyUjL1MjM14SNzITN
	ids := getUserId(emails)
	// solve data
	msg := solvePullRequestData(h, ids)
	msg.ReceiveId = chat
	// send msg
	// https://open.feishu.cn/document/uAjLw4CM/ukTMukTMukTM/reference/im-v1/message/create
	_, _, _ = Send(msg)
}

func getUserId(emails []string) []string {
	ids := make([]string, 0)
	clientCfg := &tls.Config{
		InsecureSkipVerify: true,
	}
	c, err := client.NewClient(
		client.WithTLSConfig(clientCfg),
		client.WithDialer(standard.NewDialer()),
	)
	if err != nil {
		return nil
	}
	req, res := protocol.AcquireRequest(), protocol.AcquireResponse()
	defer func() {
		protocol.ReleaseRequest(req)
		protocol.ReleaseResponse(res)
	}()
	req.SetHeader(AccessTokenHeaderKey, AccessTokenHeaderPrefix+Token)
	req.Header.SetContentTypeBytes([]byte("application/json; charset=utf-8"))
	reqUrI := UserIdRequestURl + "?"
	flag := true
	for _, v := range emails {
		if flag {
			reqUrI = reqUrI + "emails=" + v
			flag = false
		} else {
			reqUrI = reqUrI + "&emails=" + v
		}
	}
	req.SetRequestURI(reqUrI)
	req.SetMethod(consts.MethodGet)
	err = c.Do(context.Background(), req, res)
	if err != nil {
		return nil
	}
	c.CloseIdleConnections()
	resp := &Response{}
	err = json.Unmarshal(res.Body(), &resp)
	if err != nil {
		return nil
	}
	if resp.Data != nil {
		v := resp.Data["email_users"].(map[string]interface{})
		for _, vv := range v {
			vk := vv.([]interface{})
			if len(vk) > 0 {
				ids = append(ids, vk[0].(map[string]interface{})["user_id"].(string))
			}
		}
	}
	return ids
}

func solvePullRequestData(h *model.PRHook, ids []string) *PostMessage {
	p := NewPostMessage()
	var line []PostItem
	a := NewA("[PullRequest-"+h.Repository.Name+"] action: "+h.Action, h.PullRequest.Url)
	line = append(line, a)
	tx := "\n" + "(base " + h.PullRequest.Head.Ref + " merge to " + h.PullRequest.Base.Ref + ")\n"
	t := NewText(tx + h.PullRequest.Body)
	line = append(line, t)
	for _, v := range ids {
		at := NewAT(v)
		line = append(line, at)
	}
	p.AppendZHContent(line)
	p.SetZHTitle(h.PullRequest.Title)
	return p
}

// Send send message
func Send(message Message) (string, *Response, error) {
	res := &Response{}

	if Token == "" {
		return "", res, fmt.Errorf("accessToken is empty")
	}
	clientCfg := &tls.Config{
		InsecureSkipVerify: true,
	}
	//timestamp := time.Now().Unix()
	//sign, err := security.GenSign(config.Config.Server.Secret, timestamp)
	//if err != nil {
	//	return "", res, err
	//}
	//

	body := message.Body()
	//body["timestamp"] = strconv.FormatInt(timestamp, 10)
	//body["sign"] = sign

	reqBytes, err := json.Marshal(body)
	if err != nil {
		return "", res, err
	}
	reqString := string(reqBytes)

	c := resty.New()
	resp, err := c.SetTLSClientConfig(clientCfg).
		SetRetryCount(3).R().
		SetBody(body).
		SetHeader("Accept", "application/json").
		SetHeader("Content-Type", "application/json").
		SetHeader(AccessTokenHeaderKey, AccessTokenHeaderPrefix+Token).
		SetQueryParam(PostSendParamKey, PostSendChatType).
		SetResult(&Response{}).
		ForceContentType("application/json").
		Post(PostSendMsgRequestURL)
	if err != nil {
		return reqString, nil, err
	}

	result := resp.Result().(*Response)
	if result.Code != 0 {
		return reqString, result, fmt.Errorf("send message to feishu error = %s", result.Msg)
	}
	c.SetCloseConnection(true)
	return reqString, result, nil
}
