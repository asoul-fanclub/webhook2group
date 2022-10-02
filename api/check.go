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
	"strconv"
	"sync"
	"webhook2group/config"
	"webhook2group/model"
)

var (
	UserIdDir sync.Map
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
	case PullRequestComment:
		fmt.Println(PullRequestComment)
	case PullRequestRejected:
		fmt.Println(PullRequestRejected)
	case PullRequestApproved:
		fmt.Println(PullRequestApproved)
	case IssuesAssign:
		fmt.Println(IssuesAssign)
	default:
		c.JSON(404, localMsg{"event not supported"})
	}
}

// 处理gitea传来的数据，并使用robot-webhook向对应的group发送消息
func startCheckPR(h *model.PRHook, chat string) {
	// get user_id
	// https://open.feishu.cn/document/ukTMukTMukTM/uUzMyUjL1MjM14SNzITN
	err := getUserId(h)
	if err != nil {
		logger.Fatalf("%v", err.Error())
	}
	// solve data
	msg := solvePullRequestData(h)
	msg.ReceiveId = chat
	// send msg
	// https://open.feishu.cn/document/uAjLw4CM/ukTMukTMukTM/reference/im-v1/message/create
	_, _, _ = Send(msg)
}

// 处理gitea传来的数据，并使用robot-webhook向对应的group发送消息
func startCheckAssignPR(h *model.PRHook, chat string) {
	// get user_id
	// https://open.feishu.cn/document/ukTMukTMukTM/uUzMyUjL1MjM14SNzITN
	err := getUserId(h)
	if err != nil {
		logger.Fatalf("%v", err.Error())
	}
	// solve data
	msg := solvePullRequestAssignData(h)
	msg.ReceiveId = chat
	// send msg
	// https://open.feishu.cn/document/uAjLw4CM/ukTMukTMukTM/reference/im-v1/message/create
	_, _, _ = Send(msg)
}

func getUserId(h *model.PRHook) error {
	// record all relevant persons
	emails := make(map[string]bool)
	if _, ok := UserIdDir.Load(h.Sender.Email); !ok {
		emails[h.Sender.Email] = true
	}
	if _, ok := UserIdDir.Load(h.PullRequest.User.Email); !ok {
		emails[h.PullRequest.User.Email] = true
	}
	for _, v := range h.PullRequest.Assignees {
		if _, ok := UserIdDir.Load(v.Email); !ok {
			emails[v.Email] = true
		}
	}
	if emails == nil || len(emails) == 0 {
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
		return err
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
	for k, _ := range emails {
		if flag {
			reqUrI = reqUrI + "emails=" + k
			flag = false
		} else {
			reqUrI = reqUrI + "&emails=" + k
		}
	}
	req.SetRequestURI(reqUrI)
	req.SetMethod(consts.MethodGet)
	err = c.Do(context.Background(), req, res)
	if err != nil {
		return err
	}
	c.CloseIdleConnections()
	resp := &Response{}
	err = json.Unmarshal(res.Body(), &resp)
	if err != nil {
		return err
	}
	if resp.Data != nil {
		v := resp.Data["email_users"].(map[string]interface{})
		for kk, vv := range v {
			vk := vv.([]interface{})
			if len(vk) > 0 {
				id := vk[0].(map[string]interface{})["user_id"].(string)
				UserIdDir.Store(kk, id)
			}
		}
	}
	return nil
}

func solvePullRequestData(h *model.PRHook) *PostMessage {
	p := NewPostMessage()
	var line []PostItem
	if h.Action == "closed" {
		if h.PullRequest.Merged {
			h.Action = "merged"
		}
	}
	a := NewA("[PullRequest-"+h.Repository.Name+" #"+strconv.FormatInt(h.PullRequest.Number, 10)+"] action: "+h.Action, h.PullRequest.Url)
	line = append(line, a)
	tx := NewText("\n(Head [" + h.PullRequest.Head.Ref + "] merge to Base [" + h.PullRequest.Base.Ref + "])\n")
	line = append(line, tx)
	t := NewText("PullRequest By ")
	line = append(line, t)
	id, _ := UserIdDir.Load(h.PullRequest.User.Email)
	at := NewAT(id.(string))
	line = append(line, at)
	t = NewText("\nOperator: ")
	line = append(line, t)
	id, _ = UserIdDir.Load(h.Sender.Email)
	at = NewAT(id.(string))
	line = append(line, at)
	if h.PullRequest.Body != "" {
		t = NewText("\nContent: " + h.PullRequest.Body + "\n")
		line = append(line, t)
	}
	if h.PullRequest.Assignees != nil && len(h.PullRequest.Assignees) != 0 {
		t = NewText("Assignees: ")
		line = append(line, t)
		for _, v := range h.PullRequest.Assignees {
			id, _ = UserIdDir.Load(v.Email)
			at = NewAT(id.(string))
			line = append(line, at)
		}
	}
	p.AppendZHContent(line)
	p.SetZHTitle(h.PullRequest.Title)
	return p
}

func solvePullRequestAssignData(h *model.PRHook) *PostMessage {
	p := NewPostMessage()
	var line []PostItem
	a := NewA("[PullRequest-"+h.Repository.Name+" #"+strconv.FormatInt(h.PullRequest.Number, 10)+"] action: "+h.Action, h.PullRequest.Url)
	line = append(line, a)
	tx := NewText("\n(Head [" + h.PullRequest.Head.Ref + "] merge to Base [" + h.PullRequest.Base.Ref + "])\n")
	line = append(line, tx)
	t := NewText("PullRequest By ")
	line = append(line, t)
	id, _ := UserIdDir.Load(h.PullRequest.User.Email)
	at := NewAT(id.(string))
	line = append(line, at)
	t = NewText("\nOperator: ")
	line = append(line, t)
	id, _ = UserIdDir.Load(h.Sender.Email)
	at = NewAT(id.(string))
	line = append(line, at)
	if h.PullRequest.Body != "" {
		t = NewText("\nContent: \n--------------------------------------------------------------\n" +
			h.PullRequest.Body +
			"\n--------------------------------------------------------------\n")
		line = append(line, t)
	}
	if h.Action == "assigned" {
		if h.PullRequest.Assignees != nil && len(h.PullRequest.Assignees) != 0 {
			id, _ = UserIdDir.Load(h.Sender.Email)
			at = NewAT(id.(string))
			line = append(line, at)
			t = NewText("assign this PR to you")
			line = append(line, t)
			id, _ = UserIdDir.Load(h.PullRequest.Assignees[len(h.PullRequest.Assignees)-1].Email)
			at = NewAT(id.(string))
			line = append(line, at)
			t = NewText(", plz take a look")
			line = append(line, t)
		}
	} else {
		if h.PullRequest.Assignees != nil && len(h.PullRequest.Assignees) != 0 {
			id, _ = UserIdDir.Load(h.Sender.Email)
			at = NewAT(id.(string))
			line = append(line, at)
			t = NewText("unassigned this PR for someone")
			line = append(line, t)
		}
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
