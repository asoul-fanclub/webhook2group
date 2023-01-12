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
	"time"
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
		// push to repository
		var h model.RepoHook
		if err := c.BindAndValidate(&h); err != nil {
			c.JSON(http.StatusBadRequest, localMsg{err.Error()})
			return
		}
		go startCheckPush(&h, chat)
		c.JSON(http.StatusOK, localMsg{Push})
	case PullRequest:
		// open/close/reopen the pull_request
		var h model.PRHook
		if err := c.BindAndValidate(&h); err != nil {
			c.JSON(http.StatusBadRequest, localMsg{err.Error()})
			return
		}
		// solve the PR request
		go startCheckPR(&h, chat)
		c.JSON(http.StatusOK, localMsg{PullRequest})
	case PullRequestAssign:
		// assign the pr, request someone to review
		var h model.PRHook
		if err := c.BindAndValidate(&h); err != nil {
			c.JSON(http.StatusBadRequest, localMsg{err.Error()})
			return
		}
		go startCheckAssignPR(&h, chat)
		c.JSON(http.StatusOK, localMsg{PullRequestAssign})
	case IssueComment:
		// comment the issue
		var h model.IssueHook
		if err := c.BindAndValidate(&h); err != nil {
			c.JSON(http.StatusBadRequest, localMsg{err.Error()})
			return
		}
		go startCheckIssueComment(&h, chat)
		c.JSON(http.StatusOK, localMsg{IssueComment})
	case Issues:
		// open/close/reopen the issue
		var h model.IssueHook
		if err := c.BindAndValidate(&h); err != nil {
			c.JSON(http.StatusBadRequest, localMsg{err.Error()})
			return
		}
		go startCheckIssue(&h, chat)
		c.JSON(http.StatusOK, localMsg{Issues})
	case PullRequestComment:
		// comment the pr
		var h model.IssueHook
		if err := c.BindAndValidate(&h); err != nil {
			c.JSON(http.StatusBadRequest, localMsg{err.Error()})
			return
		}
		go startCheckPullRequestComment(&h, chat)
		c.JSON(http.StatusOK, localMsg{PullRequestComment})
	case PullRequestRejected:
		// reject the request of review
		var h model.PRHook
		if err := c.BindAndValidate(&h); err != nil {
			c.JSON(http.StatusBadRequest, localMsg{err.Error()})
			return
		}
		go startCheckReviewPR(&h, chat)
		c.JSON(http.StatusOK, localMsg{PullRequestRejected})
	case PullRequestApproved:
		// approve the request of review
		var h model.PRHook
		if err := c.BindAndValidate(&h); err != nil {
			c.JSON(http.StatusBadRequest, localMsg{err.Error()})
			return
		}
		go startCheckReviewPR(&h, chat)
		c.JSON(http.StatusOK, localMsg{PullRequestApproved})
	case IssuesAssign:
		// assign the issue
		var h model.IssueHook
		if err := c.BindAndValidate(&h); err != nil {
			c.JSON(http.StatusBadRequest, localMsg{err.Error()})
			return
		}
		go startCheckIssueAssign(&h, chat)
		c.JSON(http.StatusOK, localMsg{IssuesAssign})
	default:
		c.JSON(http.StatusNotFound, localMsg{"event not supported"})
	}
}

// 处理pr操作事件
func startCheckPR(h *model.PRHook, chat string) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("panic: %s\n", r)
		}
	}()
	// get user_id
	// https://open.feishu.cn/document/ukTMukTMukTM/uUzMyUjL1MjM14SNzITN
	err := getUserIdWithPRHook(h)
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

// 处理pr指派事件
func startCheckAssignPR(h *model.PRHook, chat string) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("panic: %s\n", r)
		}
	}()
	// get user_id
	// https://open.feishu.cn/document/ukTMukTMukTM/uUzMyUjL1MjM14SNzITN
	err := getUserIdWithPRHook(h)
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

// 处理pr review事件
func startCheckReviewPR(h *model.PRHook, chat string) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("panic: %s\n", r)
		}
	}()
	// get user_id
	// https://open.feishu.cn/document/ukTMukTMukTM/uUzMyUjL1MjM14SNzITN
	err := getUserIdWithPRHook(h)
	if err != nil {
		logger.Fatalf("%v", err.Error())
	}
	// solve data
	msg := solvePullRequestReviewData(h)
	msg.ReceiveId = chat
	// send msg
	// https://open.feishu.cn/document/uAjLw4CM/ukTMukTMukTM/reference/im-v1/message/create
	_, _, _ = Send(msg)
}

// 处理issue指派事件
func startCheckIssueAssign(h *model.IssueHook, chat string) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("panic: %s\n", r)
		}
	}()
	// get user_id
	// https://open.feishu.cn/document/ukTMukTMukTM/uUzMyUjL1MjM14SNzITN
	err := getUserIdWithIssueHook(h)
	if err != nil {
		logger.Fatalf("%v", err.Error())
	}
	// solve data
	msg := solveIssueAssignData(h)
	msg.ReceiveId = chat
	// send msg
	// https://open.feishu.cn/document/uAjLw4CM/ukTMukTMukTM/reference/im-v1/message/create
	_, _, _ = Send(msg)
}

// 处理推送事件
func startCheckPush(h *model.RepoHook, chat string) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("panic: %s\n", r)
		}
	}()
	// get user_id
	// https://open.feishu.cn/document/ukTMukTMukTM/uUzMyUjL1MjM14SNzITN
	err := getUserIdWithRepoHook(h)
	if err != nil {
		logger.Fatalf("%v", err.Error())
	}
	// solve data
	msg := solvePushData(h)
	msg.ReceiveId = chat
	// send msg
	// https://open.feishu.cn/document/uAjLw4CM/ukTMukTMukTM/reference/im-v1/message/create
	_, _, _ = Send(msg)
}

// 处理Issue操作事件
func startCheckIssue(h *model.IssueHook, chat string) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("panic: %s\n", r)
		}
	}()
	err := getUserIdWithIssueHook(h)
	if err != nil {
		logger.Fatalf("%v", err.Error())
	}
	msg := solveIssueData(h)
	msg.ReceiveId = chat
	_, _, _ = Send(msg)
}

// 处理issue评论事件
func startCheckIssueComment(h *model.IssueHook, chat string) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("panic: %s\n", r)
		}
	}()
	err := getUserIdWithIssueHook(h)
	if err != nil {
		logger.Fatalf("%v", err.Error())
	}
	msg := solveIssueCommentData(h)
	msg.ReceiveId = chat
	_, _, _ = Send(msg)
}

// 处理pull_request评论事件
func startCheckPullRequestComment(h *model.IssueHook, chat string) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("panic: %s\n", r)
		}
	}()
	err := getUserIdWithIssueHook(h)
	if err != nil {
		logger.Fatalf("%v", err.Error())
	}
	msg := solvePullRequestCommentData(h)
	msg.ReceiveId = chat
	_, _, _ = Send(msg)
}

func getUserIdWithIssueHook(h *model.IssueHook) error {
	// record all relevant persons
	emails := make(map[string]bool)
	if _, ok := UserIdDir.Load(h.Sender.Email); !ok {
		emails[h.Sender.Email] = true
	}
	if _, ok := UserIdDir.Load(h.Issue.User.Email); !ok {
		emails[h.Issue.User.Email] = true
	}
	if h.Comment != nil {
		if _, ok := UserIdDir.Load(h.Comment.User.Email); !ok {
			emails[h.Comment.User.Email] = true
		}
	}
	for _, v := range h.Issue.Assignees {
		if _, ok := UserIdDir.Load(v.Email); !ok {
			emails[v.Email] = true
		}
	}
	return getUserId(emails)
}

func getUserIdWithPRHook(h *model.PRHook) error {
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
	return getUserId(emails)
}

func getUserIdWithRepoHook(h *model.RepoHook) error {
	// record all relevant persons
	emails := make(map[string]bool)
	if _, ok := UserIdDir.Load(h.HeadCommit.Author.Email); !ok {
		emails[h.HeadCommit.Author.Email] = true
	}
	if _, ok := UserIdDir.Load(h.HeadCommit.Committer.Email); !ok {
		emails[h.HeadCommit.Committer.Email] = true
	}
	if _, ok := UserIdDir.Load(h.Pusher.Email); !ok {
		emails[h.Pusher.Email] = true
	}
	return getUserId(emails)
}

func getUserId(emails map[string]bool) error {
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
	for k := range emails {
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
	if resp.Data != nil && resp.Data["email_users"] != nil {
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
	var at AT
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
	id, ok := UserIdDir.Load(h.PullRequest.User.Email)
	if ok {
		at = NewAT(id.(string))
		line = append(line, at)
	} else {
		if h.PullRequest.User.FullName == "" {
			t = NewText(h.PullRequest.User.Username)
			line = append(line, t)
		} else {
			t = NewText(h.PullRequest.User.FullName)
			line = append(line, t)
		}
	}
	t = NewText("\nOperator: ")
	line = append(line, t)
	id, ok = UserIdDir.Load(h.Sender.Email)
	if ok {
		at = NewAT(id.(string))
		line = append(line, at)
	} else {
		if h.Sender.FullName == "" {
			t = NewText(h.Sender.Username)
			line = append(line, t)
		} else {
			t = NewText(h.Sender.FullName)
			line = append(line, t)
		}
	}
	if h.PullRequest.Body != "" {
		t = NewText("\nContent: \n--------------------------------------------------------------\n" +
			h.PullRequest.Body +
			"\n--------------------------------------------------------------")
		line = append(line, t)
	}
	if h.PullRequest.Assignees != nil && len(h.PullRequest.Assignees) != 0 {
		t = NewText("\nAssignees: ")
		line = append(line, t)
		for _, v := range h.PullRequest.Assignees {
			id, ok = UserIdDir.Load(v.Email)
			if ok {
				at = NewAT(id.(string))
				line = append(line, at)
			} else {
				if v.FullName == "" {
					t = NewText(v.Username + " ")
					line = append(line, t)
				} else {
					t = NewText(v.FullName + " ")
					line = append(line, t)
				}
			}
		}
	}
	p.AppendZHContent(line)
	p.SetZHTitle(h.PullRequest.Title)
	return p
}

func solvePushData(h *model.RepoHook) *PostMessage {
	p := NewPostMessage()
	var line []PostItem
	var at AT
	a := NewA("[Push-"+h.Repository.Name+"]", h.CompareUrl)
	line = append(line, a)
	tx := NewText("\n(Head [" + h.Ref + "])")
	line = append(line, tx)
	t := NewText("\nPush By ")
	line = append(line, t)
	id, ok := UserIdDir.Load(h.Pusher.Email)
	if ok {
		at = NewAT(id.(string))
		line = append(line, at)
	} else {
		if h.Pusher.FullName == "" {
			t = NewText(h.Pusher.FullName)
			line = append(line, t)
		} else {
			t = NewText(h.Pusher.FullName)
			line = append(line, t)
		}
	}
	t = NewText("\nOperator: ")
	line = append(line, t)
	id, ok = UserIdDir.Load(h.Sender.Email)
	if ok {
		at = NewAT(id.(string))
		line = append(line, at)
	} else {
		if h.Sender.FullName == "" {
			t = NewText(h.Sender.Username)
			line = append(line, t)
		} else {
			t = NewText(h.Sender.FullName)
			line = append(line, t)
		}
	}
	if h.HeadCommit.Message != "" {
		t = NewText("\nCommit Content: \n--------------------------------------------------------------\n" +
			h.HeadCommit.Message +
			"\n--------------------------------------------------------------")
		line = append(line, t)
	}
	p.AppendZHContent(line)
	p.SetZHTitle("")
	return p
}

func solvePullRequestAssignData(h *model.PRHook) *PostMessage {
	p := NewPostMessage()
	var line []PostItem
	var id any
	var t Text
	var at AT
	a := NewA("[PullRequest-"+h.Repository.Name+" #"+strconv.FormatInt(h.PullRequest.Number, 10)+"] action: "+h.Action, h.PullRequest.Url)
	line = append(line, a)
	tx := NewText("\n(Head [" + h.PullRequest.Head.Ref + "] merge to Base [" + h.PullRequest.Base.Ref + "])")
	line = append(line, tx)
	t = NewText("\nPullRequest By ")
	line = append(line, t)
	id, ok := UserIdDir.Load(h.PullRequest.User.Email)
	if ok {
		at = NewAT(id.(string))
		line = append(line, at)
	} else {
		if h.PullRequest.User.FullName == "" {
			t = NewText(h.PullRequest.User.Username)
			line = append(line, t)
		} else {
			t = NewText(h.PullRequest.User.FullName)
			line = append(line, t)
		}
	}
	t = NewText("\nOperator: ")
	line = append(line, t)
	id, ok = UserIdDir.Load(h.Sender.Email)
	if ok {
		at = NewAT(id.(string))
		line = append(line, at)
	} else {
		if h.Sender.FullName == "" {
			t = NewText(h.Sender.Username)
			line = append(line, t)
		} else {
			t = NewText(h.Sender.FullName)
			line = append(line, t)
		}
	}
	t = NewText("\n")
	line = append(line, t)
	if h.Action == "assigned" {
		if h.PullRequest.Assignees != nil && len(h.PullRequest.Assignees) != 0 {
			id, _ = UserIdDir.Load(h.Sender.Email)
			at = NewAT(id.(string))
			line = append(line, at)
			t = NewText("assign this PR to you")
			line = append(line, t)
			id, ok = UserIdDir.Load(h.PullRequest.Assignees[len(h.PullRequest.Assignees)-1].Email)
			if ok {
				at = NewAT(id.(string))
				line = append(line, at)
			} else {
				if h.PullRequest.Assignees[len(h.PullRequest.Assignees)-1].FullName == "" {
					t = NewText(h.PullRequest.Assignees[len(h.PullRequest.Assignees)-1].Username)
					line = append(line, t)
				} else {
					t = NewText(h.PullRequest.Assignees[len(h.PullRequest.Assignees)-1].FullName)
					line = append(line, t)
				}
			}
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

func solvePullRequestReviewData(h *model.PRHook) *PostMessage {
	p := NewPostMessage()
	var line []PostItem
	var id any
	var t Text
	var at AT
	a := NewA("[PullRequest-"+h.Repository.Name+" #"+strconv.FormatInt(h.PullRequest.Number, 10)+"] action: "+h.Action, h.PullRequest.Url)
	line = append(line, a)
	tx := NewText("\n(Head [" + h.PullRequest.Head.Ref + "] merge to Base [" + h.PullRequest.Base.Ref + "])")
	line = append(line, tx)
	t = NewText("\nPullRequest By ")
	line = append(line, t)
	id, ok := UserIdDir.Load(h.PullRequest.User.Email)
	if ok {
		at = NewAT(id.(string))
		line = append(line, at)
	} else {
		if h.PullRequest.User.FullName == "" {
			t = NewText(h.PullRequest.User.Username)
			line = append(line, t)
		} else {
			t = NewText(h.PullRequest.User.FullName)
			line = append(line, t)
		}
	}
	t = NewText("\nOperator: ")
	line = append(line, t)
	id, ok = UserIdDir.Load(h.Sender.Email)
	if ok {
		at = NewAT(id.(string))
		line = append(line, at)
	} else {
		if h.Sender.FullName == "" {
			t = NewText(h.Sender.Username)
			line = append(line, t)
		} else {
			t = NewText(h.Sender.FullName)
			line = append(line, t)
		}
	}
	s := "\nYour PR was "
	if h.Review.Type == "pull_request_review_rejected" {
		s = s + "rejected"
	} else {
		s = s + "approved"
	}
	s = s + " , plz take a look"
	t = NewText(s)
	line = append(line, t)
	p.AppendZHContent(line)
	p.SetZHTitle(h.PullRequest.Title)
	return p
}

func solveIssueAssignData(h *model.IssueHook) *PostMessage {
	p := NewPostMessage()
	var line []PostItem
	var id any
	var t Text
	var at AT
	a := NewA("[Issue-"+h.Repository.Name+" #"+strconv.FormatInt(h.Issue.Number, 10)+"] action: "+h.Action, h.Issue.HtmlUrl)
	line = append(line, a)
	t = NewText("\nIssue By ")
	line = append(line, t)
	id, ok := UserIdDir.Load(h.Issue.User.Email)
	if ok {
		at = NewAT(id.(string))
		line = append(line, at)
	} else {
		if h.Issue.User.FullName == "" {
			t = NewText(h.Issue.User.Username)
			line = append(line, t)
		} else {
			t = NewText(h.Issue.User.FullName)
			line = append(line, t)
		}
	}
	t = NewText("\nOperator: ")
	line = append(line, t)
	id, ok = UserIdDir.Load(h.Sender.Email)
	if ok {
		at = NewAT(id.(string))
		line = append(line, at)
	} else {
		if h.Sender.FullName == "" {
			t = NewText(h.Sender.Username)
			line = append(line, t)
		} else {
			t = NewText(h.Sender.FullName)
			line = append(line, t)
		}
	}
	t = NewText("\n")
	line = append(line, t)
	if h.Action == "assigned" {
		if h.Issue.Assignees != nil && len(h.Issue.Assignees) != 0 {
			id, _ = UserIdDir.Load(h.Sender.Email)
			at = NewAT(id.(string))
			line = append(line, at)
			t = NewText("assign this PR to you")
			line = append(line, t)
			id, ok = UserIdDir.Load(h.Issue.Assignees[len(h.Issue.Assignees)-1].Email)
			if ok {
				at = NewAT(id.(string))
				line = append(line, at)
			} else {
				if h.Issue.Assignees[len(h.Issue.Assignees)-1].FullName == "" {
					t = NewText(h.Issue.Assignees[len(h.Issue.Assignees)-1].Username)
					line = append(line, t)
				} else {
					t = NewText(h.Issue.Assignees[len(h.Issue.Assignees)-1].FullName)
					line = append(line, t)
				}
			}
			t = NewText(", plz take a look")
			line = append(line, t)
		}
	} else {
		if h.Issue.Assignees != nil && len(h.Issue.Assignees) != 0 {
			id, _ = UserIdDir.Load(h.Sender.Email)
			at = NewAT(id.(string))
			line = append(line, at)
			t = NewText("unassigned this PR for someone")
			line = append(line, t)
		}
	}

	p.AppendZHContent(line)
	p.SetZHTitle(h.Issue.Title)
	return p
}

func solveIssueData(h *model.IssueHook) *PostMessage {
	p := NewPostMessage()
	var line []PostItem
	var at AT
	var t Text
	a := NewA("[Issue-"+h.Repository.Name+" #"+strconv.FormatInt(h.Issue.Number, 10)+"] action: "+h.Action, h.Issue.HtmlUrl)
	line = append(line, a)
	t = NewText("\nIssue By ")
	line = append(line, t)
	id, ok := UserIdDir.Load(h.Issue.User.Email)
	if ok {
		at = NewAT(id.(string))
		line = append(line, at)
	} else {
		if h.Issue.User.FullName == "" {
			t = NewText(h.Issue.User.Username)
			line = append(line, t)
		} else {
			t = NewText(h.Issue.User.FullName)
			line = append(line, t)
		}
	}
	t = NewText("\nOperator: ")
	line = append(line, t)
	id, ok = UserIdDir.Load(h.Sender.Email)
	if ok {
		at = NewAT(id.(string))
		line = append(line, at)
	} else {
		if h.Sender.FullName == "" {
			t = NewText(h.Sender.Username)
			line = append(line, t)
		} else {
			t = NewText(h.Sender.FullName)
			line = append(line, t)
		}
	}
	if h.Issue.Body != "" {
		t = NewText("\nContent: \n--------------------------------------------------------------\n" +
			h.Issue.Body +
			"\n--------------------------------------------------------------")
		line = append(line, t)
	}
	if h.Issue.Assignees != nil && len(h.Issue.Assignees) != 0 {
		t = NewText("\nAssignees: ")
		line = append(line, t)
		for _, v := range h.Issue.Assignees {
			id, ok = UserIdDir.Load(v.Email)
			if ok {
				at = NewAT(id.(string))
				line = append(line, at)
			} else {
				if v.FullName == "" {
					t = NewText(v.Username + " ")
					line = append(line, t)
				} else {
					t = NewText(v.FullName + " ")
					line = append(line, t)
				}
			}
		}
	}
	p.AppendZHContent(line)
	p.SetZHTitle(h.Issue.Title)
	return p
}

func solveIssueCommentData(h *model.IssueHook) *PostMessage {
	p := NewPostMessage()
	var line []PostItem
	var at AT
	var t Text
	a := NewA("[Issue-"+h.Repository.Name+" #"+strconv.FormatInt(h.Issue.Number, 10)+"] action: "+h.Action, h.Issue.HtmlUrl)
	line = append(line, a)
	t = NewText("\nIssue By ")
	line = append(line, t)
	id, ok := UserIdDir.Load(h.Issue.User.Email)
	if ok {
		at = NewAT(id.(string))
		line = append(line, at)
	} else {
		if h.Issue.User.FullName == "" {
			t = NewText(h.Issue.User.Username)
			line = append(line, t)
		} else {
			t = NewText(h.Issue.User.FullName)
			line = append(line, t)
		}
	}
	t = NewText("\nOperator: ")
	line = append(line, t)
	id, ok = UserIdDir.Load(h.Sender.Email)
	if ok {
		at = NewAT(id.(string))
		line = append(line, at)
	} else {
		if h.Sender.FullName == "" {
			t = NewText(h.Sender.Username)
			line = append(line, t)
		} else {
			t = NewText(h.Sender.FullName)
			line = append(line, t)
		}
	}
	if h.Comment.Body != "" {
		t = NewText("\nComment: \n--------------------------------------------------------------\n" +
			h.Comment.Body +
			"\n--------------------------------------------------------------")
		line = append(line, t)
	}
	if h.Issue.Assignees != nil && len(h.Issue.Assignees) != 0 {
		t = NewText("\nAssignees: ")
		line = append(line, t)
		for _, v := range h.Issue.Assignees {
			id, ok = UserIdDir.Load(v.Email)
			if ok {
				at = NewAT(id.(string))
				line = append(line, at)
			} else {
				if v.FullName == "" {
					t = NewText(v.Username + " ")
					line = append(line, t)
				} else {
					t = NewText(v.FullName + " ")
					line = append(line, t)
				}
			}
		}
	}
	p.AppendZHContent(line)
	p.SetZHTitle(h.Issue.Title)
	return p
}

func solvePullRequestCommentData(h *model.IssueHook) *PostMessage {
	p := NewPostMessage()
	var line []PostItem
	var at AT
	var t Text
	a := NewA("[PullRequest-"+h.Repository.Name+" #"+strconv.FormatInt(h.Issue.Number, 10)+"] action: "+h.Action, h.Issue.HtmlUrl)
	line = append(line, a)
	t = NewText("\nPullRequest By ")
	line = append(line, t)
	id, ok := UserIdDir.Load(h.Issue.User.Email)
	if ok {
		at = NewAT(id.(string))
		line = append(line, at)
	} else {
		if h.Issue.User.FullName == "" {
			t = NewText(h.Issue.User.Username)
			line = append(line, t)
		} else {
			t = NewText(h.Issue.User.FullName)
			line = append(line, t)
		}
	}
	t = NewText("\nOperator: ")
	line = append(line, t)
	id, ok = UserIdDir.Load(h.Sender.Email)
	if ok {
		at = NewAT(id.(string))
		line = append(line, at)
	} else {
		if h.Sender.FullName == "" {
			t = NewText(h.Sender.Username)
			line = append(line, t)
		} else {
			t = NewText(h.Sender.FullName)
			line = append(line, t)
		}
	}
	if h.Comment.Body != "" {
		t = NewText("\nComment: \n--------------------------------------------------------------\n" +
			h.Comment.Body +
			"\n--------------------------------------------------------------")
		line = append(line, t)
	}
	if h.Issue.Assignees != nil && len(h.Issue.Assignees) != 0 {
		t = NewText("\nAssignees: ")
		line = append(line, t)
		for _, v := range h.Issue.Assignees {
			id, ok = UserIdDir.Load(v.Email)
			if ok {
				at = NewAT(id.(string))
				line = append(line, at)
			} else {
				if v.FullName == "" {
					t = NewText(v.Username + " ")
					line = append(line, t)
				} else {
					t = NewText(v.FullName + " ")
					line = append(line, t)
				}
			}
		}
	}
	p.AppendZHContent(line)
	p.SetZHTitle(h.Issue.Title)
	return p
}

// Send message
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
		SetTimeout(3*time.Second).
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
