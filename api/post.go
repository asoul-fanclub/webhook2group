package api

import (
	"fmt"
	"github.com/goccy/go-json"
)

const (
	PostSendMsgRequestURL = "https://open.feishu.cn/open-apis/im/v1/messages"
	PostSendParamKey      = "receive_id_type"
	PostSendChatType      = "chat_id"
)

type PostMessage struct {
	ReceiveId string  `json:"receive_id"`
	MsgType   MsgType `json:"msg_type"`
	Content1  PostBody
	Content   string `json:"content"`
}

func NewPostMessage() *PostMessage {
	p := &PostMessage{}
	p.MsgType = MsgTypePost
	return p
}

func (m *PostMessage) Body() map[string]interface{} {
	n := structToMap(m.Content1)
	body, err := json.Marshal(n)
	if err != nil {
		fmt.Printf("%v", err.Error())
		return nil
	}
	m.Content = string(body)
	return structToMap(m)
}

func (m *PostMessage) SetZH(u PostUnit) *PostMessage {
	m.Content1.ZH = u
	return m
}

func (m *PostMessage) SetZHTitle(t string) *PostMessage {
	m.Content1.ZH.Title = t
	return m
}

func (m *PostMessage) AppendZHContent(i []PostItem) *PostMessage {
	m.Content1.ZH.Content = append(m.Content1.ZH.Content, i)
	return m
}

func (m *PostMessage) SetJA(u PostUnit) *PostMessage {
	m.Content1.JA = u
	return m
}

func (m *PostMessage) SetJATitle(t string) *PostMessage {
	m.Content1.JA.Title = t
	return m
}

func (m *PostMessage) AppendJAContent(i []PostItem) *PostMessage {
	m.Content1.JA.Content = append(m.Content1.JA.Content, i)
	return m
}

func (m *PostMessage) SetEN(u PostUnit) *PostMessage {
	m.Content1.EN = u
	return m
}

func (m *PostMessage) SetENTitle(t string) *PostMessage {
	m.Content1.EN.Title = t
	return m
}

func (m *PostMessage) AppendENContent(i []PostItem) *PostMessage {
	m.Content1.EN.Content = append(m.Content1.EN.Content, i)
	return m
}

type PostBody struct {
	ZH PostUnit `json:"zh_cn,omitempty"`
	JA PostUnit `json:"ja_jp,omitempty"`
	EN PostUnit `json:"en_us,omitempty"`
}

type PostUnit struct {
	Title   string       `json:"title,omitempty"`
	Content [][]PostItem `json:"content"`
}

type PostItem interface{}

type Text struct {
	Tag      string `json:"tag"`
	Text     string `json:"text"`
	UnEscape bool   `json:"un_escape,omitempty"`
}

func NewText(text string) Text {
	t := Text{
		Tag:  "text",
		Text: text,
	}
	return t
}

type A struct {
	Tag      string `json:"tag"`
	Text     string `json:"text"`
	Href     string `json:"href"`
	UnEscape bool   `json:"un_escape,omitempty"`
}

func NewA(text, href string) A {
	t := A{
		Tag:  "a",
		Text: text,
		Href: href,
	}
	return t
}

type AT struct {
	Tag    string `json:"tag"`
	UserID string `json:"user_id"`
}

func NewAT(userID string) AT {
	t := AT{
		Tag:    "at",
		UserID: userID,
	}
	return t
}

type Image struct {
	Tag      string `json:"tag"`
	ImageKey string `json:"image_key"`
	Height   int    `json:"height"`
	Width    int    `json:"width"`
}

func NewImage(imageKey string, height, width int) Image {
	t := Image{
		Tag:      "image",
		ImageKey: imageKey,
		Height:   height,
		Width:    width,
	}
	return t
}
