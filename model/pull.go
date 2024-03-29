package model

type PRHook struct {
	Action      string       `json:"action"`
	Number      int64        `json:"number"`
	PullRequest *PullRequest `json:"pull_request"`
	Repository  *Repository  `json:"repository"`
	Sender      *User        `json:"sender"`
	Review      *Review      `json:"review"`
	Comment     *Comment     `json:"comment"`
}

type PullRequest struct {
	Number    int64   `json:"number"`
	Title     string  `json:"title"`
	Url       string  `json:"url"`
	Body      string  `json:"body"`
	Base      *Branch `json:"base"`
	Head      *Branch `json:"head"`
	User      *User   `json:"user"`
	Assignees []*User `json:"assignees"`
	Merged    bool    `json:"merged"`
}

type Branch struct {
	Ref  string      `json:"ref"`
	Repo *Repository `json:"repo"`
	SHA  string      `json:"sha"`
}

type User struct {
	Id       int    `json:"id"`
	Login    string `json:"login"`
	FullName string `json:"full_name"`
	Email    string `json:"email"`
	Username string `json:"username"`
	Name     string `json:"name"`
}

type Review struct {
	Type    string `json:"type"`
	Content string `json:"content"`
}
