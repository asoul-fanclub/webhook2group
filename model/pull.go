package model

type PRHook struct {
	Action      string       `json:"action"`
	Number      int64        `json:"number"`
	PullRequest *PullRequest `json:"pull_request"`
	Repository  *Repository  `json:"repository"`
	Sender      *User        `json:"sender"`
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
}
