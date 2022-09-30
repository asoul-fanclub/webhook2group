package model

type PRHook struct {
	Number      int64        `json:"number"`
	PullRequest *PullRequest `json:"pull_request"`
	Repository  *Repository  `json:"repository"`
}

type PullRequest struct {
	Number int64   `json:"number"`
	Title  string  `json:"title"`
	Base   *Branch `json:"base"`
	Head   *Branch `json:"head"`
}

type Branch struct {
	Ref  string      `json:"ref"`
	Repo *Repository `json:"repo"`
	SHA  string      `json:"sha"`
}
