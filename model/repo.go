package model

import "strings"

type RepoHook struct {
	Ref        string      `json:"ref"`
	CompareUrl string      `json:"compare_url"`
	HeadCommit *Commit     `json:"head_commit"`
	Repository *Repository `json:"repository"`
	Pusher     *User       `json:"pusher"`
	Sender     *User       `json:"sender"`
}

type Repository struct {
	Name          string `json:"name"`
	Owner         *User  `json:"owner"`
	Empty         bool   `json:"empty"`
	HTMLURL       string `json:"html_url"`
	CloneURL      string `json:"clone_url"`
	DefaultBranch string `json:"default_branch"`
}

func (r *Repository) Instance() string {
	url := strings.Split(r.CloneURL, "/")
	url = url[:len(url)-2]
	return strings.Join(url, "/")
}

func (r *Repository) DataDir(base string) string {
	return base + r.Name
}

type Commit struct {
	SHA       string `json:"id"`
	Message   string `json:"message"`
	Author    *User  `json:"author"`
	Committer *User  `json:"committer"`
}
