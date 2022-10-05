package model

type IssueHook struct {
	Action     string      `json:"action"`
	Number     int64       `json:"number"`
	Issue      *Issue      `json:"issue"`
	Repository *Repository `json:"repository"`
	Sender     *User       `json:"sender"`
}

type Issue struct {
	Id        int     `json:"id"`
	Url       string  `json:"url"`
	HtmlUrl   string  `json:"html_url"`
	Number    int64   `json:"number"`
	User      *User   `json:"user"`
	Title     string  `json:"title"`
	Body      string  `json:"body"`
	Assignee  *User   `json:"assignee"`
	Assignees []*User `json:"assignees"`
}
