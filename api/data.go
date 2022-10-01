package api

const (
	GiteaHeaderEventType = "X-Gitea-Event-Type"
	Push                 = "push"
	PullRequestAssign    = "pull_request_assign"
	IssueComment         = "issue_comment"
	PullRequest          = "pull_request"
	Issues               = "issues"
	IssuesAssign         = "issue_assign"
	GiteaData            = "gitea_data"
	GiteaSignature       = "X-Gitea-Signature"
)
