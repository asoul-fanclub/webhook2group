package api

const (
	GiteaHeaderEventType = "X-Gitea-Event-Type"
	Push                 = "push"
	PullRequestAssign    = "pull_request_assign"
	IssueComment         = "issue_comment"
	PullRequestComment   = "pull_request_comment"
	PullRequestRejected  = "pull_request_rejected"
	PullRequestApproved  = "pull_request_approved"
	PullRequest          = "pull_request"
	Issues               = "issues"
	IssuesAssign         = "issue_assign"
	GiteaData            = "gitea_data"
	GiteaSignature       = "X-Gitea-Signature"
)
