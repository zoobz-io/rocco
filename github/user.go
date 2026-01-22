package github

// GitHubUser represents the response from GET /user.
type GitHubUser struct {
	ID        int64  `json:"id"`
	Login     string `json:"login"`
	Name      string `json:"name"`
	Email     string `json:"email"`
	AvatarURL string `json:"avatar_url"`
	HTMLURL   string `json:"html_url"`
	Type      string `json:"type"`
	SiteAdmin bool   `json:"site_admin"`
}

// HasVerifiedEmail returns true if the user has a non-empty email.
// GitHub only returns the primary verified email in the /user response
// if the user has granted the user:email scope and has a verified email.
func (u *GitHubUser) HasVerifiedEmail() bool {
	return u.Email != ""
}

// GitHubOrg represents an organization from GET /user/orgs.
type GitHubOrg struct {
	ID          int64  `json:"id"`
	Login       string `json:"login"`
	Description string `json:"description"`
	AvatarURL   string `json:"avatar_url"`
}

// GitHubTeam represents a team from GET /user/teams.
type GitHubTeam struct {
	ID           int64         `json:"id"`
	Name         string        `json:"name"`
	Slug         string        `json:"slug"`
	Description  string        `json:"description"`
	Permission   string        `json:"permission"`
	Organization GitHubTeamOrg `json:"organization"`
}

// GitHubTeamOrg is the organization within a team response.
type GitHubTeamOrg struct {
	ID    int64  `json:"id"`
	Login string `json:"login"`
}
