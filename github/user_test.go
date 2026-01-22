package github

import "testing"

func TestGitHubUser_HasVerifiedEmail(t *testing.T) {
	tests := []struct {
		name  string
		email string
		want  bool
	}{
		{
			name:  "with email",
			email: "test@example.com",
			want:  true,
		},
		{
			name:  "empty email",
			email: "",
			want:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			u := &GitHubUser{Email: tt.email}
			if got := u.HasVerifiedEmail(); got != tt.want {
				t.Errorf("HasVerifiedEmail() = %v, want %v", got, tt.want)
			}
		})
	}
}
