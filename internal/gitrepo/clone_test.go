package gitrepo

import "testing"

func TestIsGitHubURL(t *testing.T) {
	tests := []struct {
		in   string
		want bool
	}{
		{"https://github.com/fatihtuzunn/vulnerable_react_app", true},
		{"https://github.com/expressjs/express.git", true},
		{"http://github.com/owner/repo", true},
		{"./testdata/next-app", false},
		{"https://gitlab.com/owner/repo", false},
		{"https://github.com/owner", false},
	}
	for _, tc := range tests {
		if got := IsGitHubURL(tc.in); got != tc.want {
			t.Errorf("IsGitHubURL(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}
