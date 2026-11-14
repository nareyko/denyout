package desktop

import "testing"

func TestIsDenyoutDesktopOrProxyd(t *testing.T) {
	cases := []struct {
		args string
		want bool
	}{
		{"/home/u/.local/bin/denyout desktop", true},
		{"denyout desktop", true},
		{"/home/u/.local/bin/denyout-desktop", true},
		{"denyout-desktop", true},
		{"/home/u/.local/bin/denyout hostctl proxyd --port 1", true},
		{"denyout hostctl proxyd", true},
		{"/home/u/.local/bin/denyout install", false},
		{"/home/u/.local/bin/denyout version", false},
		{"/usr/bin/something else desktop", false},
		{"", false},
	}
	for _, tc := range cases {
		if got := isDenyoutDesktopOrProxyd(tc.args); got != tc.want {
			t.Errorf("isDenyoutDesktopOrProxyd(%q)=%v want %v", tc.args, got, tc.want)
		}
	}
}
