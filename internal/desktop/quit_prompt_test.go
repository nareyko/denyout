package desktop

import "testing"

func TestQuitPrompt(t *testing.T) {
	const tail = "\n\nCancel keeps DenyOut running."
	cases := []struct {
		name    string
		q       quitInputs
		ok      bool
		primary string
		body    string
	}{
		{"nothing live", quitInputs{}, false, "", ""},
		{"computer", quitInputs{On: true, HasProxyd: true}, true, "Turn off protection and quit", "Quit turns off protection and stops My agents wraps." + tail},
		{"unhealthy browse", quitInputs{On: true, Unhealthy: true}, true, "Clear intent and quit", "Protect is not running. Quit clears restore intent.\n\nCancel keeps DenyOut open."},
		{"unhealthy agents", quitInputs{On: true, Unhealthy: true, AgentsIntent: true}, true, "Clear intent and quit", "Agents only is not running. Quit clears restore intent.\n\nCancel keeps DenyOut open."},
		{"wraps only", quitInputs{WrapsRunning: true}, true, "Stop agents and quit", "Quit stops My agents wraps." + tail},
		{"agents only live", quitInputs{On: true, HasProxyd: true, AgentsIntent: true}, true, "Turn off Agents only and quit", "Quit turns off Agents only and stops My agents wraps. Everyday browsing was already unprotected." + tail},
		{"session", quitInputs{On: true, HasSession: true}, true, "Turn off Session protection and quit", "Quit turns off Session protection and stops My agents wraps." + tail},
		{"unhealthy but live", quitInputs{On: true, Unhealthy: true, HasProxyd: true}, true, "Turn off protection and quit", "Quit turns off protection and stops My agents wraps." + tail},
	}
	for _, c := range cases {
		body, primary, ok := quitPrompt(c.q)
		if ok != c.ok || primary != c.primary || body != c.body {
			t.Errorf("%s: %q %q %v", c.name, body, primary, ok)
		}
	}
}
