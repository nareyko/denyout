package run

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/nareyko/denyout/internal/notify"
	"github.com/nareyko/denyout/internal/proxy"
)

// Options for denyout run.
type Options struct {
	ConfigPath     string
	TLSMode        proxy.TLSMode
	Version        string
	Command        []string
	Sandbox        string // srt when Stronger isolation
	Notify         bool   // OS notifications on deny
	OnDeny         proxy.DenyHook
	RequireSandbox bool // fail closed if Sandbox cannot be applied
}

// Exec starts proxy, wraps child, returns child exit code.
func Exec(opts Options) (int, error) {
	if len(opts.Command) == 0 {
		return 2, fmt.Errorf("no command after --")
	}

	onDeny := opts.OnDeny
	if onDeny == nil && opts.Notify {
		onDeny = notify.Deny
	}
	sess, err := StartSession(SessionOptions{
		ConfigPath: opts.ConfigPath,
		TLSMode:    opts.TLSMode,
		Version:    opts.Version,
		Sandbox:    opts.Sandbox,
		OnDeny:     onDeny,
	})
	if err != nil {
		return 2, err
	}
	defer sess.Stop()

	st := sess.Status()
	fmt.Fprintf(os.Stderr, "denyout: mode=%s preset=%s tls=%s proxy=%s session=%s\n",
		st.Mode, st.Preset, st.TLSMode, st.ProxyURL, st.SessionID)

	sandbox := opts.Sandbox
	if opts.RequireSandbox && sandbox == "" {
		sandbox = "srt"
	}
	argv, envExtra, clean, err := WrapSandbox(sandbox, opts.Command, st.ProxyURL)
	if clean != nil {
		defer clean()
	}
	if err != nil {
		if opts.RequireSandbox || sandbox != "" {
			return 2, err
		}
	}
	if sandbox == "" {
		fmt.Fprintln(os.Stderr, "denyout: note — without OS sandbox / Protect this computer, some tools can bypass the proxy (see docs/10-security-boundaries.md)")
	} else {
		fmt.Fprintf(os.Stderr, "denyout: stronger isolation via %s\n", sandbox)
	}

	cmd := exec.Command(argv[0], argv[1:]...)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	env := childEnv(os.Environ(), st.ProxyURL, st.SessionID, sess.ca)
	env = append(env, envExtra...)
	cmd.Env = env
	setProcGroup(cmd)

	if err := cmd.Start(); err != nil {
		return 2, err
	}
	waitErr := cmd.Wait()
	killProcGroup(cmd)

	code := 0
	if waitErr != nil {
		if ee, ok := waitErr.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			return 2, waitErr
		}
	}
	return code, nil
}

func childEnv(base []string, proxyURL, sessionID string, ca *proxy.SessionCA) []string {
	out := make([]string, 0, len(base)+16)
	skip := map[string]struct{}{
		"HTTP_PROXY": {}, "HTTPS_PROXY": {}, "http_proxy": {}, "https_proxy": {},
		"ALL_PROXY": {}, "all_proxy": {}, "NO_PROXY": {}, "no_proxy": {},
		"SSL_CERT_FILE": {}, "REQUESTS_CA_BUNDLE": {}, "CURL_CA_BUNDLE": {},
		"NODE_EXTRA_CA_CERTS": {}, "GIT_SSL_CAINFO": {},
		"DENYOUT_SESSION_ID": {}, "DENYOUT_PROXY": {},
	}
	for _, e := range base {
		key := e
		if i := indexByte(e, '='); i >= 0 {
			key = e[:i]
		}
		if _, ok := skip[key]; ok {
			continue
		}
		out = append(out, e)
	}
	out = append(out,
		"HTTP_PROXY="+proxyURL,
		"HTTPS_PROXY="+proxyURL,
		"http_proxy="+proxyURL,
		"https_proxy="+proxyURL,
		"NO_PROXY=localhost,127.0.0.1,::1",
		"no_proxy=localhost,127.0.0.1,::1",
		"DENYOUT_SESSION_ID="+sessionID,
		"DENYOUT_PROXY="+proxyURL,
	)
	if ca != nil {
		p := ca.CertFile()
		out = append(out,
			"SSL_CERT_FILE="+p,
			"REQUESTS_CA_BUNDLE="+p,
			"CURL_CA_BUNDLE="+p,
			"NODE_EXTRA_CA_CERTS="+p,
			"GIT_SSL_CAINFO="+p,
		)
	}
	return out
}

func indexByte(s string, c byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == c {
			return i
		}
	}
	return -1
}
