package desktop

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/nareyko/denyout/internal/notify"
	"github.com/nareyko/denyout/internal/proxy"
	"github.com/nareyko/denyout/internal/run"
)

type wrapProc struct {
	id      string
	name    string
	cmd     *exec.Cmd
	sess    *run.Session
	started time.Time
}

func (a *App) ensureWraps() {
	a.mu.Lock()
	if a.wraps == nil {
		a.wraps = map[string]*wrapProc{}
	}
	a.mu.Unlock()
}

func (a *App) startProfile(id string) error {
	a.ensureWraps()
	p, err := LoadProfile(id)
	if err != nil {
		return err
	}
	a.mu.Lock()
	if _, ok := a.wraps[id]; ok {
		a.mu.Unlock()
		return fmt.Errorf("%s is already running", p.Name)
	}
	a.mu.Unlock()

	cfg, err := p.PolicyConfig()
	if err != nil {
		return err
	}
	sandbox := strings.TrimSpace(p.Sandbox)
	if p.RequireIsolation && sandbox == "" {
		sandbox = "srt"
	}
	if (sandbox == "srt" || p.RequireIsolation) && !run.SRTAvailable() {
		return fmt.Errorf("stronger isolation required but srt was not found in PATH - install sandbox-runtime or turn off require_isolation")
	}

	var sessRef *run.Session
	profileName := p.Name
	profileID := p.ID
	ask := p.AskMode
	notifyBlocks := p.Notify
	threats := a.ensureThreatStore(false)
	sess, err := run.StartSession(run.SessionOptions{
		Config:        cfg,
		TLSMode:       proxy.TLSIntercept,
		Version:       a.opts.Version,
		Sandbox:       sandbox,
		PolicyProfile: "agent",
		Process:       "wrap:" + p.ID,
		Threats:       threats,
		OnDeny: func(host string, reasons []string, redactedURL string) {
			a.onWrapDeny(sessRef, profileID, profileName, ask, notifyBlocks, host, reasons, redactedURL)
		},
	})
	if err != nil {
		return err
	}
	sessRef = sess

	cmdArgs := append([]string{}, p.Command...)
	if len(cmdArgs) == 0 {
		_ = sess.Stop()
		return fmt.Errorf("profile has empty command")
	}
	st := sess.Status()
	argv, envExtra, clean, err := run.WrapSandbox(sandbox, cmdArgs, st.ProxyURL)
	if clean != nil {
		defer clean()
	}
	if err != nil {
		_ = sess.Stop()
		return err
	}

	cmd := exec.Command(argv[0], argv[1:]...)
	if p.WorkDir != "" {
		cmd.Dir = p.WorkDir
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	base := os.Environ()
	for k, v := range st.Env {
		base = append(base, k+"="+v)
	}
	base = append(base, envExtra...)
	base = append(base, "DENYOUT_PROFILE_ID="+p.ID)
	if p.Notify {
		base = append(base, "DENYOUT_DESKTOP_NOTIFY=1")
	}
	cmd.Env = base

	if err := cmd.Start(); err != nil {
		_ = sess.Stop()
		return err
	}
	wp := &wrapProc{id: p.ID, name: p.Name, cmd: cmd, sess: sess, started: time.Now()}
	a.mu.Lock()
	a.wraps[p.ID] = wp
	a.state.WrapPIDs = appendPID(a.state.WrapPIDs, cmd.Process.Pid)
	stSave := a.state
	a.mu.Unlock()
	_ = SaveState(stSave)
	notify.Info("DenyOut", "Started: "+p.Name)
	if sandbox == "" {
		fmt.Fprintln(os.Stderr, "denyout: note - without Stronger isolation (srt), some tools can bypass the proxy")
	}

	go func() {
		_ = cmd.Wait()
		_ = sess.Stop()
		a.mu.Lock()
		delete(a.wraps, p.ID)
		a.state.WrapPIDs = removePID(a.state.WrapPIDs, cmd.Process.Pid)
		st2 := a.state
		a.mu.Unlock()
		_ = SaveState(st2)
	}()
	return nil
}

func (a *App) stopProfile(id string) {
	a.ensureWraps()
	a.mu.Lock()
	wp := a.wraps[id]
	delete(a.wraps, id)
	a.mu.Unlock()
	if wp == nil {
		return
	}
	if wp.cmd != nil && wp.cmd.Process != nil {
		_ = wp.cmd.Process.Kill()
		_, _ = wp.cmd.Process.Wait()
		a.mu.Lock()
		a.state.WrapPIDs = removePID(a.state.WrapPIDs, wp.cmd.Process.Pid)
		st := a.state
		a.mu.Unlock()
		_ = SaveState(st)
	}
	if wp.sess != nil {
		_ = wp.sess.Stop()
	}
	notify.Info("DenyOut", "Stopped: "+wp.name)
}

func (a *App) stopAllWraps(reason string) {
	a.stopAllWrapsOpts(reason, false)
}

func (a *App) stopAllWrapsOpts(reason string, force bool) {
	a.ensureWraps()
	a.mu.Lock()
	ids := make([]string, 0, len(a.wraps))
	for id := range a.wraps {
		ids = append(ids, id)
	}
	n := len(ids)
	a.mu.Unlock()
	if n == 0 {
		return
	}
	if !force && n > 1 {
		msg := fmt.Sprintf("Stop %d running agents?", n)
		if reason != "" {
			msg += "\n\n" + reason
		}
		if !nativeConfirm("DenyOut", msg, "Stop all", "Cancel") {
			return
		}
	}
	for _, id := range ids {
		a.stopProfile(id)
	}
}

func (a *App) runningWrapCount() int {
	a.ensureWraps()
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.wraps)
}

func appendPID(list []int, pid int) []int {
	if pid <= 0 {
		return list
	}
	for _, p := range list {
		if p == pid {
			return list
		}
	}
	return append(list, pid)
}

func removePID(list []int, pid int) []int {
	out := list[:0]
	for _, p := range list {
		if p != pid {
			out = append(out, p)
		}
	}
	return out
}

// ProfilePathForCLI exposes profile path for CLI messages.
func ProfilePathForCLI(id string) string {
	return filepath.Join(ProfilesDir(), id+".yaml")
}
