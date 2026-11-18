package main

import (
	"fmt"
	"os"

	"github.com/nareyko/denyout/internal/desktop"
	"github.com/nareyko/denyout/internal/proxy"
	"github.com/nareyko/denyout/internal/run"
)

const runUsage = "Usage: denyout-cli run [--config path] [--profile id] [--tls-mode intercept|passthrough] [--sandbox=srt] [--notify|--no-notify] -- <command>..."

type runOpts struct {
	cfgPath        string
	tlsMode        string
	sandbox        string
	profileID      string
	requireSandbox bool
	notify         bool
	command        []string
}

// parseRunArgs turns `run` flags (before "--") and the wrapped command (after
// it) into options. getenv supplies DENYOUT_NOTIFY (pure given getenv).
func parseRunArgs(args []string, getenv func(string) string) (runOpts, *cliExit) {
	o := runOpts{tlsMode: string(proxy.TLSIntercept), notify: getenv("DENYOUT_NOTIFY") != "0"}
	flagArgs, cmdArgs := splitDash(args)
	o.command = cmdArgs
	fs := flagSet{
		cmd:  "run",
		help: runUsage,
		values: []flagSpec{
			{names: []string{"--config", "-c"}, set: setStr(&o.cfgPath), missing: "--config requires a path"},
			{names: []string{"--profile"}, eq: true, set: setStr(&o.profileID), missing: "--profile requires an id"},
			{names: []string{"--tls-mode"}, eq: true, set: setStr(&o.tlsMode), missing: "--tls-mode requires a value"},
			{names: []string{"--sandbox"}, eq: true, set: setStr(&o.sandbox), missing: "--sandbox requires a value"},
		},
		bools: map[string]func(){
			"--notify":    func() { o.notify = true },
			"--no-notify": func() { o.notify = false },
		},
		unknown: "unknown flag %q (command must follow --)",
	}
	if ex := fs.parse(flagArgs); ex != nil {
		return o, ex
	}
	return o, nil
}

// profileSpec is what a saved profile contributes to a run.
type profileSpec struct {
	configPath       string
	command          []string
	sandbox          string
	requireIsolation bool
	workDir          string
}

// runDeps are the side effects of `run`, swappable in tests.
type runDeps struct {
	getenv      func(string) string
	loadProfile func(id string) (profileSpec, error)
	chdir       func(dir string) error
	exec        func(run.Options) (int, error)
}

func realRunDeps() runDeps {
	return runDeps{
		getenv:      os.Getenv,
		loadProfile: loadProfileSpec,
		chdir:       os.Chdir,
		exec:        run.Exec,
	}
}

// loadProfileSpec loads a saved profile and materialises its temp config.
func loadProfileSpec(id string) (profileSpec, error) {
	p, err := desktop.LoadProfile(id)
	if err != nil {
		return profileSpec{}, fmt.Errorf("profile: %w", err)
	}
	cfgFile, err := p.WriteTempConfig()
	if err != nil {
		return profileSpec{}, fmt.Errorf("profile config: %w", err)
	}
	return profileSpec{
		configPath:       cfgFile,
		command:          append([]string{}, p.Command...),
		sandbox:          p.Sandbox,
		requireIsolation: p.RequireIsolation,
		workDir:          p.WorkDir,
	}, nil
}

// applyProfile merges the profile named by o.profileID into o.
func applyProfile(o *runOpts, d runDeps) *cliExit {
	p, err := d.loadProfile(o.profileID)
	if err != nil {
		return failExit("denyout-cli run: %v", err)
	}
	o.cfgPath = p.configPath
	if len(o.command) == 0 {
		o.command = p.command
	}
	if o.sandbox == "" {
		o.sandbox = p.sandbox
	}
	o.requireSandbox = p.requireIsolation
	if p.workDir != "" {
		if err := d.chdir(p.workDir); err != nil {
			return failExit("denyout-cli run: workdir: %v", err)
		}
	}
	return nil
}

// validateRun checks the resolved options before anything is executed.
func validateRun(o runOpts) (proxy.TLSMode, *cliExit) {
	if len(o.command) == 0 {
		return "", failExit("denyout-cli run: missing -- <command> (or --profile with a command)")
	}
	mode := proxy.TLSMode(o.tlsMode)
	if mode != proxy.TLSIntercept && mode != proxy.TLSPassthrough {
		return "", failExit("denyout-cli run: invalid tls-mode %q", o.tlsMode)
	}
	return mode, nil
}

// execRun resolves the profile, validates and runs the wrapped command.
func execRun(o runOpts, d runDeps) *cliExit {
	if o.profileID != "" {
		if ex := applyProfile(&o, d); ex != nil {
			return ex
		}
	}
	mode, ex := validateRun(o)
	if ex != nil {
		return ex
	}
	code, err := d.exec(run.Options{
		ConfigPath:     o.cfgPath,
		TLSMode:        mode,
		Version:        version,
		Command:        o.command,
		Sandbox:        o.sandbox,
		RequireSandbox: o.requireSandbox,
		Notify:         o.notify || d.getenv("DENYOUT_DESKTOP_NOTIFY") == "1",
	})
	if err == nil {
		return &cliExit{code: code}
	}
	if code == 0 {
		code = 2
	}
	return &cliExit{code: code, err: fmt.Sprintf("denyout-cli run: %v\n", err)}
}

func cmdRun(args []string) int {
	d := realRunDeps()
	o, ex := parseRunArgs(args, d.getenv)
	if ex != nil {
		return ex.emit()
	}
	return execRun(o, d).emit()
}
