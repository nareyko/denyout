package main

import (
	"github.com/nareyko/denyout/internal/check"
	"github.com/nareyko/denyout/internal/policy"
)

const checkUsage = "Usage: denyout-cli check [--config path] [--json] <url>"

type checkOpts struct {
	cfgPath string
	url     string
	jsonOut bool
}

// parseCheckArgs turns the command line into options (pure).
func parseCheckArgs(args []string) (checkOpts, *cliExit) {
	var o checkOpts
	fs := flagSet{
		cmd:  "check",
		help: checkUsage,
		values: []flagSpec{
			{names: []string{"--config", "-c"}, set: setStr(&o.cfgPath), missing: "--config requires a path"},
		},
		bools:   map[string]func(){"--json": func() { o.jsonOut = true }},
		unknown: "unknown flag %q",
		positional: func(a string) string {
			if o.url != "" {
				return "only one URL allowed"
			}
			o.url = a
			return ""
		},
	}
	if ex := fs.parse(args); ex != nil {
		return o, ex
	}
	if o.url == "" {
		return o, failExit("denyout-cli check: URL required")
	}
	return o, nil
}

// evalCheck loads the policy and evaluates the URL; it returns the outcome
// (verdict text on stdout, exit 1 on deny).
func evalCheck(o checkOpts) *cliExit {
	var cfg *policy.Config
	var err error
	if o.cfgPath != "" {
		cfg, err = policy.LoadFile(o.cfgPath)
	} else {
		cfg, err = policy.DefaultEnforceModels()
	}
	if err != nil {
		return failExit("denyout-cli check: config: %v", err)
	}
	res, err := check.URL(cfg, o.url)
	if err != nil {
		return failExit("denyout-cli check: %v", err)
	}
	text := res.Human()
	if o.jsonOut {
		text = res.JSON()
	}
	code := 0
	if res.Verdict == check.VerdictDeny {
		code = 1
	}
	return &cliExit{code: code, out: text + "\n"}
}

func cmdCheck(args []string) int {
	o, ex := parseCheckArgs(args)
	if ex != nil {
		return ex.emit()
	}
	return evalCheck(o).emit()
}
