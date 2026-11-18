package main

import (
	"github.com/nareyko/denyout/internal/proxy"
	"github.com/nareyko/denyout/internal/serve"
)

const serveUsage = `Usage: denyout-cli serve --config path [--listen 127.0.0.1:8080] [--health-listen addr] [--metrics-listen addr] [--tls-mode intercept|passthrough] [--ca-dir path]

  Long-running policy proxy for sidecar / compose / systemd.
  Same engine as denyout-cli run. Hardened deployments MUST pair with NetworkPolicy
  (or host firewall) so the agent cannot bypass the proxy — docs/08-server.md.

  DENYOUT_KILL=1 refuses to start (fail closed).`

// parseServeArgs parses and validates `serve` flags into serve.Options (pure).
func parseServeArgs(args []string) (serve.Options, *cliExit) {
	var o serve.Options
	var tlsMode string
	fs := flagSet{
		cmd:  "serve",
		help: serveUsage,
		values: []flagSpec{
			{names: []string{"--config", "-c"}, set: setStr(&o.ConfigPath), missing: "--config requires a path"},
			{names: []string{"--listen"}, eq: true, set: setStr(&o.Listen), missing: "--listen requires a value"},
			{names: []string{"--metrics-listen"}, eq: true, set: setStr(&o.MetricsListen), missing: "--metrics-listen requires a value"},
			{names: []string{"--health-listen"}, eq: true, set: setStr(&o.HealthListen), missing: "--health-listen requires a value"},
			{names: []string{"--tls-mode"}, eq: true, set: setStr(&tlsMode), missing: "--tls-mode requires a value"},
			{names: []string{"--ca-dir"}, eq: true, set: setStr(&o.CADir), missing: "--ca-dir requires a path"},
		},
		unknown: "unknown flag %q",
	}
	if ex := fs.parse(args); ex != nil {
		return o, ex
	}
	if o.ConfigPath == "" {
		return o, failExit("denyout-cli serve: --config is required")
	}
	if tlsMode != "" {
		o.TLSMode = proxy.TLSMode(tlsMode)
		if o.TLSMode != proxy.TLSIntercept && o.TLSMode != proxy.TLSPassthrough {
			return o, failExit("denyout-cli serve: invalid tls-mode %q", tlsMode)
		}
	}
	o.Version = version
	return o, nil
}

// serveRun runs the sidecar proxy; swappable in tests.
var serveRun = serve.Run

func cmdServe(args []string) int {
	o, ex := parseServeArgs(args)
	if ex != nil {
		return ex.emit()
	}
	ctx, stop := notifyContext()
	defer stop()
	if err := serveRun(ctx, o); err != nil {
		return failExit("denyout-cli serve: %v", err).emit()
	}
	return 0
}
