package main

import (
	"fmt"
	"os"
)

const starterConfig = `apiVersion: denyout/v1
kind: Config

metadata:
  name: local
  description: "Starter policy — preset models, enforce, TLS intercept"

mode: enforce
preset: models

tls:
  mode: intercept
  session_ca: true

listen:
  host: 127.0.0.1
  port: 0

allow_private: false
allow_ip_literals: false
deny_on_dns_failure: true

allowed_ports: [443, 80]

allow: []
deny: []

scanners:
  hard_secrets_in_audit_mode: true
  min_value_len: 6
  named_query:
    enabled: true
  high_entropy:
    enabled: false
  canaries:
    - "DENYOUT_CANARY_"
    - "ARVISER_CANARY_"

audit:
  jsonl_path: "~/.local/state/denyout/audit.jsonl"
  stdout: false
`

type initOpts struct{ path string }

func parseInitArgs(args []string) (initOpts, *cliExit) {
	o := initOpts{path: "denyout.yaml"}
	fs := flagSet{
		cmd:  "init",
		help: "Usage: denyout-cli init [path]",
		positional: func(a string) string {
			o.path = a
			return ""
		},
	}
	if ex := fs.parse(args); ex != nil {
		return o, ex
	}
	return o, nil
}

// writeStarter creates the starter config at path unless it already exists.
func writeStarter(path string) *cliExit {
	if _, err := os.Stat(path); err == nil {
		return failExit("denyout-cli init: %s already exists", path)
	}
	if err := os.WriteFile(path, []byte(starterConfig), 0o644); err != nil {
		return failExit("denyout-cli init: %v", err)
	}
	return &cliExit{out: fmt.Sprintf("wrote %s\n", path)}
}

func cmdInit(args []string) int {
	o, ex := parseInitArgs(args)
	if ex != nil {
		return ex.emit()
	}
	return writeStarter(o.path).emit()
}
