package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/nareyko/denyout/internal/appstate"
	"github.com/nareyko/denyout/internal/settings"
)

// cmdConfig implements `denyout-cli config show [--json]`.
func cmdConfig(args []string) int {
	if len(args) == 0 || args[0] != "show" {
		fmt.Fprintln(os.Stderr, "Usage: denyout-cli config show [--json]")
		return 2
	}
	jsonOut := false
	for _, a := range args[1:] {
		switch a {
		case "--json":
			jsonOut = true
		default:
			fmt.Fprintf(os.Stderr, "denyout-cli config show: unknown flag %q\n", a)
			return 2
		}
	}
	st := appstate.LoadState()
	vals := settings.Resolve(st, os.Getenv, nil)
	problems := settings.Validate(st)
	if jsonOut {
		type row struct {
			Key    string          `json:"key"`
			Value  string          `json:"value"`
			Source settings.Source `json:"source"`
			Env    string          `json:"env,omitempty"`
		}
		out := struct {
			SchemaVersion int      `json:"schema_version"`
			Settings      []row    `json:"settings"`
			Problems      []string `json:"problems,omitempty"`
		}{SchemaVersion: settings.SchemaVersion}
		for _, v := range vals {
			out.Settings = append(out.Settings, row{v.Key, v.Display(), v.Source, v.Env})
		}
		for _, e := range problems {
			out.Problems = append(out.Problems, e.Error())
		}
		b, _ := json.MarshalIndent(out, "", "  ")
		fmt.Println(string(b))
		return 0
	}
	fmt.Printf("# settings schema v%d (precedence: flag > env > state file > default)\n", settings.SchemaVersion)
	for _, v := range vals {
		fmt.Printf("%-26s %-8s %s\n", v.Key, "["+string(v.Source)+"]", v.Display())
	}
	for _, e := range problems {
		fmt.Fprintf(os.Stderr, "warning: %v\n", e)
	}
	return 0
}
