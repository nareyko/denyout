package main

import (
	"fmt"
	"os"

	"github.com/nareyko/denyout/internal/policy"
)

func cmdPolicy(args []string) int {
	if len(args) == 0 || (args[0] != "validate" && args[0] != "check") {
		fmt.Fprintln(os.Stderr, "Usage: denyout-cli policy check <file>")
		return 2
	}
	if len(args) < 2 {
		fmt.Fprintf(os.Stderr, "denyout-cli policy %s: file required\n", args[0])
		return 2
	}
	raw, err := os.ReadFile(args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "denyout-cli policy %s: %v\n", args[0], err)
		return 2
	}
	if ds := policy.Check(raw); len(ds) > 0 {
		fmt.Fprintf(os.Stderr, "invalid: %s: %d problem(s)\n%s", args[1], len(ds), policy.FormatDiagnostics(raw, ds))
		return 2
	}
	fmt.Println("ok")
	return 0
}
