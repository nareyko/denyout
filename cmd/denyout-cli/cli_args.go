package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
)

// cliExit is the pure outcome of parsing/validating a command line: what to
// print and which exit code to return. Parse functions return it instead of
// printing so the argument handling is unit-testable without side effects.
type cliExit struct {
	code int
	out  string // stdout text, verbatim
	err  string // stderr text, verbatim
}

// emit writes the outcome to the process streams and returns the exit code.
func (e *cliExit) emit() int { return e.emitTo(os.Stdout, os.Stderr) }

// emitTo is emit with explicit streams.
func (e *cliExit) emitTo(stdout, stderr io.Writer) int {
	if e.out != "" {
		fmt.Fprint(stdout, e.out)
	}
	if e.err != "" {
		fmt.Fprint(stderr, e.err)
	}
	return e.code
}

// helpExit is a successful exit that prints text followed by a newline.
func helpExit(text string) *cliExit { return &cliExit{code: 0, out: text + "\n"} }

// failExit is an exit-2 usage/validation error: one line on stderr.
func failExit(format string, a ...any) *cliExit {
	return &cliExit{code: 2, err: fmt.Sprintf(format, a...) + "\n"}
}

// flagSpec describes one value-taking flag ("--name value" and, when eq is
// set, "--name=value"; the = form belongs to names[0]).
type flagSpec struct {
	names []string
	eq    bool
	// set stores the value; a non-empty return is an error message (without
	// the "denyout-cli <cmd>: " prefix) that aborts parsing with exit 2.
	set func(v string) string
	// missing is the message when the flag is last on the line. Empty means
	// the dangling flag is silently ignored (lenient legacy behaviour).
	missing string
}

// flagSet is a tiny declarative argument scanner that reproduces the
// hand-rolled loops it replaced: sequential, first match wins, a value flag
// always consumes the next argument.
type flagSet struct {
	cmd    string // used in the "denyout-cli <cmd>: " prefix
	help   string // printed (plus newline) on -h/--help; "" = no built-in help
	values []flagSpec
	bools  map[string]func()
	// unknown is a format with one %q for unrecognised flags; "" ignores them.
	unknown string
	// positional, if set, receives arguments that do not start with "-".
	positional func(a string) string
}

func (fs *flagSet) prefix() string { return "denyout-cli " + fs.cmd + ": " }

func (fs *flagSet) errExit(msg string) *cliExit { return failExit("%s%s", fs.prefix(), msg) }

// matchValue tries the value flags against a; it returns whether one matched
// and an exit if parsing must stop. *i is advanced past a consumed value.
func (fs *flagSet) matchValue(args []string, i *int) (bool, *cliExit) {
	a := args[*i]
	for _, v := range fs.values {
		var val string
		switch {
		case v.eq && strings.HasPrefix(a, v.names[0]+"="):
			val = strings.TrimPrefix(a, v.names[0]+"=")
		case containsStr(v.names, a):
			*i++
			if *i >= len(args) {
				if v.missing != "" {
					return true, fs.errExit(v.missing)
				}
				return true, nil
			}
			val = args[*i]
		default:
			continue
		}
		if msg := v.set(val); msg != "" {
			return true, fs.errExit(msg)
		}
		return true, nil
	}
	return false, nil
}

// parse scans args; it returns nil when scanning finished normally.
func (fs *flagSet) parse(args []string) *cliExit {
	for i := 0; i < len(args); i++ {
		a := args[i]
		if fs.help != "" && (a == "--help" || a == "-h") {
			return helpExit(fs.help)
		}
		if f, ok := fs.bools[a]; ok {
			f()
			continue
		}
		if matched, ex := fs.matchValue(args, &i); matched {
			if ex != nil {
				return ex
			}
			continue
		}
		if ex := fs.other(a); ex != nil {
			return ex
		}
	}
	return nil
}

// other handles an argument no declared flag matched.
func (fs *flagSet) other(a string) *cliExit {
	if fs.positional != nil && !strings.HasPrefix(a, "-") {
		if msg := fs.positional(a); msg != "" {
			return fs.errExit(msg)
		}
		return nil
	}
	if fs.unknown != "" {
		return failExit("denyout-cli "+fs.cmd+": "+fs.unknown, a)
	}
	return nil
}

func containsStr(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// setStr returns a flagSpec setter that stores into *dst.
func setStr(dst *string) func(string) string {
	return func(v string) string { *dst = v; return "" }
}

// setInt stores a leading integer like fmt.Sscanf("%d") (garbage leaves *dst
// unchanged, "12abc" yields 12).
func setInt(dst *int) func(string) string {
	return func(v string) string { fmt.Sscanf(v, "%d", dst); return "" }
}

// splitDash splits args at the first "--": flags before it, command after.
func splitDash(args []string) (flagArgs, command []string) {
	for i, a := range args {
		if a == "--" {
			return args[:i], args[i+1:]
		}
	}
	return args, nil
}

// notifyContext is the signal-aware context for long-running commands
// (swappable in tests).
var notifyContext = func() (context.Context, context.CancelFunc) {
	return signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
}

// localListen reports whether addr is a loopback listen address as accepted by
// the local-only UIs.
func localListen(addr string) bool {
	return strings.HasPrefix(addr, "127.0.0.1:") || strings.HasPrefix(addr, "localhost:")
}
