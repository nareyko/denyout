package main

import (
	"fmt"

	"github.com/nareyko/denyout/internal/desktop"
	"github.com/nareyko/denyout/internal/profiles"
)

const profileUsage = `Usage: denyout-cli profile <command>

  list                         List saved agent profiles
  create --name N -- <cmd>…    Create a profile (Agent+Cursor + learning)
  show <id>                    Print profile YAML path / summary
  export <id> <file>           Write a profile to a file
  import [--force] <id> <file> Validate and import a profile file as <id>
  delete <id>                  Delete a profile
  run <id>                     Run profile (same as denyout-cli run --profile <id>)
  pin <id>                     Pin all pending Once hosts (learning)
  discard <id>                 Discard pending Once hosts

Profiles live in ~/.config/denyout/profiles/`

// profileSubcommands dispatches `profile <sub>`; each handler gets the full
// args (args[0] is the subcommand name).
var profileSubcommands = map[string]func(args []string) *cliExit{
	"list":    profileList,
	"create":  profileCreate,
	"show":    profileShow,
	"export":  profileExport,
	"import":  profileImport,
	"delete":  profileDelete,
	"run":     profileRun,
	"pin":     profilePin,
	"discard": profileDiscard,
}

func cmdProfile(args []string) int {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" {
		return helpExit(profileUsage).emit()
	}
	h, ok := profileSubcommands[args[0]]
	if !ok {
		return failExit("denyout-cli profile: unknown %q", args[0]).emit()
	}
	return h(args).emit()
}

// profileID returns the <id> operand of a subcommand.
func profileID(args []string) (string, *cliExit) {
	if len(args) < 2 {
		return "", failExit("denyout-cli profile %s: need id", args[0])
	}
	return args[1], nil
}

// profileFail is the standard "denyout-cli profile <sub>: <err>" exit.
func profileFail(sub string, err error) *cliExit {
	return failExit("denyout-cli profile %s: %v", sub, err)
}

func profileList([]string) *cliExit {
	list, err := desktop.ListProfiles()
	if err != nil {
		return profileFail("list", err)
	}
	if len(list) == 0 {
		return &cliExit{out: "(no profiles)\n"}
	}
	out := ""
	for _, p := range list {
		out += fmt.Sprintf("%s\t%s\t%s\tpending=%d\n", p.ID, p.Name, p.CommandLine(), len(p.PendingOnce))
	}
	return &cliExit{out: out}
}

// parseProfileCreate extracts --name and the command after "--".
func parseProfileCreate(args []string) (name string, command []string, ex *cliExit) {
	flagArgs, command := splitDash(args)
	fs := flagSet{
		cmd:     "profile create",
		values:  []flagSpec{{names: []string{"--name"}, eq: true, set: setStr(&name)}},
		unknown: "unknown flag %q",
	}
	if ex := fs.parse(flagArgs); ex != nil {
		return "", nil, ex
	}
	if name == "" || len(command) == 0 {
		return "", nil, failExit("denyout-cli profile create: need --name and -- <command>")
	}
	return name, command, nil
}

func profileCreate(args []string) *cliExit {
	name, command, ex := parseProfileCreate(args[1:])
	if ex != nil {
		return ex
	}
	p := desktop.NewAgentProfile(name, command)
	if err := desktop.SaveProfile(p); err != nil {
		return profileFail("create", err)
	}
	return &cliExit{out: fmt.Sprintf("created %s (%s)\n", p.ID, desktop.ProfilePathForCLI(p.ID))}
}

func profileShow(args []string) *cliExit {
	id, ex := profileID(args)
	if ex != nil {
		return ex
	}
	p, err := desktop.LoadProfile(id)
	if err != nil {
		return profileFail("show", err)
	}
	return &cliExit{out: fmt.Sprintf("id=%s name=%q preset=%s ask=%v sandbox=%q pending=%v allow=%v\npath=%s\n",
		p.ID, p.Name, p.Preset, p.AskMode, p.Sandbox, p.PendingOnce, p.ExtraAllow, desktop.ProfilePathForCLI(p.ID))}
}

func profileExport(args []string) *cliExit {
	if len(args) != 3 {
		return failExit("Usage: denyout-cli profile export <id> <file>")
	}
	if err := profiles.ExportProfile(args[1], args[2]); err != nil {
		return profileFail("export", err)
	}
	return &cliExit{out: fmt.Sprintf("exported %s to %s\n", args[1], args[2])}
}

// parseProfileImport splits [--force] <id> <file>.
func parseProfileImport(args []string) (force bool, pos []string) {
	for _, a := range args {
		if a == "--force" {
			force = true
		} else {
			pos = append(pos, a)
		}
	}
	return force, pos
}

func profileImport(args []string) *cliExit {
	force, pos := parseProfileImport(args[1:])
	if len(pos) != 2 {
		return failExit("Usage: denyout-cli profile import [--force] <id> <file>")
	}
	p, err := profiles.ImportProfile(pos[0], pos[1], force)
	if err != nil {
		return profileFail("import", err)
	}
	return &cliExit{out: fmt.Sprintf("imported %s (%s)\n", p.ID, desktop.ProfilePathForCLI(p.ID))}
}

func profileDelete(args []string) *cliExit {
	id, ex := profileID(args)
	if ex != nil {
		return ex
	}
	if err := desktop.DeleteProfile(id); err != nil {
		return profileFail("delete", err)
	}
	return &cliExit{out: "deleted " + id + "\n"}
}

// profileRunFn runs a profile (same as `run --profile <id>`); swappable in tests.
var profileRunFn = func(id string) int { return cmdRun([]string{"--profile", id}) }

func profileRun(args []string) *cliExit {
	id, ex := profileID(args)
	if ex != nil {
		return ex
	}
	return &cliExit{code: profileRunFn(id)}
}

func profilePin(args []string) *cliExit {
	id, ex := profileID(args)
	if ex != nil {
		return ex
	}
	p, err := desktop.LoadProfile(id)
	if err != nil {
		return profileFail("pin", err)
	}
	n := len(p.PendingOnce)
	p.PinPending(nil)
	p.Learning.Enabled = false
	if err := desktop.SaveProfile(p); err != nil {
		return profileFail("pin", err)
	}
	return &cliExit{out: fmt.Sprintf("pinned %d host(s); learning off\n", n)}
}

func profileDiscard(args []string) *cliExit {
	id, ex := profileID(args)
	if ex != nil {
		return ex
	}
	p, err := desktop.LoadProfile(id)
	if err != nil {
		return profileFail("discard", err)
	}
	p.DiscardPending()
	if err := desktop.SaveProfile(p); err != nil {
		return profileFail("discard", err)
	}
	return &cliExit{out: "discarded pending\n"}
}
