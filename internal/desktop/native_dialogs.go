package desktop

import (
	"errors"
	"fmt"
	"os/exec"
	"runtime"
	"strings"

	"github.com/nareyko/denyout/internal/audit"
	"github.com/nareyko/denyout/internal/notify"
)

// Seams so each platform's argv and output parser can be unit-tested without
// running any dialog.
var (
	dialogGOOS     = runtime.GOOS
	dialogLookPath = exec.LookPath
	// dialogExec runs a dialog tool; combined merges stderr into the output.
	dialogExec = func(combined bool, name string, args ...string) ([]byte, error) {
		cmd := exec.Command(name, args...)
		if combined {
			return cmd.CombinedOutput()
		}
		return cmd.Output()
	}
)

func exitCodeOf(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return 2
}

// ---- Ask dialog (Allow once / Always allow / Keep blocked) ----

func zenityAskArgs(text string) []string {
	// Default (cancel) = Keep blocked; OK = Allow once; extra = Always.
	return []string{"--question",
		"--title=DenyOut",
		"--text=" + text,
		"--ok-label=Allow once",
		"--cancel-label=Keep blocked",
		"--extra-button=Always allow",
		"--width=480",
		"--default-cancel",
	}
}

func parseZenityAsk(out []byte, err error) string {
	if strings.Contains(strings.TrimSpace(string(out)), "Always allow") {
		return "always"
	}
	if err == nil {
		return "once"
	}
	return "deny"
}

func kdialogAskArgs(text string) []string {
	return []string{"--yesnocancel", text,
		"--yes-label", "Allow once",
		"--no-label", "Always allow",
		"--cancel-label", "Keep blocked",
		"--title", "DenyOut",
	}
}

func parseKdialogAsk(code int) string {
	switch code {
	case 0:
		return "once"
	case 1:
		return "always"
	}
	return "deny"
}

func osascriptAskScript(text string) string {
	return fmt.Sprintf(`set r to button returned of (display dialog %q buttons {"Keep blocked","Allow once","Always allow"} default button "Keep blocked" with title "DenyOut")
return r`, text)
}

func parseOsascriptAsk(out []byte) string {
	s := strings.TrimSpace(string(out))
	switch {
	case strings.Contains(s, "Always"):
		return "always"
	case strings.Contains(s, "once"):
		return "once"
	}
	return "deny"
}

func powershellAskScript(text string) string {
	return fmt.Sprintf(`Add-Type -AssemblyName PresentationFramework
$r = [System.Windows.MessageBox]::Show(%q, 'DenyOut - new site', 'YesNoCancel', 'Question')
# Yes=Allow once, No=Always allow, Cancel=Keep blocked (default Cancel via focus)
if ($r -eq 'Yes') { 'once' } elseif ($r -eq 'No') { 'always' } else { 'deny' }`, text)
}

func parseAskPowershell(out []byte) string {
	s := strings.TrimSpace(strings.ToLower(string(out)))
	if s == "once" || s == "always" || s == "deny" {
		return s
	}
	return "deny"
}

func runAskDialog(text string) string {
	switch dialogGOOS {
	case "linux":
		return askDialogLinux(text)
	case "darwin":
		out, err := dialogExec(false, "osascript", "-e", osascriptAskScript(text))
		if err != nil {
			return "deny"
		}
		return parseOsascriptAsk(out)
	case "windows":
		out, err := dialogExec(false, "powershell", "-NoProfile", "-Command", powershellAskScript(text))
		if err != nil {
			return "deny"
		}
		return parseAskPowershell(out)
	}
	return "deny"
}

func askDialogLinux(text string) string {
	if zenity, err := dialogLookPath("zenity"); err == nil {
		out, err := dialogExec(true, zenity, zenityAskArgs(text)...)
		return parseZenityAsk(out, err)
	}
	if kdialog, err := dialogLookPath("kdialog"); err == nil {
		_, err := dialogExec(false, kdialog, kdialogAskArgs(text)...)
		return parseKdialogAsk(exitCodeOf(err))
	}
	notify.Info("DenyOut", "Install zenity for permission dialogs (e.g. apt install zenity).")
	return "deny"
}

// ---- Denials chooser ----

// denialReasonCode is the primary post-block reason code, or the first reason.
func denialReasonCode(reasons []string) string {
	code := primaryPostBlockReason(reasons)
	if code == "" && len(reasons) > 0 {
		code = reasons[0]
	}
	return code
}

// nativeDenialsChooserV2 returns host, reason code, action, and the selected event when known.
// action: always|undo|details|refresh|close|problems
func nativeDenialsChooserV2(events []audit.Event) (host, reason, action string, ev *audit.Event) {
	if dialogGOOS == "linux" {
		if _, err := dialogLookPath("zenity"); err == nil {
			return nativeDenialsChooserZenityV2(events)
		}
	}
	h, act, e := nativeDenialsChooser(events)
	return h, "", act, e
}

func nativeDenialsChooser(events []audit.Event) (selectedHost, action string, ev *audit.Event) {
	h, act, e, handled := denialsChooserFor(dialogGOOS, events)
	if handled {
		return h, act, e
	}
	notify.Info("DenyOut", "No native list dialog available. See diagnostics folder for audit.jsonl.")
	return "", "close", nil
}

// denialsChooserFor dispatches per platform; handled=false means no dialog was
// available (or the platform fell through) and the caller shows the notice.
func denialsChooserFor(goos string, events []audit.Event) (host, action string, ev *audit.Event, handled bool) {
	switch goos {
	case "linux":
		return denialsChooserLinux(events)
	case "darwin":
		h, a, e := denialsChooserDarwin(events)
		return h, a, e, true
	case "windows":
		return denialsChooserWindows(events)
	}
	return "", "", nil, false
}

func denialsChooserLinux(events []audit.Event) (string, string, *audit.Event, bool) {
	if _, err := dialogLookPath("zenity"); err == nil {
		h, _, act, e := nativeDenialsChooserZenityV2(events)
		return h, act, e, true
	}
	kdialog, err := dialogLookPath("kdialog")
	if err != nil {
		return "", "", nil, false
	}
	items, byHost := kdialogDenialItems(events)
	if len(items) == 0 {
		return "", "close", nil, true
	}
	out, err := dialogExec(false, kdialog, kdialogDenialArgs(items)...)
	if err != nil {
		return "", "close", nil, true
	}
	host := strings.TrimSpace(string(out))
	return host, "details", byHost[host], true
}

func kdialogDenialItems(events []audit.Event) ([]string, map[string]*audit.Event) {
	items := make([]string, 0, len(events)*2)
	byHost := map[string]*audit.Event{}
	for i := len(events) - 1; i >= 0; i-- {
		e := events[i]
		host := e.Network.DestHost
		if host == "" {
			continue
		}
		urlStr := audit.TruncateMiddle(audit.DisplayURL(e.Network, e.HTTP), 64)
		why := notify.HumanReasons(e.Reasons)
		label := fmt.Sprintf("%s - %s", host, why)
		if urlStr != "" {
			label = fmt.Sprintf("%s - %s - %s", host, urlStr, why)
		}
		items = append(items, host, label)
		if _, ok := byHost[host]; !ok {
			evCopy := e
			byHost[host] = &evCopy
		}
	}
	return items, byHost
}

func kdialogDenialArgs(items []string) []string {
	return append([]string{"--menu", "Recent denials - pick a row (URL shown in label)", "--title", "DenyOut - What was blocked"}, items...)
}

type darwinDenialRows struct {
	lines      []string
	hostByLine map[string]string
	evByLine   map[string]*audit.Event
}

func darwinDenialLines(events []audit.Event) darwinDenialRows {
	r := darwinDenialRows{hostByLine: map[string]string{}, evByLine: map[string]*audit.Event{}}
	for i := len(events) - 1; i >= 0 && len(r.lines) < 25; i-- {
		e := events[i]
		host := e.Network.DestHost
		if host == "" {
			continue
		}
		urlStr := audit.TruncateMiddle(audit.DisplayURL(e.Network, e.HTTP), 48)
		why := notify.HumanReasons(e.Reasons)
		line := fmt.Sprintf("%s - %s", host, why)
		if urlStr != "" {
			line = fmt.Sprintf("%s - %s - %s", host, urlStr, why)
		}
		// Escape quotes for AppleScript.
		line = strings.ReplaceAll(line, `"`, `'`)
		r.lines = append(r.lines, line)
		r.hostByLine[line] = host
		evCopy := e
		r.evByLine[line] = &evCopy
	}
	return r
}

func darwinDenialsScript(lines []string) string {
	list := strings.Join(lines, `","`)
	return fmt.Sprintf(`set hostList to {"%s"}
set chosen to choose from list hostList with prompt "Recent denials (host - URL - why). Open details?" OK button name "Details" cancel button name "Close"
if chosen is false then
 return "CLOSE"
end if
return item 1 of chosen`, list)
}

func parseDarwinDenials(out []byte, r darwinDenialRows) (string, string, *audit.Event) {
	s := strings.TrimSpace(string(out))
	if s == "CLOSE" || s == "" {
		return "", "close", nil
	}
	if h, ok := r.hostByLine[s]; ok {
		return h, "details", r.evByLine[s]
	}
	return "", "close", nil
}

func denialsChooserDarwin(events []audit.Event) (string, string, *audit.Event) {
	r := darwinDenialLines(events)
	if len(r.lines) == 0 {
		return "", "close", nil
	}
	out, err := dialogExec(false, "osascript", "-e", darwinDenialsScript(r.lines))
	if err != nil {
		return "", "close", nil
	}
	return parseDarwinDenials(out, r)
}

func windowsDenialsMessage(events []audit.Event) (msg, firstHost string, firstEv *audit.Event) {
	var b strings.Builder
	b.WriteString("Recent denials:\n")
	n := 0
	for i := len(events) - 1; i >= 0 && n < 15; i-- {
		e := events[i]
		host := e.Network.DestHost
		if host == "" {
			continue
		}
		if firstHost == "" {
			firstHost = host
			evCopy := e
			firstEv = &evCopy
		}
		urlStr := audit.TruncateMiddle(audit.DisplayURL(e.Network, e.HTTP), 72)
		why := notify.HumanReasons(e.Reasons)
		if urlStr != "" {
			fmt.Fprintf(&b, "- %s\n %s\n %s\n", host, urlStr, why)
		} else {
			fmt.Fprintf(&b, "- %s (%s)\n", host, why)
		}
		n++
	}
	return b.String() + "\n\nOpen details for first host " + firstHost + "?", firstHost, firstEv
}

func windowsDenialsScript(msg string) string {
	return fmt.Sprintf("Add-Type -AssemblyName PresentationFramework; $r = [System.Windows.MessageBox]::Show(%q, 'DenyOut - What was blocked', 'YesNo', 'Information'); if ($r -eq 'Yes') { 'details' } else { 'close' }", msg)
}

func denialsChooserWindows(events []audit.Event) (string, string, *audit.Event, bool) {
	msg, firstHost, firstEv := windowsDenialsMessage(events)
	out, err := dialogExec(false, "powershell", "-NoProfile", "-Command", windowsDenialsScript(msg))
	if err != nil {
		return "", "close", nil, true
	}
	if strings.TrimSpace(string(out)) == "details" {
		return firstHost, "details", firstEv, true
	}
	// Anything else falls through to the "no native list dialog" notice.
	return "", "", nil, false
}

// ---- zenity denials list ----

type zenityDenialRows struct {
	args       []string
	byIdx      map[string]*audit.Event
	hostReason map[string]string
}

func zenityDenialsBaseArgs() []string {
	return []string{
		"--list",
		"--title=DenyOut - What was blocked",
		"--text=Select a row. Secrets in URLs are redacted. Details shows the full request.",
		"--column=#",
		"--column=Time",
		"--column=Host",
		"--column=URL",
		"--column=Why",
		"--print-column=1",
		"--width=920",
		"--height=480",
		"--ok-label=Details",
		"--cancel-label=Back",
		"--extra-button=Always allow",
		"--extra-button=Undo",
		"--extra-button=Refresh",
	}
}

// zenityDenialCells returns the Time, URL and Why cells for one event.
func zenityDenialCells(e audit.Event, host string) (ts, urlStr, why string) {
	ts = e.TS
	if len(ts) >= 19 {
		ts = ts[11:19]
	}
	if ts == "" {
		ts = "-"
	}
	why = notify.HumanReasons(e.Reasons)
	if why == "" {
		why = "-"
	}
	if len(why) > 72 {
		why = why[:69] + "..."
	}
	urlStr = audit.DisplayURL(e.Network, e.HTTP)
	if urlStr == "" {
		urlStr = host
	}
	return ts, audit.TruncateMiddle(urlStr, 72), why
}

func zenityDenialsRows(events []audit.Event) zenityDenialRows {
	r := zenityDenialRows{
		args:       zenityDenialsBaseArgs(),
		byIdx:      map[string]*audit.Event{},
		hostReason: map[string]string{},
	}
	row := 0
	for i := len(events) - 1; i >= 0; i-- {
		e := events[i]
		host := e.Network.DestHost
		if host == "" {
			continue
		}
		row++
		idx := fmt.Sprintf("%d", row)
		ts, urlStr, why := zenityDenialCells(e, host)
		r.args = append(r.args, idx, ts, host, urlStr, why)
		evCopy := e
		r.byIdx[idx] = &evCopy
		if _, ok := r.hostReason[host]; !ok {
			r.hostReason[host] = denialReasonCode(e.Reasons)
		}
	}
	return r
}

func parseZenityDenials(out []byte, err error, r zenityDenialRows) (selectedHost, reason, action string, ev *audit.Event) {
	s := strings.TrimSpace(string(out))
	if strings.Contains(s, "Refresh") {
		return "", "", "refresh", nil
	}
	always := strings.Contains(s, "Always allow")
	undo := strings.Contains(s, "Undo")
	s = strings.ReplaceAll(s, "Always allow", "")
	s = strings.ReplaceAll(s, "Undo", "")
	lines := strings.Split(strings.TrimSpace(s), "\n")
	sel := r.byIdx[strings.TrimSpace(lines[len(lines)-1])]
	if sel == nil {
		return "", "", "close", nil
	}
	host := sel.Network.DestHost
	code := r.hostReason[host]
	if code == "" {
		code = denialReasonCode(sel.Reasons)
	}
	switch {
	case always:
		return host, code, "always", sel
	case undo:
		return host, code, "undo", sel
	case err != nil:
		return "", "", "close", nil
	}
	return host, code, "details", sel
}

func nativeDenialsChooserZenityV2(events []audit.Event) (selectedHost, reason, action string, ev *audit.Event) {
	zenity, err := dialogLookPath("zenity")
	if err != nil {
		return "", "", "close", nil
	}
	r := zenityDenialsRows(events)
	if len(r.byIdx) == 0 {
		return "", "", "close", nil
	}
	out, err := dialogExec(true, zenity, r.args...)
	return parseZenityDenials(out, err, r)
}
