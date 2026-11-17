package policy

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/santhosh-tekuri/jsonschema/v5"
	"gopkg.in/yaml.v3"
)

// Diagnostic is one problem found by Check. Line is 1-based (0 = unknown).
type Diagnostic struct {
	Line    int    `json:"line"`
	Path    string `json:"path,omitempty"` // JSON-pointer-like location, e.g. /allow/0/host
	Message string `json:"message"`
}

func (d Diagnostic) String() string {
	loc := ""
	if d.Line > 0 {
		loc = "line " + strconv.Itoa(d.Line) + ": "
	}
	if d.Path != "" {
		return loc + d.Path + ": " + d.Message
	}
	return loc + d.Message
}

var yamlLineRE = regexp.MustCompile(`line (\d+)`)

// Check validates a policy document exactly like LoadBytes (same schema, same
// semantic checks) but reports every schema problem it can locate with a line
// number instead of stopping at the first. It returns nil only when LoadBytes
// would accept raw.
func Check(raw []byte) []Diagnostic {
	var root yaml.Node
	if err := yaml.Unmarshal(raw, &root); err != nil {
		d := Diagnostic{Message: "yaml: " + err.Error()}
		if m := yamlLineRE.FindStringSubmatch(err.Error()); m != nil {
			d.Line, _ = strconv.Atoi(m[1])
		}
		return []Diagnostic{d}
	}
	var out []Diagnostic
	if err := validateSchema(raw); err != nil {
		var ve *jsonschema.ValidationError
		if errors.As(err, &ve) {
			seen := map[string]bool{}
			for _, leaf := range schemaLeaves(ve) {
				d := Diagnostic{Path: leaf.InstanceLocation, Message: leaf.Message}
				d.Line = lineForPointer(&root, leaf.InstanceLocation)
				if k := d.String(); !seen[k] {
					seen[k] = true
					out = append(out, d)
				}
			}
		}
		if len(out) == 0 {
			out = append(out, Diagnostic{Message: "schema: " + err.Error()})
		}
		return out
	}
	// Schema is fine; run the remaining semantic checks of LoadBytes.
	if _, err := LoadBytes(raw); err != nil {
		d := Diagnostic{Message: err.Error()}
		d.Line = lineForSemantic(&root, err.Error())
		out = append(out, d)
	}
	return out
}

func schemaLeaves(ve *jsonschema.ValidationError) []*jsonschema.ValidationError {
	if len(ve.Causes) == 0 {
		return []*jsonschema.ValidationError{ve}
	}
	var out []*jsonschema.ValidationError
	for _, c := range ve.Causes {
		out = append(out, schemaLeaves(c)...)
	}
	return out
}

// lineForPointer resolves /a/0/b against a YAML document node.
func lineForPointer(doc *yaml.Node, ptr string) int {
	n := doc
	if n.Kind == yaml.DocumentNode && len(n.Content) > 0 {
		n = n.Content[0]
	}
	line := n.Line
	for _, seg := range strings.Split(strings.TrimPrefix(ptr, "/"), "/") {
		if seg == "" {
			continue
		}
		seg = strings.NewReplacer("~1", "/", "~0", "~").Replace(seg)
		switch n.Kind {
		case yaml.MappingNode:
			found := false
			for i := 0; i+1 < len(n.Content); i += 2 {
				if n.Content[i].Value == seg {
					line = n.Content[i].Line
					n = n.Content[i+1]
					found = true
					break
				}
			}
			if !found {
				return line
			}
		case yaml.SequenceNode:
			idx, err := strconv.Atoi(seg)
			if err != nil || idx < 0 || idx >= len(n.Content) {
				return line
			}
			n = n.Content[idx]
			line = n.Line
		default:
			return line
		}
	}
	return line
}

// lineForSemantic finds a best-effort line for non-schema errors (custom_regex,
// apiVersion, kind, preset) by locating the offending key.
func lineForSemantic(doc *yaml.Node, msg string) int {
	switch {
	case strings.HasPrefix(msg, "apiVersion"):
		return lineForPointer(doc, "/apiVersion")
	case strings.HasPrefix(msg, "kind"):
		return lineForPointer(doc, "/kind")
	case strings.HasPrefix(msg, "custom_regex"):
		return lineForPointer(doc, "/scanners/custom_regex")
	case strings.Contains(msg, "preset"):
		return lineForPointer(doc, "/preset")
	}
	return 0
}

// FormatDiagnostics renders diagnostics with the offending source line quoted.
func FormatDiagnostics(raw []byte, ds []Diagnostic) string {
	lines := strings.Split(string(raw), "\n")
	var b strings.Builder
	for _, d := range ds {
		b.WriteString(d.String())
		b.WriteByte('\n')
		if d.Line > 0 && d.Line <= len(lines) {
			fmt.Fprintf(&b, "  %4d | %s\n", d.Line, strings.TrimRight(lines[d.Line-1], "\r"))
		}
	}
	return b.String()
}
