package privexec

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestNoShellInPrivilegedPackages fails if code in the privileged packages runs a shell
// (exec.Command("sh"/"bash"/..., ...)): the class of bug behind the root
// command injection found in the 2026-11 review. Use privexec instead.
func TestNoShellInPrivilegedPackages(t *testing.T) {
	root := filepath.Join("..")
	shells := map[string]bool{"sh": true, "bash": true, "zsh": true, "dash": true, "cmd": true, "cmd.exe": true}
	for _, pkg := range []string{"hostguard", "tun"} {
		files, _ := filepath.Glob(filepath.Join(root, pkg, "*.go"))
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			src, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			fset := token.NewFileSet()
			af, err := parser.ParseFile(fset, f, src, 0)
			if err != nil {
				t.Fatal(err)
			}
			ast.Inspect(af, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				id, ok := sel.X.(*ast.Ident)
				if !ok || id.Name != "exec" || (sel.Sel.Name != "Command" && sel.Sel.Name != "CommandContext") {
					return true
				}
				for _, a := range call.Args {
					if bl, ok := a.(*ast.BasicLit); ok && bl.Kind == token.STRING {
						v := strings.Trim(bl.Value, "\"`")
						if shells[v] {
							t.Errorf("%s: shell execution (%s) is forbidden here; use internal/privexec", fset.Position(call.Pos()), v)
						}
					}
				}
				return true
			})
		}
	}
}
