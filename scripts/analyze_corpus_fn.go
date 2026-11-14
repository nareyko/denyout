// Analyze DenyOut secret-scanner recall on Prowl JSONL corpora.
//
//	go run ./scripts/analyze_corpus_fn.go examples/fixtures/corpus/prowl_corpus.jsonl
//	go run ./scripts/analyze_corpus_fn.go examples/fixtures/corpus/prowlbench.jsonl
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/nareyko/denyout/internal/secrets"
)

type row struct {
	ID            string `json:"id"`
	URL           string `json:"url"`
	ExpectVerdict string `json:"expect_verdict"`
	Note          string `json:"note"`
}

type typeStats struct {
	Pos, TP, FN int
}

func labelType(note string) string {
	const p = "type="
	i := strings.Index(note, p)
	if i < 0 {
		return "(unknown)"
	}
	t := note[i+len(p):]
	if j := strings.IndexAny(t, " \t"); j >= 0 {
		t = t[:j]
	}
	if t == "" || t == "-" {
		return "(none)"
	}
	return t
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: go run ./scripts/analyze_corpus_fn.go <corpus.jsonl> [more.jsonl...]")
		os.Exit(2)
	}
	canaries := []string{"DENYOUT_CANARY_", "ARVISER_CANARY_", "SECRET_MARKER_"}

	var (
		tp, fp, tn, fn int
		byType         = map[string]*typeStats{}
		fnSamples      = map[string][]string{} // type -> up to 3 sample payloads (from q=)
	)

	for _, path := range os.Args[1:] {
		f, err := os.Open(path)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		sc := bufio.NewScanner(f)
		buf := make([]byte, 0, 1024*1024)
		sc.Buffer(buf, 4*1024*1024)
		n := 0
		for sc.Scan() {
			line := strings.TrimSpace(sc.Text())
			if line == "" {
				continue
			}
			var r row
			if err := json.Unmarshal([]byte(line), &r); err != nil {
				fmt.Fprintf(os.Stderr, "%s: %v\n", path, err)
				os.Exit(1)
			}
			hits := secrets.ScanURL(r.URL, canaries, 6, true)
			gotDeny := len(hits) > 0
			wantDeny := r.ExpectVerdict == "deny"
			lt := labelType(r.Note)
			switch {
			case wantDeny && gotDeny:
				tp++
				st := byType[lt]
				if st == nil {
					st = &typeStats{}
					byType[lt] = st
				}
				st.Pos++
				st.TP++
			case wantDeny && !gotDeny:
				fn++
				st := byType[lt]
				if st == nil {
					st = &typeStats{}
					byType[lt] = st
				}
				st.Pos++
				st.FN++
				if len(fnSamples[lt]) < 3 {
					fnSamples[lt] = append(fnSamples[lt], sampleQ(r.URL))
				}
			case !wantDeny && gotDeny:
				fp++
			default:
				tn++
			}
			n++
			if n%100000 == 0 {
				fmt.Fprintf(os.Stderr, "…%d %s\n", n, path)
			}
		}
		_ = f.Close()
		if err := sc.Err(); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "scanned %d from %s\n", n, path)
	}

	prec := float64(tp) / float64(max1(tp+fp))
	rec := float64(tp) / float64(max1(tp+fn))
	spec := float64(tn) / float64(max1(tn+fp))
	fmt.Printf("overall tp=%d fp=%d tn=%d fn=%d precision=%.4f recall=%.4f specificity=%.4f\n\n",
		tp, fp, tn, fn, prec, rec, spec)

	type ranked struct {
		Name string
		St   *typeStats
	}
	var list []ranked
	for name, st := range byType {
		if st.Pos == 0 {
			continue
		}
		list = append(list, ranked{name, st})
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].St.FN != list[j].St.FN {
			return list[i].St.FN > list[j].St.FN
		}
		return list[i].St.Pos > list[j].St.Pos
	})

	fmt.Println("FN by label_type (positives only; top 40 by FN count)")
	fmt.Printf("%-40s %8s %8s %8s %8s\n", "type", "pos", "tp", "fn", "recall")
	limit := 40
	if len(list) < limit {
		limit = len(list)
	}
	for _, e := range list[:limit] {
		r := float64(e.St.TP) / float64(max1(e.St.Pos))
		fmt.Printf("%-40s %8d %8d %8d %7.1f%%\n", e.Name, e.St.Pos, e.St.TP, e.St.FN, 100*r)
	}

	fmt.Println("\nSample FN payloads (redacted-ish, first 80 chars of q=) for top 15 FN types:")
	for i, e := range list {
		if i >= 15 {
			break
		}
		fmt.Printf("\n## %s (fn=%d)\n", e.Name, e.St.FN)
		for _, s := range fnSamples[e.Name] {
			fmt.Printf("  %q\n", s)
		}
	}
}

func sampleQ(rawURL string) string {
	i := strings.Index(rawURL, "q=")
	if i < 0 {
		return trim(rawURL, 80)
	}
	q := rawURL[i+2:]
	if j := strings.IndexByte(q, '&'); j >= 0 {
		q = q[:j]
	}
	// keep encoded form short
	return trim(q, 80)
}

func trim(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}

func max1(n int) int {
	if n == 0 {
		return 1
	}
	return n
}
