#!/bin/bash
# CRAP report (complexity^2 * (1-coverage)^3 + complexity) per function. Docker only.
# Usage: scripts/crap.sh [top-N] [path-filter-regex]   (default: 30, all)
# Output: summary + worst N functions. Writes nothing into the repo tree.
set -euo pipefail
TOP="${1:-30}"; FILTER="${2:-.}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
OUT="$(mktemp -d)"
docker run --rm -v "$ROOT":/src -v "$OUT":/out -w /src \
  -v denyout-gocache:/go/pkg/mod -v denyout-gobuild:/root/.cache/go-build \
  -e GOFLAGS=-buildvcs=false golang:1.27.4 bash -c '
    go install github.com/fzipp/gocyclo/cmd/gocyclo@latest >/dev/null 2>&1
    go test -count=1 -coverprofile=/out/cover.out ./internal/... ./cmd/denyout-cli/... >/dev/null 2>&1 || true
    go tool cover -func=/out/cover.out > /out/cover.func
    /go/bin/gocyclo -over 1 internal cmd > /out/cyclo.txt
    chown -R '"$(id -u):$(id -g)"' /out'
python3 - "$OUT" "$TOP" "$FILTER" <<'PY'
import re,sys
out,top,flt=sys.argv[1],int(sys.argv[2]),re.compile(sys.argv[3])
cov={}
for l in open(out+"/cover.func"):
    m=re.match(r'github.com/nareyko/denyout/(\S+?):(\d+):\s+(\S+)\s+([\d.]+)%',l)
    if m: cov[(m.group(1),int(m.group(2)))]=float(m.group(4))/100
rows=[]
for l in open(out+"/cyclo.txt"):
    p=l.split()
    if len(p)<4: continue
    c=int(p[0]); f,ln,_=p[3].rsplit(':',2)
    cv=cov.get((f,int(ln)))
    if cv is None or not flt.search(f): continue
    rows.append((c*c*(1-cv)**3+c,c,cv,f,ln,p[2]))
rows.sort(reverse=True)
tot=[l.split()[-1] for l in open(out+"/cover.func") if l.startswith("total")]
print("funcs=%d  CRAP>30=%d  CRAP>100=%d  total coverage=%s"%(len(rows),sum(r[0]>30 for r in rows),sum(r[0]>100 for r in rows),tot[0] if tot else "?"))
for r in rows[:top]: print("%7.0f cc=%-3d cov=%3.0f%% %s:%s %s"%(r[0],r[1],r[2]*100,r[3],r[4],r[5]))
PY
rm -rf "$OUT"
