#!/usr/bin/env python3
"""Download and convert external corpora into DenyOut lab JSONL.

Sources:
  - Podric/prowl-secrets-corpus (CC BY-NC 4.0) — do NOT redistribute commercially;
    local cache only under examples/fixtures/corpus/ (gitignored).
  - agent-egress-bench (Apache-2.0) — url / false-positive / ssrf-bypass cases.

Usage:
  .venv-corpus/bin/python scripts/fetch_corpus.py
  .venv-corpus/bin/python scripts/fetch_corpus.py --skip-download
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
import urllib.parse
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / "examples" / "fixtures" / "corpus"
MAX_Q = 1800  # keep probe URLs within practical length


def download_prowl() -> None:
    from huggingface_hub import hf_hub_download

    OUT.mkdir(parents=True, exist_ok=True)
    for name in ("corpus.parquet", "prowlbench.parquet"):
        print(f"download {name}…", flush=True)
        path = hf_hub_download(
            repo_id="Podric/prowl-secrets-corpus",
            filename=name,
            repo_type="dataset",
            local_dir=str(OUT),
        )
        print(f"  -> {path} ({os.path.getsize(path)} bytes)", flush=True)


def probe_url(case_id: str, payload: str) -> str:
    q = payload.replace("\x00", "")
    if len(q) > MAX_Q:
        q = q[:MAX_Q]
    return "https://api.anthropic.com/denyout-lab/" + urllib.parse.quote(case_id, safe="") + "?q=" + urllib.parse.quote(q, safe="")


def convert_prowl_parquet(parquet: Path, suite: str, out_jsonl: Path) -> int:
    import pyarrow.parquet as pq

    table = pq.read_table(parquet)
    n = table.num_rows
    print(f"convert {parquet.name} -> {out_jsonl.name} ({n} rows)…", flush=True)
    cols = {name: table.column(name) for name in table.column_names}
    written = 0
    with out_jsonl.open("w", encoding="utf-8") as f:
        for i in range(n):
            if "label_binary" in cols:
                label = int(cols["label_binary"][i].as_py() or 0)
            else:
                label = int(cols["label"][i].as_py() or 0)
            text = (cols["text"][i].as_py() or "") if "text" in cols else ""
            value = cols["value"][i].as_py() if "value" in cols else None
            if not value and "span" in cols and text:
                sp = cols["span"][i].as_py()
                if isinstance(sp, (list, tuple)) and len(sp) == 2 and sp[0] is not None and sp[1] is not None:
                    try:
                        value = text[int(sp[0]) : int(sp[1])]
                    except Exception:
                        value = None
            ltype = None
            if "label_type" in cols:
                ltype = cols["label_type"][i].as_py()
            elif "type" in cols:
                ltype = cols["type"][i].as_py()
            payload = value if value else text
            if not payload:
                continue
            if "id" in cols and cols["id"][i].as_py():
                cid = f"{suite}-{cols['id'][i].as_py()}"
            else:
                cid = f"{suite}-{i:06d}"
            expect = "deny" if label == 1 else "allow"
            # Verdict-only: corpus is a recall/precision yardstick for ScanURL shapes.
            row = {
                "id": cid,
                "suite": suite,
                "url": probe_url(cid, str(payload)),
                "mode": "enforce",
                "preset": "models",
                "expect_verdict": expect,
                "expect_reasons": [],
                "note": f"prowl label={label} type={ltype or '-'}",
            }
            f.write(json.dumps(row, ensure_ascii=False) + "\n")
            written += 1
            if written % 50000 == 0:
                print(f"  …{written}", flush=True)
    print(f"  wrote {written}", flush=True)
    return written


def convert_egress_bench(src: Path, out_jsonl: Path) -> int:
    cats = ("url", "false-positive", "ssrf-bypass")
    written = 0
    with out_jsonl.open("w", encoding="utf-8") as f:
        for cat in cats:
            d = src / "cases" / cat
            if not d.is_dir():
                continue
            for p in sorted(d.glob("*.json")):
                data = json.loads(p.read_text(encoding="utf-8"))
                payload = data.get("payload") or {}
                url = payload.get("url") or data.get("url")
                if not url or not isinstance(url, str):
                    continue
                if not url.startswith(("http://", "https://")):
                    url = "https://" + url.lstrip("/")
                verdict = (data.get("expected_verdict") or "").lower()
                if verdict in ("block", "deny"):
                    expect = "deny"
                elif verdict in ("allow", "pass"):
                    expect = "allow"
                else:
                    continue  # skip warn/unknown
                suite = "egress_" + cat.replace("-", "_")
                cid = data.get("id") or p.stem
                reasons = []
                tags = data.get("capability_tags") or []
                if "ssrf" in tags or cat == "ssrf-bypass":
                    reasons = ["unsafe_ip", "host_not_allowed"]
                elif expect == "deny":
                    reasons = ["secret_in_url", "canary_detected", "host_not_allowed", "host_denied"]
                row = {
                    "id": cid,
                    "suite": suite,
                    "url": url,
                    "mode": "enforce",
                    "preset": "agent" if cat != "false-positive" else "none",
                    "expect_verdict": expect,
                    "expect_reasons": reasons,
                    "note": (data.get("title") or "")[:200],
                }
                if cat == "false-positive":
                    row["mode"] = "blocklist"
                    row["preset"] = "none"
                f.write(json.dumps(row, ensure_ascii=False) + "\n")
                written += 1
    print(f"egress-bench wrote {written} -> {out_jsonl}", flush=True)
    return written


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-download", action="store_true")
    ap.add_argument(
        "--egress-src",
        default="/tmp/agent-egress-bench",
        help="clone of luckyPipewrench/agent-egress-bench",
    )
    args = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)

    if not args.skip_download:
        download_prowl()

    total = 0
    corpus_pq = OUT / "corpus.parquet"
    bench_pq = OUT / "prowlbench.parquet"
    if not corpus_pq.is_file():
        print("missing corpus.parquet — run without --skip-download", file=sys.stderr)
        return 2
    total += convert_prowl_parquet(corpus_pq, "prowl_corpus", OUT / "prowl_corpus.jsonl")
    if bench_pq.is_file():
        total += convert_prowl_parquet(bench_pq, "prowlbench", OUT / "prowlbench.jsonl")

    egress_src = Path(args.egress_src)
    if not egress_src.is_dir():
        print(f"clone egress bench: git clone --depth 1 https://github.com/luckyPipewrench/agent-egress-bench.git {egress_src}", flush=True)
        os.system(f"git clone --depth 1 https://github.com/luckyPipewrench/agent-egress-bench.git {egress_src}")
    if egress_src.is_dir():
        total += convert_egress_bench(egress_src, OUT / "egress_bench.jsonl")
        # keep a local mirror of the small Apache-2.0 JSON cases
        mirror = OUT / "egress-bench-cases"
        if mirror.exists():
            shutil.rmtree(mirror)
        mirror.mkdir(parents=True)
        for cat in ("url", "false-positive", "ssrf-bypass"):
            src = egress_src / "cases" / cat
            if src.is_dir():
                shutil.copytree(src, mirror / cat)

    meta = {
        "prowl_license": "CC BY-NC 4.0 — local eval only; do not ship in commercial redistributions",
        "prowl_source": "https://huggingface.co/datasets/Podric/prowl-secrets-corpus",
        "egress_license": "Apache-2.0",
        "egress_source": "https://github.com/luckyPipewrench/agent-egress-bench",
        "total_jsonl_cases": total,
    }
    (OUT / "MANIFEST.json").write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(meta, indent=2))
    print(f"total cases {total}", flush=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
