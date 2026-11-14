# External corpora (local cache)

**Not part of the normative 67-case lab.** Large third-party sets for recall/precision yardsticks.

| File | Source | License | Notes |
| --- | --- | --- | --- |
| `corpus.parquet` / `prowl_corpus.jsonl` | [Podric/prowl-secrets-corpus](https://huggingface.co/datasets/Podric/prowl-secrets-corpus) | **CC BY-NC 4.0** | ~503k labeled secret/neg; **local eval only — do not ship commercially** |
| `prowlbench.parquet` / `prowlbench.jsonl` | same HF repo, `prowlbench` config | CC BY-NC 4.0 | held-out eval split |
| `egress_bench.jsonl` + `egress-bench-cases/` | [agent-egress-bench](https://github.com/luckyPipewrench/agent-egress-bench) | Apache-2.0 | url / false-positive / ssrf-bypass |

Parquet/JSONL/SQLite under this directory are **gitignored**.

## Fetch + convert (full, no row cap)

```bash
python3 -m venv .venv-corpus
. .venv-corpus/bin/activate
pip install huggingface_hub pyarrow
# optional: git clone --depth 1 https://github.com/luckyPipewrench/agent-egress-bench.git /tmp/agent-egress-bench
python scripts/fetch_corpus.py
```

## Run

```bash
# Prowl full (~503k) — quiet + metrics (exit 0; yardstick, not CI gate)
denyout test --quiet --metrics \
  --corpus-jsonl examples/fixtures/corpus/prowl_corpus.jsonl \
  --suite prowl_corpus

# ProwlBench
denyout test --quiet --metrics \
  --corpus-jsonl examples/fixtures/corpus/prowlbench.jsonl \
  --suite prowlbench

# Agent egress bench (Apache-2.0)
denyout test --quiet --metrics \
  --corpus-jsonl examples/fixtures/corpus/egress_bench.jsonl
```

Each secret/neg fragment is embedded as  
`https://api.anthropic.com/denyout-lab/<id>?q=<payload>` so DenyOut’s URL scanners run without network dial.
