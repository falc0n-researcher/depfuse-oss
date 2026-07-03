# Contributing to Depfuse

Thank you for contributing. Depfuse follows standard Go open-source conventions.

**Scope:** v0.1/v0.1.x covers exploit-evidence decisions for npm dependency exposure. App-context features (reachability, VEX export) are planned for v0.2 and should not be added ahead of that milestone.

---

## Development setup

```bash
git clone https://github.com/falc0n-researcher/depfuse-oss.git
cd depfuse-oss
make test     # generates testdata fixtures and runs full test suite
make build    # produces bin/depfuse
```

**Requirements:** Go 1.25+, Git (optional — only needed for remote repo scans)

---

## Project layout

| Directory | Purpose |
|-----------|---------|
| `cmd/depfuse/` | CLI entrypoint |
| `cmd/seed-testdata/` | Generates `testdata/intel.db` for tests (internal) |
| `cmd/build-snapshot/` | Builds the embedded offline snapshot (internal) |
| `internal/cli/` | Cobra command definitions |
| `internal/scan/` | Pipeline orchestration |
| `internal/resolve/` | Lockfile and registry resolution |
| `internal/classify/` | Evidence level model (P0–P4) |
| `internal/verdict/` | Verdict logic (FIX NOW / FIX SOON / OK) |
| `internal/intel/` | SQLite store, feeds, OSV cache |
| `internal/report/` | CLI, HTML, JSON, SARIF output |
| `internal/history/` | Scan history and decision memory |
| `pkg/models/` | Public domain types |
| `testdata/` | Golden npm project fixtures |
| `demo_package/` | Pinned npm project for generating sample output |
| `samples/` | Pre-generated HTML report samples |

---

## Before submitting a PR

```bash
make lint         # gofmt + go vet
make test         # full test suite with race detector
make test-golden  # lockfile + scan regression fixtures
```

---

## Classification changes

Any change to `internal/classify/` must include an invariant test in `internal/classify/classify_test.go`. The key invariant: unverified PoC cannot produce a level above P2.

---

## Documentation

There are no separate docs beyond this README and CONTRIBUTING. Keep design decisions in PR descriptions or commit messages.

---

## Commit messages

Imperative mood, concise subject line:

```
Add yarn berry lockfile support
Fix PoC cap when unverified PoC and KEV are both present
```

---

## Code of conduct

Security tooling requires precision about what the tool does and does not claim. Do not describe exploit-evidence leveling as reachability analysis or app-context-aware behavior.
