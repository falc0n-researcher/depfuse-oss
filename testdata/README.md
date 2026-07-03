# Test fixtures

Golden npm projects used by resolution and integration tests.

| Directory | Purpose |
|-----------|---------|
| `express-app/` | Express app with prod + dev deps and transitive packages |
| `noise-app/` | Minimal app for CI pass / low-noise corpus |
| `next-app/` | Next.js app with npm lockfile |
| `yarn-berry-app/` | Yarn Berry lockfile |
| `bun-app/` | Bun text lockfile |
| `monorepo-npm/` | npm workspaces + shared lockfile |
| `monorepo-yarn/` | Yarn workspaces |
| `monorepo-pnpm/` | pnpm workspaces |

## Intelligence database

`intel.db` is **generated locally** and gitignored. Create it with:

```bash
make testdata
# or
go run ./cmd/seed-testdata
```

CI generates this file before running tests. The database includes seed exploit-risk artifacts and cached OSV responses for fixture packages (offline scan support).

## Adding fixtures

1. Add a directory with `package.json` + lockfile
2. Extend resolution golden tests in `internal/resolve/`
3. Re-run `make testdata` if offline scan tests need OSV cache entries
4. Add scan golden tests in `internal/scan/fixtures_golden_test.go` when the fixture encodes level/verdict expectations
