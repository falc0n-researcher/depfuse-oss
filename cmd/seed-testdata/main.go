package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/falc0n-researcher/depfuse-oss/internal/testdata"
)

func main() {
	demo := flag.Bool("demo", false, "seed demo_package/intel.db for CFP booth demo")
	flag.Parse()

	repoRoot, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	var dbPath string
	var roots []string
	if *demo {
		dbPath, _ = testdata.DemoPaths(repoRoot)
		roots = []string{filepath.Join(repoRoot, testdata.DemoFixtureRoot)}
	} else {
		dbPath, _ = testdata.DefaultPaths(repoRoot)
		roots = []string{filepath.Join(repoRoot, testdata.DemoFixtureRoot), filepath.Join(repoRoot, "testdata/express-app"), filepath.Join(repoRoot, "testdata/next-app")}
	}

	if err := testdata.SeedIntelDB(dbPath, roots...); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	fmt.Printf("Seeded %s from %s\n", dbPath, filepath.Join(roots...))
}
