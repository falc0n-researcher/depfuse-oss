package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/falc0n-researcher/depfuse-oss/internal/version"
)

// Execute runs the Depfuse CLI.
func Execute() error {
	return NewRoot().Execute()
}

// NewRoot constructs the root command tree.
func NewRoot() *cobra.Command {
	root := &cobra.Command{
		Use:   "depfuse",
		Short: "Find which dependency blows the fuse before you ship",
		Long: `Depfuse tracks when exposed npm dependencies become weaponized.

Your lockfile is a fuse box — Depfuse shows which dependency trips it, with cited
exploit evidence (KEV, Nuclei, Metasploit, PoC) and FIX NOW / FIX SOON / OK verdicts.

All local data lives in ~/.depfuse/:
  intel.db       Intelligence snapshot (auto-refreshes when older than 4 hours)
  report.html    Latest project scan report (written on every scan)
  report.md      Markdown version of the same report

Before scan, package, cve, watch, or decisions: if intel.db is stale (>4h),
Depfuse runs collect automatically, then proceeds.

Core workflow:
  depfuse scan .          Scan lockfiles → verdicts + shadow dep tree + CVE badges
  depfuse scan . --tree   Expand full nested dependency tree in output
  depfuse watch .         What needs review vs stays silent (decision memory)
  depfuse decisions …     Record and list accept-risk decisions

First run:
  depfuse doctor          Check ~/.depfuse setup and token

Output formats (--format): cli (default), json, html, sarif (scan commands)

Run depfuse <command> --help for details.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.Version = version.String()
	root.SetVersionTemplate("depfuse " + version.String() + "\n")
	root.InitDefaultVersionFlag()

	root.AddGroup(&cobra.Group{ID: "core", Title: "Core commands"})
	root.AddGroup(&cobra.Group{ID: "memory", Title: "Decision memory"})
	root.AddGroup(&cobra.Group{ID: "intel", Title: "Intelligence"})

	flags := bindGlobalFlags(root)

	root.AddCommand(
		newScanCmd(flags),
		newWatchCmd(flags),
		newDecisionsCmd(flags),
		newCVECmd(flags),
		newPackageCmd(flags),
		newCollectCmd(flags),
		newDoctorCmd(flags),
	)

	// Hidden compatibility aliases — avoid breaking scripts.
	root.AddCommand(newDecideAlias(flags), newEvidenceAlias(flags))

	return root
}

// Run is the entrypoint used by main.
func Run() {
	loadDotEnv()
	if err := Execute(); err != nil {
		if exitErr, ok := err.(ExitError); ok {
			if exitErr.Message != "" {
				fmt.Fprintln(os.Stderr, exitErr.Message)
			}
			os.Exit(exitErr.Code)
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// ExitError carries a non-zero exit code without calling os.Exit in library code.
type ExitError struct {
	Code    int
	Message string
}

func (e ExitError) Error() string {
	if e.Message != "" {
		return e.Message
	}
	return fmt.Sprintf("exit status %d", e.Code)
}
