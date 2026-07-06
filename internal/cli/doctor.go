package cli

import (
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/falc0n-researcher/depfuse-oss/internal/cidoctor"
	"github.com/falc0n-researcher/depfuse-oss/internal/cli/ui"
	"github.com/falc0n-researcher/depfuse-oss/internal/decisions"
	"github.com/falc0n-researcher/depfuse-oss/internal/intel"
)

func newDoctorCmd(flags *globalFlags) *cobra.Command {
	var ciMode bool
	cmd := &cobra.Command{
		Use:   "doctor",
		Short: "Check local setup: intel.db, token, and decision files",
		Long:  "Validates ~/.depfuse state, environment, and project decision files before your first scan.",
		RunE: func(cmd *cobra.Command, args []string) error {
			code, err := runDoctor(cmd.OutOrStdout(), flags, ciMode)
			if err != nil {
				return err
			}
			if code != 0 {
				return ExitError{Code: code}
			}
			return nil
		},
	}
	cmd.Flags().BoolVar(&ciMode, "ci", false, "CI lint — exit 1 when intel setup is non-deterministic")
	return cmd
}

func runDoctor(w io.Writer, flags *globalFlags, ciMode bool) (int, error) {
	dbPath := intel.ResolvedPath()
	home := intel.HomeDir()

	fmt.Fprintf(w, "\n  %s\n\n", ui.Bold(w, "Depfuse doctor"))

	fmt.Fprintf(w, "  %s\n", ui.Bold(w, "Local data (~/.depfuse)"))
	ui.MetaLine(w, "Home", home)
	ui.MetaLine(w, "Intel DB", dbPath)
	ui.MetaLine(w, "Reports", home+"/report.html")

	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		fmt.Fprintf(w, "    %s\n", ui.Dim(w, "intel.db not found — first scan extracts embedded snapshot, or run `depfuse collect`"))
	} else {
		store, err := intel.Open(dbPath)
		if err != nil {
			fmt.Fprintf(w, "    %s %v\n", ui.Danger(w, "error opening:"), err)
		} else {
			defer store.Close()
			has, _ := store.HasData()
			collected, _ := store.CollectedAt()
			stats, _ := store.Stats()
			if has {
				age := "unknown age"
				stale := false
				if !collected.IsZero() {
					since := time.Since(collected)
					age = formatAge(since)
					stale = since > intel.CollectTTL()
				}
				fmt.Fprintf(w, "    %s version %s · %d artifacts · collected %s ago\n",
					ui.Dim(w, "ok"), store.Version(), stats.Total, age)
				if stale {
					fmt.Fprintf(w, "    %s intel is older than %s — next scan will auto-refresh feeds\n",
						ui.Dim(w, "●"), intel.FormatCollectTTL(intel.CollectTTL()))
				}
			} else {
				fmt.Fprintf(w, "    %s\n", ui.Dim(w, "empty — run `depfuse collect`"))
			}
		}
	}

	fmt.Fprintf(w, "\n  %s\n", ui.Bold(w, "Environment"))
	fmt.Fprintf(w, "    %s auto-refresh when intel.db is older than %s\n",
		ui.Dim(w, "●"), intel.FormatCollectTTL(intel.CollectTTL()))
	token := strings.TrimSpace(os.Getenv("DEPFUSE_VULNCHECK_TOKEN"))
	if token == "" {
		token = strings.TrimSpace(os.Getenv("VULNCHECK_TOKEN"))
	}
	if token != "" {
		fmt.Fprintf(w, "    %s VulnCheck token set (full `collect`)\n", ui.Dim(w, "●"))
	} else {
		fmt.Fprintf(w, "    %s no VulnCheck token — `collect` needs DEPFUSE_VULNCHECK_TOKEN\n", ui.Dim(w, "○"))
	}

	fmt.Fprintf(w, "\n  %s\n", ui.Bold(w, "Decision memory"))
	file, err := decisions.Load(".")
	if err != nil || len(file.Decisions) == 0 {
		fmt.Fprintf(w, "    %s no decisions in .depfuse/decisions.yaml\n", ui.Dim(w, "○"))
	} else {
		fmt.Fprintf(w, "    %s %d decision(s) in %s\n", ui.Dim(w, "●"), len(file.Decisions), file.Path)
	}

	fmt.Fprintf(w, "\n  %s\n", ui.Dim(w, "Workflow: depfuse scan . → decisions record → depfuse watch ."))
	fmt.Fprintln(w)

	if ciMode {
		return runDoctorCI(w, dbPath)
	}
	return 0, nil
}

func runDoctorCI(w io.Writer, dbPath string) (int, error) {
	fmt.Fprintf(w, "  %s\n\n", ui.Bold(w, "CI checks"))
	problems := 0
	if os.Getenv("DEPFUSE_INTEL_DB") == "" {
		fmt.Fprintf(w, "    %s DEPFUSE_INTEL_DB not set — pin intel.db for reproducible CI\n", ui.Danger(w, "✗"))
		problems++
	} else {
		fmt.Fprintf(w, "    %s DEPFUSE_INTEL_DB=%s\n", ui.Dim(w, "●"), os.Getenv("DEPFUSE_INTEL_DB"))
	}
	if os.Getenv("DEPFUSE_SKIP_AUTO_COLLECT") != "1" {
		fmt.Fprintf(w, "    %s DEPFUSE_SKIP_AUTO_COLLECT=1 not set — scans may auto-refresh intel and drift\n", ui.Danger(w, "✗"))
		problems++
	} else {
		fmt.Fprintf(w, "    %s auto-collect disabled\n", ui.Dim(w, "●"))
	}
	if _, err := os.Stat(dbPath); os.IsNotExist(err) {
		fmt.Fprintf(w, "    %s intel.db missing at %s\n", ui.Danger(w, "✗"), dbPath)
		problems++
	}
	if problems > 0 {
		fmt.Fprintf(w, "\n  %s\n\n", ui.Danger(w, fmt.Sprintf("%d CI issue(s) — see docs/arsenal/operator-sheet.md", problems)))
	} else {
		fmt.Fprintf(w, "    %s CI intel setup looks pinned and deterministic\n\n", ui.Dim(w, "●"))
	}

	workflowProblems, err := runWorkflowHardeningCheck(w, ".")
	if err != nil {
		return 1, err
	}
	if problems > 0 || workflowProblems > 0 {
		return 1, nil
	}
	return 0, nil
}

// runWorkflowHardeningCheck lints .github/workflows/*.yml for supply-chain
// hardening gaps — kept as its own section, separate from CVE findings and
// from the intel-db determinism checks above. Only HIGH severity findings
// affect the exit code; MEDIUM/LOW are printed as advisories.
func runWorkflowHardeningCheck(w io.Writer, root string) (int, error) {
	fmt.Fprintf(w, "  %s\n\n", ui.Bold(w, "Workflow hardening (.github/workflows)"))
	findings, err := cidoctor.LintDir(root)
	if err != nil {
		return 0, err
	}
	if len(findings) == 0 {
		fmt.Fprintf(w, "    %s no workflow hardening gaps found\n\n", ui.Dim(w, "●"))
		return 0, nil
	}
	problems := 0
	for _, f := range findings {
		marker := ui.Dim(w, "○")
		switch f.Severity {
		case cidoctor.SeverityHigh:
			marker = ui.Danger(w, "✗")
			problems++
		case cidoctor.SeverityMedium:
			marker = ui.Dim(w, "●")
		}
		fmt.Fprintf(w, "    %s %s  %s\n", marker, ui.Dim(w, "["+f.File+"]"), f.Message)
		fmt.Fprintf(w, "        %s\n", ui.Dim(w, f.Recommendation))
	}
	fmt.Fprintln(w)
	return problems, nil
}

func formatAge(d time.Duration) string {
	if d < time.Minute {
		return "just now"
	}
	if d < time.Hour {
		return fmt.Sprintf("%dm", int(d.Minutes()))
	}
	if d < 24*time.Hour {
		return fmt.Sprintf("%dh", int(d.Hours()))
	}
	return fmt.Sprintf("%dd", int(d.Hours()/24))
}
