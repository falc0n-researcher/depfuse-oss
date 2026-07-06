package cli

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/falc0n-researcher/depfuse-oss/internal/cli/ui"
	"github.com/falc0n-researcher/depfuse-oss/internal/decisions"
	"github.com/falc0n-researcher/depfuse-oss/internal/intel"
	"github.com/falc0n-researcher/depfuse-oss/internal/scan"
	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

func newDecisionsCmd(flags *globalFlags) *cobra.Command {
	var projectPath string

	cmd := &cobra.Command{
		Use:     "decisions",
		GroupID: "memory",
		Short:   "Manage stored accept-risk decisions",
		Long:    "Decisions live in .depfuse/decisions.yaml and auto-apply on scan/watch until exploit evidence reopens them.",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return validateFormat(flags.format, formatsMemory)
		},
	}
	cmd.PersistentFlags().StringVar(&projectPath, "path", ".", "Project root (default .)")

	cmd.AddCommand(newDecisionsListCmd(flags, &projectPath))
	cmd.AddCommand(newDecisionsRecordCmd(flags, &projectPath))
	cmd.AddCommand(newDecisionsExportCmd(flags, &projectPath))
	cmd.AddCommand(newDecisionsExplainCmd(flags, &projectPath))

	cmd.RunE = func(cmd *cobra.Command, args []string) error {
		return renderDecisionsList(flags, projectPath)
	}
	return cmd
}

func newDecisionsListCmd(flags *globalFlags, projectPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List stored decisions (default)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return renderDecisionsList(flags, *projectPath)
		},
	}
}

func newDecisionsRecordCmd(flags *globalFlags, projectPath *string) *cobra.Command {
	var as, reason, pkg, version string

	cmd := &cobra.Command{
		Use:   "record [CVE-ID]",
		Short: "Record a decision bound to current evidence",
		Example: `  depfuse decisions record CVE-2025-29927 --as accept --reason "not deployed"
  depfuse decisions record CVE-2025-29927 --as accept --reason "dev only" --package next --version 15.1.0`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			kind, err := parseDecisionAs(as)
			if err != nil {
				return err
			}
			runner := &scan.Runner{}
			d, err := runner.RunDecide(cmd.Context(), scan.DecideOptions{
				CVE: args[0], Package: pkg, Version: version,
				Decision: kind, Reason: reason, Path: *projectPath,
				DBPath: intel.ResolvedPath(), Offline: intel.OfflineFromEnv(),
			})
			if err != nil {
				return err
			}
			if flags.format == "json" {
				return json.NewEncoder(os.Stdout).Encode(d)
			}
			file, _ := decisions.Load(*projectPath)
			ui.RenderDecideConfirm(os.Stdout, d, file.Path)
			return nil
		},
	}
	cmd.Flags().StringVar(&as, "as", "", "Decision type: accept, block, na (required)")
	cmd.Flags().StringVar(&reason, "reason", "", "Why you made this call (required)")
	cmd.Flags().StringVar(&pkg, "package", "", "Scope to package name")
	cmd.Flags().StringVar(&version, "version", "", "Scope to exact version")
	_ = cmd.MarkFlagRequired("as")
	_ = cmd.MarkFlagRequired("reason")
	return cmd
}

func newDecisionsExplainCmd(flags *globalFlags, projectPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "explain CVE-ID",
		Short: "Show a stored decision's history vs current evidence, and reopen status",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			runner := &scan.Runner{}
			explains, err := runner.RunDecisionsExplain(cmd.Context(), args[0], *projectPath, intel.ResolvedPath(), intel.OfflineFromEnv())
			if err != nil {
				return err
			}
			if flags.format == "json" {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(explains)
			}
			ui.RenderDecisionExplain(os.Stdout, explains)
			return nil
		},
	}
}

func newDecisionsExportCmd(flags *globalFlags, projectPath *string) *cobra.Command {
	var format string
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export decisions.yaml",
		RunE: func(cmd *cobra.Command, args []string) error {
			if format == "" {
				format = flags.format
			}
			if format == "cli" {
				format = "yaml"
			}
			return scan.ExportDecisions(*projectPath, format)
		},
	}
	cmd.Flags().StringVar(&format, "format", "yaml", "yaml or json")
	return cmd
}

func newWatchCmd(flags *globalFlags) *cobra.Command {
	var baselineDB, since string
	var intelOnly bool

	cmd := &cobra.Command{
		Use:     "watch [path]",
		GroupID: "memory",
		Short:   "What needs attention vs what stays silent",
		Long: `Decision-memory hub: reopened accept-risk decisions, scan escalations,
and optional intel feed changes (--since last-db).

Replaces: scan --delta, evidence diff`,
		Args: cobra.MaximumNArgs(1),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return validateFormat(flags.format, formatsMemory)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := flags.baseOpts()
			if len(args) > 0 {
				opts.Path = args[0]
			} else {
				opts.Path = "."
			}
			if intelOnly {
				return runIntelWatch(cmd, flags, baselineDB, since)
			}
			runner := &scan.Runner{}
			_, err := runner.RunWatch(cmd.Context(), scan.WatchOptions{
				Options: opts.toScanOptions(), BaselineDB: baselineDB, SinceSpec: since,
			})
			return err
		},
	}
	cmd.Flags().StringVar(&since, "since", "", "Intel changes since date or last-db")
	cmd.Flags().StringVar(&baselineDB, "baseline-db", "", "Compare intel.db against a baseline snapshot")
	cmd.Flags().BoolVar(&intelOnly, "intel-only", false, "Skip project scan — only show intel evidence diff")
	return cmd
}

func runIntelWatch(cmd *cobra.Command, flags *globalFlags, baselineDB, since string) error {
	runner := &scan.Runner{}
	return runner.RunEvidenceDiff(cmd.Context(), scan.EvidenceDiffOptions{
		DBPath: intel.ResolvedPath(), BaselineDB: baselineDB, SinceSpec: since, OutputFormat: flags.format,
	})
}

func renderDecisionsList(flags *globalFlags, path string) error {
	file, err := scan.ListDecisions(path)
	if err != nil {
		return err
	}
	if flags.format == "json" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(models.DecisionFile{Decisions: file.Decisions})
	}
	ui.RenderDecisionsList(os.Stdout, file.Decisions)
	return nil
}

func parseDecisionAs(as string) (models.DecisionKind, error) {
	switch strings.ToLower(strings.TrimSpace(as)) {
	case "accept", "accepted", "accepted-risk", "accept-risk":
		return models.DecisionAcceptedRisk, nil
	case "block", "blocked":
		return models.DecisionBlocked, nil
	case "na", "n/a", "not-applicable", "not_applicable":
		return models.DecisionNotApplicable, nil
	case "":
		return "", fmt.Errorf("--as is required (accept, block, or na)")
	default:
		return "", fmt.Errorf("unknown --as %q (use accept, block, or na)", as)
	}
}

// Hidden alias: depfuse decide → decisions record
func newDecideAlias(flags *globalFlags) *cobra.Command {
	var as, reason, pkg, version, path string
	cmd := &cobra.Command{
		Use:        "decide [CVE-ID]",
		Hidden:     true,
		Deprecated: "use `depfuse decisions record`",
		Args:       cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			kind, err := parseDecisionAs(as)
			if err != nil {
				return err
			}
			if reason == "" {
				return fmt.Errorf("--reason is required")
			}
			runner := &scan.Runner{}
			d, err := runner.RunDecide(cmd.Context(), scan.DecideOptions{
				CVE: args[0], Package: pkg, Version: version,
				Decision: kind, Reason: reason, Path: path,
				DBPath: intel.ResolvedPath(), Offline: intel.OfflineFromEnv(),
			})
			if err != nil {
				return err
			}
			if flags.format == "json" {
				return json.NewEncoder(os.Stdout).Encode(d)
			}
			file, _ := decisions.Load(path)
			ui.RenderDecideConfirm(os.Stdout, d, file.Path)
			return nil
		},
	}
	cmd.Flags().StringVar(&as, "as", "accept", "accept, block, or na")
	cmd.Flags().Bool("accept", false, "Deprecated — use --as accept")
	cmd.Flags().StringVar(&reason, "reason", "", "Rationale")
	cmd.Flags().StringVar(&pkg, "package", "", "Package scope")
	cmd.Flags().StringVar(&version, "version", "", "Version scope")
	cmd.Flags().StringVar(&path, "path", ".", "Project root")
	return cmd
}

func newEvidenceAlias(flags *globalFlags) *cobra.Command {
	var baselineDB, since string
	cmd := &cobra.Command{
		Use:        "evidence",
		Hidden:     true,
		Deprecated: "use `depfuse watch --since` or `depfuse watch --intel-only`",
	}
	diff := &cobra.Command{
		Use:   "diff [CVE-ID]",
		Short: "Diff exploit evidence (deprecated)",
		Args:  cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := scan.EvidenceDiffOptions{
				DBPath: intel.ResolvedPath(), BaselineDB: baselineDB, SinceSpec: since, OutputFormat: flags.format,
			}
			if len(args) > 0 {
				opts.CVE = args[0]
			}
			return (&scan.Runner{}).RunEvidenceDiff(cmd.Context(), opts)
		},
	}
	diff.Flags().StringVar(&baselineDB, "baseline-db", "", "Baseline intel.db")
	diff.Flags().StringVar(&since, "since", "", "Since date or last-db")
	cmd.AddCommand(diff)
	return cmd
}
