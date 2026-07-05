package cli

import (
	"context"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/falc0n-researcher/depfuse-oss/internal/gitrepo"
	"github.com/falc0n-researcher/depfuse-oss/internal/scan"
)

type scanOpts struct {
	Path           string
	RepoURL        string
	RepoRef        string
	Package        string
	DBPath         string
	Offline        bool
	Format         string
	OutDir         string
	CI             bool
	FailOn         string
	Quiet          bool
	Verbose        bool
	ShowSuppressed bool
	Delta          bool
	NoHistory      bool
	TreeDepth      int
	IncludeDev     bool
	ShowTree       bool // expand full nested shadow dep tree in CLI output
}

func (o scanOpts) toScanOptions() scan.Options {
	return scan.Options{
		Path: o.Path, RepoURL: o.RepoURL, RepoRef: o.RepoRef, Package: o.Package,
		DBPath: o.DBPath, Offline: o.Offline, Format: o.Format, OutDir: o.OutDir,
		CI: o.CI, FailOn: o.FailOn, Quiet: o.Quiet, Verbose: o.Verbose,
		ShowSuppressed: o.ShowSuppressed, Delta: o.Delta, NoHistory: o.NoHistory,
		TreeDepth: o.TreeDepth, IncludeDev: o.IncludeDev, ShowTree: o.ShowTree,
	}
}

func runScan(ctx context.Context, opts scanOpts) error {
	runner := &scan.Runner{}
	_, code, err := runner.Run(ctx, opts.toScanOptions())
	if err != nil {
		return err
	}
	if code != 0 {
		return ExitError{Code: code}
	}
	return nil
}

func newScanCmd(flags *globalFlags) *cobra.Command {
	var repoURL, repoRef string
	var local scanCommandFlags
	var treeLocal treeCommandFlags

	cmd := &cobra.Command{
		Use:     "scan [path]",
		GroupID: "core",
		Short:   "Scan a project for weaponized dependency exposure",
		Long:    "Resolve npm lockfiles, match OSV advisories, classify exploit evidence, and emit FIX NOW / FIX SOON / OK verdicts with receipts.",
		Args:    cobra.MaximumNArgs(1),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return validateFormat(flags.format, formatsScan)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := flags.mergedScanOpts(local)
			applyTreeFlags(&opts, treeLocal)
			opts.Path = "."
			if len(args) > 0 {
				if gitrepo.IsGitHubURL(args[0]) {
					opts.RepoURL = args[0]
				} else {
					opts.Path = args[0]
				}
			}
			if repoURL != "" {
				if opts.RepoURL != "" && opts.RepoURL != repoURL {
					return fmt.Errorf("conflicting repository URLs: %q and %q", opts.RepoURL, repoURL)
				}
				opts.RepoURL = repoURL
			}
			opts.RepoRef = repoRef
			return runScan(cmd.Context(), opts)
		},
	}

	cmd.Flags().StringVar(&repoURL, "repo", "", "GitHub repo URL to shallow-clone")
	cmd.Flags().StringVar(&repoRef, "ref", "", "Git ref with --repo")
	cmd.Flags().BoolVar(&local.ShowTree, "tree", false, "Expand full nested shadow dependency tree in output")
	bindScanFlags(cmd, &local)
	bindTreeFlags(cmd, &treeLocal)
	return cmd
}

func newPackageCmd(flags *globalFlags) *cobra.Command {
	var treeLocal treeCommandFlags
	var local scanCommandFlags

	cmd := &cobra.Command{
		Use:     "package [name[@version]]",
		GroupID: "core",
		Short:   "Look up CVEs for one npm package and its dependency tree",
		Args:    cobra.ExactArgs(1),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return validateFormat(flags.format, formatsScan)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := flags.baseOpts()
			opts.OutDir = local.OutDir
			opts.ShowTree = local.ShowTree
			applyTreeFlags(&opts, treeLocal)
			opts.Package = args[0]
			runner := &scan.Runner{}
			if opts.Verbose {
				code, err := runner.RunPackageEvidence(cmd.Context(), args[0], opts.toScanOptions())
				if err != nil {
					return err
				}
				if code != 0 {
					return ExitError{Code: code}
				}
				return nil
			}
			return runScan(cmd.Context(), opts)
		},
	}
	cmd.Flags().BoolVar(&local.ShowTree, "tree", false, "Expand full nested shadow dependency tree in output")
	bindReportFlags(cmd, &local)
	bindTreeFlags(cmd, &treeLocal)
	return cmd
}

func newCVECmd(flags *globalFlags) *cobra.Command {
	var timeline bool
	var local scanCommandFlags

	cmd := &cobra.Command{
		Use:     "cve [CVE-ID]",
		GroupID: "core",
		Short:   "Classify exploit evidence for a CVE",
		Args:    cobra.ExactArgs(1),
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return validateFormat(flags.format, formatsScan)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			opts := flags.baseOpts()
			opts.OutDir = local.OutDir
			runner := &scan.Runner{}
			if timeline {
				return runner.RunCVETimeline(cmd.Context(), args[0], opts.toScanOptions())
			}
			_, err := runner.RunCVE(cmd.Context(), args[0], opts.toScanOptions())
			return err
		},
	}
	cmd.Flags().BoolVar(&timeline, "timeline", false, "Show dated evidence timeline")
	bindReportFlags(cmd, &local)
	return cmd
}
