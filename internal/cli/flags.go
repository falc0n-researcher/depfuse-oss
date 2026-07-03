package cli

import (
	"github.com/spf13/cobra"

	"github.com/falc0n-researcher/depfuse-oss/internal/intel"
)

// globalFlags are shared output/runtime options (kept minimal).
type globalFlags struct {
	format  string
	quiet   bool
	verbose bool
}

func bindGlobalFlags(root *cobra.Command) *globalFlags {
	f := &globalFlags{}
	root.PersistentFlags().StringVar(&f.format, "format", "cli", "Output: cli, json, html, or sarif")
	root.PersistentFlags().BoolVar(&f.quiet, "quiet", false, "Suppress progress output")
	root.PersistentFlags().BoolVar(&f.verbose, "verbose", false, "Show evidence details and briefings")
	return f
}

func (f *globalFlags) baseOpts() scanOpts {
	return scanOpts{
		DBPath:  intel.ResolvedPath(),
		Offline: intel.OfflineFromEnv(),
		Format:  f.format,
		Quiet:   f.quiet,
		Verbose: f.verbose,
	}
}

// scanCommandFlags are scan-only options (global flags are read at RunE time).
type scanCommandFlags struct {
	OutDir         string
	CI             bool
	FailOn         string
	ShowSuppressed bool
	Delta          bool
	NoHistory      bool
	ShowTree       bool
}

// treeCommandFlags control registry dependency-tree resolution.
type treeCommandFlags struct {
	TreeDepth  int
	IncludeDev bool
}

func bindTreeFlags(cmd *cobra.Command, local *treeCommandFlags) {
	cmd.Flags().IntVar(&local.TreeDepth, "depth", 0, "Dependency tree depth (0=full tree, 1=root/direct only)")
	cmd.Flags().BoolVar(&local.IncludeDev, "include-dev", false, "Include devDependencies when resolving registry trees")
}

func (f *globalFlags) mergedScanOpts(local scanCommandFlags) scanOpts {
	o := f.baseOpts()
	o.OutDir = local.OutDir
	o.CI = local.CI
	o.FailOn = local.FailOn
	o.ShowSuppressed = local.ShowSuppressed
	o.Delta = local.Delta
	o.NoHistory = local.NoHistory
	o.ShowTree = local.ShowTree
	return o
}

func applyTreeFlags(opts *scanOpts, tree treeCommandFlags) {
	opts.TreeDepth = tree.TreeDepth
	opts.IncludeDev = tree.IncludeDev
}

// bindReportFlags adds --out-dir for commands that write HTML/MD reports.
func bindReportFlags(cmd *cobra.Command, local *scanCommandFlags) {
	cmd.Flags().StringVar(&local.OutDir, "out-dir", "", "Override report output directory (default: ~/.depfuse)")
}

// bindScanFlags adds CI/report flags only on scan (not global noise).
func bindScanFlags(cmd *cobra.Command, local *scanCommandFlags) {
	bindReportFlags(cmd, local)
	cmd.Flags().BoolVar(&local.CI, "ci", false, "CI gate — exit 1 on weaponized prod findings (--fail-on); incomplete lockfile coverage always exits 1")
	cmd.Flags().StringVar(&local.FailOn, "fail-on", "p0,p1", "Prod priorities that fail CI (aliases: Exploited, Exploit-Ready, p0, p1, …)")
	cmd.Flags().BoolVar(&local.ShowSuppressed, "show-suppressed", false, "Include .depfuseignore suppressions")
	cmd.Flags().BoolVar(&local.Delta, "delta", false, "Show changes since last scan (prefer: depfuse watch)")
	_ = cmd.Flags().MarkDeprecated("delta", "use `depfuse watch` for decision memory")
	cmd.Flags().BoolVar(&local.NoHistory, "no-history", false, "Skip scan history persistence")
}
