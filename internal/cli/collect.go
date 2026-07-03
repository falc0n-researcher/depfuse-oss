package cli

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/spf13/cobra"

	"github.com/falc0n-researcher/depfuse-oss/internal/cli/ui"
	"github.com/falc0n-researcher/depfuse-oss/internal/intel"
	"github.com/falc0n-researcher/depfuse-oss/internal/intel/collector"
)

func newCollectCmd(flags *globalFlags) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "collect",
		GroupID: "intel",
		Short:   "Fetch intelligence feeds into the local database",
		Long:    "Downloads VulnCheck KEV, Metasploit, Exploit-DB, Nuclei, PoC metadata, EPSS, and OSV advisories into ~/.depfuse/intel.db. Scan/package/cve auto-refresh when the DB is older than 4 hours; use collect to force a refresh. Requires DEPFUSE_VULNCHECK_TOKEN (or VULNCHECK_TOKEN in .env).",
		PreRunE: func(cmd *cobra.Command, args []string) error {
			return validateFormat(flags.format, formatsCollect)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			path := flags.baseOpts().DBPath

			ctx := cmd.Context()
			if ctx == nil {
				ctx = context.Background()
			}

			store, err := intel.Open(path)
			if err != nil {
				return err
			}
			defer store.Close()

			ui.BeginCommand(os.Stderr, flags.quiet, "intelligence feeds refreshed")
			prog := ui.NewProgress(os.Stderr, flags.quiet)
			col := collector.New(store)
			col.OnProgress = prog.Step

			if err := col.RunAll(ctx); err != nil {
				has, _ := store.HasData()
				if has {
					fmt.Fprintf(os.Stderr, "warning: collect finished with errors: %v\n", err)
				} else {
					return err
				}
			}

			stats, err := store.Stats()
			if err != nil {
				return err
			}
			feeds := feedRows(stats)

			if flags.format == "json" {
				out := collectResult{
					Path:      path,
					Version:   store.Version(),
					Total:     stats.Total,
					Timestamp: time.Now().UTC().Format(time.RFC3339),
					Feeds:     feeds,
				}
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				return enc.Encode(out)
			}

			ui.RenderCollectDone(os.Stdout, path, store.Version(), stats.Total, feeds)
			return nil
		},
	}
	return cmd
}

type collectResult struct {
	Path      string       `json:"path"`
	Version   string       `json:"version"`
	Total     int          `json:"totalArtifacts"`
	Timestamp string       `json:"timestamp"`
	Feeds     []ui.FeedRow `json:"feeds"`
}

func feedRows(stats intel.FeedStats) []ui.FeedRow {
	rows := make([]ui.FeedRow, 0, len(stats.Feeds))
	for _, f := range stats.Feeds {
		rows = append(rows, ui.FeedRow{
			Name:        f.Name,
			LastSuccess: f.LastSuccess,
			LastError:   f.LastError,
			Artifacts:   f.ArtifactCount,
		})
	}
	return rows
}
