package cli

import (
	"fmt"
	"strings"
)

var (
	formatsScan    = []string{"cli", "json", "jsonl", "html", "sarif"}
	formatsMemory  = []string{"cli", "json", "markdown", "md"}
	formatsCollect = []string{"cli", "json"}
)

func validateFormat(format string, allowed []string) error {
	for _, a := range allowed {
		if format == a {
			return nil
		}
	}
	return fmt.Errorf("unsupported --format %q (use %s)", format, strings.Join(allowed, ", "))
}
