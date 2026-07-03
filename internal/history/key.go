package history

import (
	"fmt"
	"strings"

	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
)

func FindingKey(comp models.Component, cve models.CveMatch) string {
	id := cve.CVEID
	if id == "" {
		id = cve.AdvisoryID()
	}
	return fmt.Sprintf("%s@%s:%s", comp.Name, comp.Version, strings.ToUpper(id))
}
