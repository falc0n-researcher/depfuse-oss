package models_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/falc0n-researcher/depfuse-oss/pkg/models"
	"github.com/stretchr/testify/require"
)

func schemasDir(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	require.True(t, ok)
	return filepath.Join(filepath.Dir(file), "..", "..", "schemas")
}

func TestScanResultSchemaVersionMatchesConstant(t *testing.T) {
	result := models.ScanResult{SchemaVersion: models.CurrentSchemaVersion}
	data, err := json.Marshal(result)
	require.NoError(t, err)

	var decoded map[string]any
	require.NoError(t, json.Unmarshal(data, &decoded))
	require.Equal(t, models.CurrentSchemaVersion, decoded["schemaVersion"])
}

func TestScanResultSchemaFilesAreValidJSON(t *testing.T) {
	dir := schemasDir(t)
	for _, name := range []string{"scan-result.schema.json", "finding.schema.json"} {
		data, err := os.ReadFile(filepath.Join(dir, name))
		require.NoError(t, err, name)
		var doc map[string]any
		require.NoError(t, json.Unmarshal(data, &doc), "%s must be valid JSON", name)
		require.Equal(t, name, doc["$id"], "%s must declare a matching $id for $ref resolution", name)
	}
}
