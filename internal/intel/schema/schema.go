package schema

import (
	_ "embed"
	"fmt"
	"strings"
)

const SchemaVersion = "2"

//go:embed 002_v2.sql
var v2SQL string

// V2DDL returns the v2 schema DDL statements.
func V2DDL() string {
	return v2SQL
}

var legacyDrops = []string{
	`DROP TABLE IF EXISTS artifacts`,
	`DROP TABLE IF EXISTS feed_runs`,
	`DROP TABLE IF EXISTS feeds`,
	`DROP TABLE IF EXISTS vuln_aliases`,
	`DROP TABLE IF EXISTS vulnerabilities`,
	`DROP VIEW IF EXISTS v_vuln_signals`,
}

// Migrate applies schema migrations idempotently.
func Migrate(exec func(string) error, getMeta func(string) (string, error), setMeta func(string, string) error) error {
	current, _ := getMeta("schema_version")
	if current == SchemaVersion {
		return nil
	}
	for _, drop := range legacyDrops {
		_ = exec(drop)
	}
	stmts := splitSQL(v2SQL)
	for _, stmt := range stmts {
		if strings.TrimSpace(stmt) == "" {
			continue
		}
		if err := exec(stmt); err != nil {
			return fmt.Errorf("migrate: %w", err)
		}
	}
	return setMeta("schema_version", SchemaVersion)
}

func splitSQL(sql string) []string {
	var out []string
	var buf strings.Builder
	for _, line := range strings.Split(sql, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "--") {
			continue
		}
		buf.WriteString(line)
		buf.WriteByte('\n')
		if strings.HasSuffix(trimmed, ";") {
			out = append(out, buf.String())
			buf.Reset()
		}
	}
	if s := strings.TrimSpace(buf.String()); s != "" {
		out = append(out, s)
	}
	return out
}
