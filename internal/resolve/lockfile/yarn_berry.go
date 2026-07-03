package lockfile

import "strings"

func isYarnBerryLock(content string) bool {
	return strings.Contains(content, "__metadata:")
}

func parseYarnBerryLock(content string) map[string]string {
	out := map[string]string{}
	lines := strings.Split(content, "\n")
	var currentKey string
	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") && strings.HasSuffix(trimmed, ":") {
			currentKey = strings.TrimSuffix(trimmed, ":")
			currentKey = strings.Trim(currentKey, `"'`)
			continue
		}
		if strings.HasPrefix(trimmed, "version") && currentKey != "" && currentKey != "__metadata" {
			ver := strings.TrimSpace(strings.TrimPrefix(trimmed, "version"))
			ver = strings.TrimPrefix(ver, ":")
			ver = strings.Trim(ver, " \"")
			name := yarnBerryPackageName(currentKey)
			if name != "" && ver != "" {
				out[name] = ver
			}
		}
	}
	return out
}

func yarnBerryPackageName(key string) string {
	for _, sep := range []string{"@npm:", "@workspace:", "@patch:", "@portal:"} {
		if at := strings.Index(key, sep); at > 0 {
			return key[:at]
		}
	}
	return yarnPackageName(key)
}
