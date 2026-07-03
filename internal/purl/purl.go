package purl

import "fmt"

// NPM builds a Package URL for an npm package.
func NPM(name, version string) string {
	return fmt.Sprintf("pkg:npm/%s@%s", name, version)
}
