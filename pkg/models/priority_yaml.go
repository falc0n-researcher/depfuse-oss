package models

import (
	"fmt"

	"gopkg.in/yaml.v3"
)

// MarshalYAML writes priority as P0–P4.
func (p Priority) MarshalYAML() (interface{}, error) {
	return p.String(), nil
}

// UnmarshalYAML accepts P0–P4 codes or legacy level names.
func (p *Priority) UnmarshalYAML(value *yaml.Node) error {
	var s string
	if err := value.Decode(&s); err == nil {
		*p = ParsePriority(s)
		return nil
	}
	var n int
	if err := value.Decode(&n); err == nil {
		*p = Priority(n)
		return nil
	}
	return fmt.Errorf("invalid priority: %v", value.Value)
}
