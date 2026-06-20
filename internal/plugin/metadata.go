package plugin

import (
	"bufio"
	"fmt"
	"os"
	"strings"

	"github.com/terraform-lint/terraform-lint/internal/types"
)

type RuleMetadata struct {
	ID          string
	Name        string
	Description string
	Severity    types.Severity
	Category    types.RuleCategory
	Enabled     bool
	FilePath    string
}

func ParseMetadata(filePath string) (*RuleMetadata, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("opening file: %w", err)
	}
	defer file.Close()

	meta := &RuleMetadata{
		FilePath: filePath,
		Enabled:  true,
	}

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" {
			continue
		}

		if !strings.HasPrefix(line, "//") {
			break
		}

		comment := strings.TrimSpace(strings.TrimPrefix(line, "//"))
		if !strings.HasPrefix(comment, "rule:") {
			continue
		}

		ruleLine := strings.TrimPrefix(comment, "rule:")
		parts := strings.SplitN(ruleLine, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		switch key {
		case "id":
			meta.ID = value
		case "name":
			meta.Name = value
		case "description":
			meta.Description = value
		case "severity":
			meta.Severity = types.Severity(value)
		case "category":
			meta.Category = types.RuleCategory(value)
		case "enabled":
			meta.Enabled = strings.ToLower(value) == "true"
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}

	if meta.ID == "" {
		return nil, fmt.Errorf("missing rule:id metadata")
	}
	if meta.Name == "" {
		return nil, fmt.Errorf("missing rule:name metadata")
	}
	if meta.Severity == "" {
		return nil, fmt.Errorf("missing rule:severity metadata")
	}
	if meta.Category == "" {
		return nil, fmt.Errorf("missing rule:category metadata")
	}

	return meta, nil
}
