package output

import (
	"fmt"
	"os"

	"github.com/terraform-lint/terraform-lint/internal/types"
)

type Formatter interface {
	Format(result *types.ScanResult) (string, error)
	Name() string
}

func GetFormatter(format string) (Formatter, error) {
	switch format {
	case "terminal", "table", "":
		return NewTerminalFormatter(), nil
	case "json":
		return NewJSONFormatter(), nil
	case "sarif":
		return NewSARIFFormatter(), nil
	case "junit", "xml":
		return NewJUnitFormatter(), nil
	case "markdown", "md":
		return NewMarkdownFormatter(), nil
	default:
		return nil, fmt.Errorf("unsupported output format: %s (supported: terminal, json, sarif, junit, markdown)", format)
	}
}

func WriteOutput(formatter Formatter, result *types.ScanResult, outputPath string) error {
	content, err := formatter.Format(result)
	if err != nil {
		return fmt.Errorf("formatting output: %w", err)
	}

	if outputPath != "" {
		return os.WriteFile(outputPath, []byte(content), 0644)
	}

	fmt.Print(content)
	return nil
}

func DetermineExitCode(result *types.ScanResult, failOn string) int {
	if len(result.Findings) == 0 {
		return 0
	}

	var hasError, hasWarning bool
	for _, finding := range result.Findings {
		switch finding.Severity {
		case types.SeverityError:
			hasError = true
		case types.SeverityWarning:
			hasWarning = true
		}
	}

	switch failOn {
	case "error", "":
		if hasError {
			return 1
		}
		return 0
	case "warning":
		if hasError || hasWarning {
			return 1
		}
		return 0
	case "info":
		return 1
	default:
		if hasError {
			return 1
		}
		return 0
	}
}
