package output

import (
	"fmt"
	"sort"
	"strings"

	"github.com/terraform-lint/terraform-lint/internal/types"
)

type MarkdownFormatter struct{}

func NewMarkdownFormatter() *MarkdownFormatter {
	return &MarkdownFormatter{}
}

func (f *MarkdownFormatter) Name() string {
	return "markdown"
}

func (f *MarkdownFormatter) Format(result *types.ScanResult) (string, error) {
	var sb strings.Builder

	errorCount := 0
	warningCount := 0
	infoCount := 0

	for _, finding := range result.Findings {
		switch finding.Severity {
		case types.SeverityError:
			errorCount++
		case types.SeverityWarning:
			warningCount++
		case types.SeverityInfo:
			infoCount++
		}
	}

	sb.WriteString("# Terraform Lint Scan Results\n\n")
	sb.WriteString(fmt.Sprintf("**Files scanned:** %d  \n", result.FilesScanned))
	sb.WriteString(fmt.Sprintf("**Duration:** %s  \n\n", result.Duration))

	if len(result.Findings) == 0 {
		sb.WriteString("✅ **No issues found!**\n")
		return sb.String(), nil
	}

	sb.WriteString(fmt.Sprintf("## Summary\n\n"))
	sb.WriteString(fmt.Sprintf("| Severity | Count |\n"))
	sb.WriteString(fmt.Sprintf("|----------|-------|\n"))
	sb.WriteString(fmt.Sprintf("| 🔴 Error | %d |\n", errorCount))
	sb.WriteString(fmt.Sprintf("| 🟡 Warning | %d |\n", warningCount))
	sb.WriteString(fmt.Sprintf("| 🔵 Info | %d |\n", infoCount))
	sb.WriteString(fmt.Sprintf("| **Total** | **%d** |\n\n", len(result.Findings)))

	findings := make([]types.Finding, len(result.Findings))
	copy(findings, result.Findings)

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Severity.Value() != findings[j].Severity.Value() {
			return findings[i].Severity.Value() > findings[j].Severity.Value()
		}
		if findings[i].Category != findings[j].Category {
			return findings[i].Category < findings[j].Category
		}
		if findings[i].File != findings[j].File {
			return findings[i].File < findings[j].File
		}
		return findings[i].Line < findings[j].Line
	})

	byCategory := make(map[string][]types.Finding)
	for _, finding := range findings {
		cat := string(finding.Category)
		byCategory[cat] = append(byCategory[cat], finding)
	}

	for _, category := range []string{string(types.CategorySecurity), string(types.CategoryBestPractice), string(types.CategoryCost)} {
		catFindings, ok := byCategory[category]
		if !ok || len(catFindings) == 0 {
			continue
		}

		catName := strings.Title(strings.ReplaceAll(category, "_", " "))
		sb.WriteString(fmt.Sprintf("## %s\n\n", catName))
		sb.WriteString("| File | Line | Rule ID | Severity | Message |\n")
		sb.WriteString("|------|------|---------|----------|---------|\n")

		for _, finding := range catFindings {
			severityIcon := ""
			switch finding.Severity {
			case types.SeverityError:
				severityIcon = "🔴 error"
			case types.SeverityWarning:
				severityIcon = "🟡 warning"
			case types.SeverityInfo:
				severityIcon = "🔵 info"
			}

			sb.WriteString(fmt.Sprintf(
				"| `%s` | %d | `%s` | %s | %s |\n",
				escapeMarkdown(finding.File),
				finding.Line,
				finding.RuleID,
				severityIcon,
				escapeMarkdown(finding.Message),
			))
		}

		sb.WriteString("\n")
	}

	return sb.String(), nil
}

func escapeMarkdown(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	s = strings.ReplaceAll(s, "`", "\\`")
	s = strings.ReplaceAll(s, "*", "\\*")
	s = strings.ReplaceAll(s, "_", "\\_")
	return s
}
