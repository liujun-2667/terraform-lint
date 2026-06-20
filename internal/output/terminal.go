package output

import (
	"fmt"
	"sort"
	"strings"

	"github.com/fatih/color"
	"github.com/olekukonko/tablewriter"
	"github.com/terraform-lint/terraform-lint/internal/types"
)

type TerminalFormatter struct{}

func NewTerminalFormatter() *TerminalFormatter {
	return &TerminalFormatter{}
}

func (f *TerminalFormatter) Name() string {
	return "terminal"
}

func (f *TerminalFormatter) Format(result *types.ScanResult) (string, error) {
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

	sb.WriteString(color.New(color.Bold).Sprintf("\nTerraform Lint Scan Results\n"))
	sb.WriteString(fmt.Sprintf("Files scanned: %d\n", result.FilesScanned))
	sb.WriteString(fmt.Sprintf("Duration: %s\n\n", result.Duration))

	if len(result.Findings) == 0 {
		sb.WriteString(color.New(color.FgGreen, color.Bold).Sprintf("✓ No issues found!\n"))
		return sb.String(), nil
	}

	sb.WriteString(fmt.Sprintf(
		"Found %d issues: %s %s %s\n\n",
		len(result.Findings),
		color.New(color.FgRed).Sprintf("%d errors", errorCount),
		color.New(color.FgYellow).Sprintf("%d warnings", warningCount),
		color.New(color.FgBlue).Sprintf("%d infos", infoCount),
	))

	findings := make([]types.Finding, len(result.Findings))
	copy(findings, result.Findings)

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].Severity.Value() != findings[j].Severity.Value() {
			return findings[i].Severity.Value() > findings[j].Severity.Value()
		}
		if findings[i].File != findings[j].File {
			return findings[i].File < findings[j].File
		}
		return findings[i].Line < findings[j].Line
	})

	table := tablewriter.NewWriter(&sb)
	table.SetHeader([]string{"File", "Line", "Rule ID", "Severity", "Message"})
	table.SetAutoWrapText(false)
	table.SetAutoFormatHeaders(true)
	table.SetHeaderAlignment(tablewriter.ALIGN_LEFT)
	table.SetAlignment(tablewriter.ALIGN_LEFT)
	table.SetCenterSeparator("")
	table.SetColumnSeparator("")
	table.SetRowSeparator("")
	table.SetHeaderLine(false)
	table.SetTablePadding("  ")
	table.SetNoWhiteSpace(true)

	for _, finding := range findings {
		severityStr := string(finding.Severity)
		switch finding.Severity {
		case types.SeverityError:
			severityStr = color.New(color.FgRed, color.Bold).Sprint(severityStr)
		case types.SeverityWarning:
			severityStr = color.New(color.FgYellow, color.Bold).Sprint(severityStr)
		case types.SeverityInfo:
			severityStr = color.New(color.FgBlue, color.Bold).Sprint(severityStr)
		}

		ruleID := color.New(color.FgCyan).Sprint(finding.RuleID)

		table.Append([]string{
			truncatePath(finding.File),
			fmt.Sprintf("%d", finding.Line),
			ruleID,
			severityStr,
			truncateMessage(finding.Message, 80),
		})
	}

	table.Render()

	sb.WriteString("\n")

	return sb.String(), nil
}

func truncatePath(path string) string {
	if len(path) > 40 {
		return "..." + path[len(path)-37:]
	}
	return path
}

func truncateMessage(msg string, maxLen int) string {
	if len(msg) > maxLen {
		return msg[:maxLen-3] + "..."
	}
	return msg
}
