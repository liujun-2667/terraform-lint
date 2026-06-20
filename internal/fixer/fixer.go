package fixer

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/terraform-lint/terraform-lint/internal/types"
)

type Fixer struct {
	backupDir string
}

func NewFixer() *Fixer {
	return &Fixer{
		backupDir: ".tflint-backup",
	}
}

func (f *Fixer) Fix(findings []types.Finding, ruleRegistry interface{}) (int, error) {
	fixedCount := 0
	fixedFiles := make(map[string]bool)

	for _, finding := range findings {
		if finding.FixSuggestion == "" {
			continue
		}

		rule, ok := f.getRuleByID(ruleRegistry, finding.RuleID)
		if !ok {
			continue
		}

		canFixRule, ok := rule.(interface{ CanFix() bool })
		if !ok || !canFixRule.CanFix() {
			continue
		}

		if !fixedFiles[finding.File] {
			if err := f.backupFile(finding.File); err != nil {
				return fixedCount, fmt.Errorf("backup file %s: %w", finding.File, err)
			}
			fixedFiles[finding.File] = true
		}

		if err := f.applyFix(finding); err == nil {
			fixedCount++
		}
	}

	return fixedCount, nil
}

func (f *Fixer) getRuleByID(registry interface{}, ruleID string) (types.Rule, bool) {
	type getRuleByID interface {
		GetByID(string) (types.Rule, bool)
	}
	if r, ok := registry.(getRuleByID); ok {
		return r.GetByID(ruleID)
	}
	return nil, false
}

func (f *Fixer) backupFile(filePath string) error {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	if err := os.MkdirAll(f.backupDir, 0755); err != nil {
		return err
	}

	backupPath := filepath.Join(
		f.backupDir,
		fmt.Sprintf("%s.%s.bak",
			filepath.Base(filePath),
			time.Now().Format("20060102150405"),
		),
	)

	return os.WriteFile(backupPath, content, 0644)
}

func (f *Fixer) applyFix(finding types.Finding) error {
	content, err := os.ReadFile(finding.File)
	if err != nil {
		return err
	}

	lines := strings.Split(string(content), "\n")
	if finding.Line < 1 || finding.Line > len(lines) {
		return fmt.Errorf("invalid line number: %d", finding.Line)
	}

	ruleID := finding.RuleID

	switch ruleID {
	case "RESOURCE_TAGS":
		return f.fixMissingTags(finding, lines)
	case "VARIABLE_DESCRIPTION":
		return f.fixVariableDescription(finding, lines)
	case "OUTPUT_DESCRIPTION":
		return f.fixOutputDescription(finding, lines)
	default:
		return fmt.Errorf("no auto-fix available for rule: %s", ruleID)
	}
}

func (f *Fixer) fixMissingTags(finding types.Finding, lines []string) error {
	lineIdx := finding.Line - 1
	for i := lineIdx; i < len(lines); i++ {
		if strings.Contains(lines[i], "}") {
			indent := getIndent(lines[lineIdx])
			tagBlock := fmt.Sprintf(
				"%s  tags = {\n%s    Environment = \"dev\"\n%s    Owner       = \"team\"\n%s  }\n",
				indent, indent, indent, indent,
			)
			lines[i] = tagBlock + lines[i]

			content := strings.Join(lines, "\n")
			return os.WriteFile(finding.File, []byte(content), 0644)
		}
	}
	return fmt.Errorf("could not find end of resource block")
}

func (f *Fixer) fixVariableDescription(finding types.Finding, lines []string) error {
	lineIdx := finding.Line - 1
	for i := lineIdx; i < len(lines) && i < lineIdx+10; i++ {
		if strings.Contains(lines[i], "}") {
			indent := getIndent(lines[lineIdx])
			descriptionLine := fmt.Sprintf("%s  description = \"Variable description\"\n", indent)
			lines[i] = descriptionLine + lines[i]

			content := strings.Join(lines, "\n")
			return os.WriteFile(finding.File, []byte(content), 0644)
		}
	}
	return fmt.Errorf("could not find end of variable block")
}

func (f *Fixer) fixOutputDescription(finding types.Finding, lines []string) error {
	lineIdx := finding.Line - 1
	for i := lineIdx; i < len(lines) && i < lineIdx+10; i++ {
		if strings.Contains(lines[i], "}") {
			indent := getIndent(lines[lineIdx])
			descriptionLine := fmt.Sprintf("%s  description = \"Output description\"\n", indent)
			lines[i] = descriptionLine + lines[i]

			content := strings.Join(lines, "\n")
			return os.WriteFile(finding.File, []byte(content), 0644)
		}
	}
	return fmt.Errorf("could not find end of output block")
}

func getIndent(line string) string {
	for i, c := range line {
		if c != ' ' && c != '\t' {
			return line[:i]
		}
	}
	return ""
}
