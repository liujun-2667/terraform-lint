package fixer

import (
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/terraform-lint/terraform-lint/internal/types"
)

type Fixer struct {
}

func NewFixer() *Fixer {
	return &Fixer{}
}

type instructionWithFinding struct {
	instruction types.FixInstruction
	finding     types.Finding
}

func (f *Fixer) Fix(
	findings []types.Finding,
	ruleRegistry interface{},
	getRuleContext func(string) *types.RuleContext,
) (*types.FixSummary, error) {
	summary := &types.FixSummary{}

	fileFindings := groupFindingsByFile(findings)

	for filePath, fileFindingsList := range fileFindings {
		fileSummary, err := f.fixFile(filePath, fileFindingsList, ruleRegistry, getRuleContext)
		if err != nil {
			return summary, fmt.Errorf("fixing file %s: %w", filePath, err)
		}
		if fileSummary.FindingsFixed > 0 {
			summary.FilesFixed++
			summary.TotalFixed += fileSummary.FindingsFixed
		}
		if fileSummary.RolledBack {
			summary.FilesRolledBack++
		}
		summary.FileSummaries = append(summary.FileSummaries, *fileSummary)
	}

	return summary, nil
}

func groupFindingsByFile(findings []types.Finding) map[string][]types.Finding {
	fileMap := make(map[string][]types.Finding)
	for _, finding := range findings {
		fileMap[finding.File] = append(fileMap[finding.File], finding)
	}
	return fileMap
}

func (f *Fixer) fixFile(
	filePath string,
	findings []types.Finding,
	ruleRegistry interface{},
	getRuleContext func(string) *types.RuleContext,
) (*types.FileFixSummary, error) {
	summary := &types.FileFixSummary{
		File: filePath,
	}

	backupPath, err := f.backupFile(filePath)
	if err != nil {
		return summary, fmt.Errorf("backup file: %w", err)
	}
	summary.BackupPath = backupPath

	content, err := os.ReadFile(filePath)
	if err != nil {
		return summary, fmt.Errorf("read file: %w", err)
	}
	lines := strings.Split(string(content), "\n")

	var fixableInstructions []instructionWithFinding
	ctx := getRuleContext(filePath)
	seenKeys := make(map[string]bool)

	for _, finding := range findings {
		rule, ok := f.getRuleByID(ruleRegistry, finding.RuleID)
		if !ok || !rule.CanFix() {
			continue
		}

		instructions, err := rule.GenerateFix(ctx, &finding)
		if err != nil || len(instructions) == 0 {
			continue
		}

		for _, inst := range instructions {
			key := f.getInstructionKey(inst, finding)
			if key != "" && seenKeys[key] {
				continue
			}
			if key != "" {
				seenKeys[key] = true
			}

			fixableInstructions = append(fixableInstructions, instructionWithFinding{
				instruction: inst,
				finding:     finding,
			})
		}
	}

	if len(fixableInstructions) == 0 {
		os.Remove(backupPath)
		return summary, nil
	}

	sort.Slice(fixableInstructions, func(i, j int) bool {
		return fixableInstructions[i].instruction.Line > fixableInstructions[j].instruction.Line
	})

	for _, iwf := range fixableInstructions {
		result := f.applyInstruction(&lines, iwf.instruction)
		result.File = filePath
		result.RuleID = iwf.finding.RuleID
		summary.Results = append(summary.Results, result)
		if result.Applied {
			summary.FindingsFixed++
		}
	}

	if summary.FindingsFixed > 0 {
		newContent := strings.Join(lines, "\n")
		if err := os.WriteFile(filePath, []byte(newContent), 0644); err != nil {
			return summary, fmt.Errorf("write fixed file: %w", err)
		}
	} else {
		os.Remove(backupPath)
	}

	return summary, nil
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

func (f *Fixer) backupFile(filePath string) (string, error) {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return "", err
	}

	backupPath := filePath + ".bak"
	if err := os.WriteFile(backupPath, content, 0644); err != nil {
		return "", err
	}

	return backupPath, nil
}

func (f *Fixer) RestoreBackup(backupPath string) error {
	originalPath := strings.TrimSuffix(backupPath, ".bak")
	content, err := os.ReadFile(backupPath)
	if err != nil {
		return err
	}
	if err := os.WriteFile(originalPath, content, 0644); err != nil {
		return err
	}
	return os.Remove(backupPath)
}

func detectIndentStyle(lines []string) (string, int) {
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}
		if line[0] == '\t' {
			return "\t", 1
		}
		if line[0] == ' ' {
			indentCount := 0
			for _, c := range line {
				if c == ' ' {
					indentCount++
				} else {
					break
				}
			}
			if indentCount >= 2 {
				if indentCount%2 == 0 {
					return "  ", 2
				}
				return strings.Repeat(" ", indentCount), indentCount
			}
		}
	}
	return "  ", 2
}

func (f *Fixer) applyInstruction(lines *[]string, inst types.FixInstruction) types.FixResult {
	result := types.FixResult{
		Action: inst.Action,
	}

	switch inst.Action {
	case types.FixActionAppendAttribute:
		return f.applyAppendAttribute(lines, inst)
	case types.FixActionReplaceValue:
		return f.applyReplaceValue(lines, inst)
	case types.FixActionAppendBlock:
		return f.applyAppendBlock(lines, inst)
	case types.FixActionDeleteAttribute:
		return f.applyDeleteAttribute(lines, inst)
	default:
		result.Error = fmt.Sprintf("unknown fix action: %s", inst.Action)
		return result
	}
}

func findBlockEnd(lines []string, startLine int) int {
	if startLine < 1 || startLine > len(lines) {
		return -1
	}

	braceCount := 0
	foundOpening := false

	for i := startLine - 1; i < len(lines); i++ {
		line := lines[i]
		inString := false
		for _, c := range line {
			if c == '"' {
				inString = !inString
				continue
			}
			if inString {
				continue
			}
			if c == '{' {
				braceCount++
				foundOpening = true
			} else if c == '}' {
				braceCount--
				if foundOpening && braceCount == 0 {
					return i + 1
				}
			}
		}
	}

	return -1
}

func getLineIndent(line string) string {
	for i, c := range line {
		if c != ' ' && c != '\t' {
			return line[:i]
		}
	}
	return ""
}

func getBlockInnerIndent(lines []string, startLine int) string {
	if startLine < 1 || startLine > len(lines) {
		return "  "
	}
	outerIndent := getLineIndent(lines[startLine-1])
	innerIndent := outerIndent + "  "

	blockEnd := findBlockEnd(lines, startLine)
	if blockEnd == -1 {
		return innerIndent
	}

	for i := startLine; i < blockEnd-1 && i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, "//") {
			continue
		}
		curIndent := getLineIndent(lines[i])
		if len(curIndent) > len(outerIndent) {
			return curIndent
		}
	}

	return innerIndent
}

func (f *Fixer) applyAppendAttribute(lines *[]string, inst types.FixInstruction) types.FixResult {
	result := types.FixResult{
		Action: types.FixActionAppendAttribute,
	}

	blockEndLine := findBlockEnd(*lines, inst.Line)
	if blockEndLine == -1 {
		result.Error = "could not find end of block"
		return result
	}

	attrIndent := getBlockInnerIndent(*lines, inst.Line)

	contentLines := strings.Split(inst.Content, "\n")
	var indentedLines []string
	for i, cl := range contentLines {
		if i == 0 || cl == "" {
			indentedLines = append(indentedLines, attrIndent+cl)
		} else {
			indentedLines = append(indentedLines, attrIndent+cl)
		}
	}

	result.FixedLine = strings.Join(indentedLines, "\n")

	if blockEndLine-1 > 0 {
		prevLine := (*lines)[blockEndLine-2]
		if strings.TrimSpace(prevLine) != "" {
			result.OriginalLine = prevLine
		}
	}

	insertIdx := blockEndLine - 1
	newLines := make([]string, 0, len(*lines)+len(indentedLines))
	newLines = append(newLines, (*lines)[:insertIdx]...)
	newLines = append(newLines, indentedLines...)
	newLines = append(newLines, (*lines)[insertIdx:]...)
	*lines = newLines

	result.Applied = true
	return result
}

func (f *Fixer) applyReplaceValue(lines *[]string, inst types.FixInstruction) types.FixResult {
	result := types.FixResult{
		Action: types.FixActionReplaceValue,
	}

	if inst.Line < 1 || inst.Line > len(*lines) {
		result.Error = "invalid line number"
		return result
	}

	lineIdx := inst.Line - 1
	originalLine := (*lines)[lineIdx]
	result.OriginalLine = originalLine

	attrName := inst.Attribute
	if attrName == "" {
		result.Error = "attribute name required for replace value"
		return result
	}

	idx := findAttributeOnLine(originalLine, attrName)
	if idx == -1 {
		result.Error = fmt.Sprintf("attribute %s not found on line", attrName)
		return result
	}

	eqIdx := strings.Index(originalLine[idx:], "=")
	if eqIdx == -1 {
		result.Error = "could not find = in attribute line"
		return result
	}

	valueStart := idx + eqIdx + 1
	for valueStart < len(originalLine) && (originalLine[valueStart] == ' ' || originalLine[valueStart] == '\t') {
		valueStart++
	}

	valueEnd := findValueEnd(originalLine, valueStart)

	newLine := originalLine[:valueStart] + inst.NewValue + originalLine[valueEnd:]
	result.FixedLine = newLine
	(*lines)[lineIdx] = newLine
	result.Applied = true

	return result
}

func findAttributeOnLine(line, attrName string) int {
	trimmed := strings.TrimLeft(line, " \t")
	if strings.HasPrefix(trimmed, attrName) {
		after := trimmed[len(attrName):]
		if len(after) > 0 && (after[0] == ' ' || after[0] == '\t' || after[0] == '=') {
			return len(line) - len(trimmed)
		}
	}
	return -1
}

func findValueEnd(line string, start int) int {
	if start >= len(line) {
		return start
	}

	firstChar := line[start]
	if firstChar == '"' {
		i := start + 1
		for i < len(line) {
			if line[i] == '\\' && i+1 < len(line) {
				i += 2
				continue
			}
			if line[i] == '"' {
				return i + 1
			}
			i++
		}
		return len(line)
	}

	if firstChar == '[' {
		bracketCount := 1
		i := start + 1
		inString := false
		for i < len(line) && bracketCount > 0 {
			c := line[i]
			if c == '"' {
				inString = !inString
			} else if !inString {
				if c == '[' {
					bracketCount++
				} else if c == ']' {
					bracketCount--
				}
			}
			i++
		}
		return i
	}

	if firstChar == '{' {
		braceCount := 1
		i := start + 1
		inString := false
		for i < len(line) && braceCount > 0 {
			c := line[i]
			if c == '"' {
				inString = !inString
			} else if !inString {
				if c == '{' {
					braceCount++
				} else if c == '}' {
					braceCount--
				}
			}
			i++
		}
		return i
	}

	i := start
	for i < len(line) {
		c := line[i]
		if c == '#' || c == ' ' || c == '\t' {
			break
		}
		i++
	}
	return i
}

func (f *Fixer) applyAppendBlock(lines *[]string, inst types.FixInstruction) types.FixResult {
	result := types.FixResult{
		Action: types.FixActionAppendBlock,
	}

	blockEndLine := findBlockEnd(*lines, inst.Line)
	if blockEndLine == -1 {
		result.Error = "could not find end of block"
		return result
	}

	blockIndent := getBlockInnerIndent(*lines, inst.Line)

	blockContentLines := strings.Split(inst.Content, "\n")
	var indentedBlockLines []string
	for _, bl := range blockContentLines {
		if bl == "" {
			indentedBlockLines = append(indentedBlockLines, "")
		} else {
			indentedBlockLines = append(indentedBlockLines, blockIndent+bl)
		}
	}

	result.FixedLine = strings.Join(indentedBlockLines, "\n")

	if blockEndLine-1 > 0 {
		prevLine := (*lines)[blockEndLine-2]
		if strings.TrimSpace(prevLine) != "" {
			result.OriginalLine = prevLine
		}
	}

	insertIdx := blockEndLine - 1
	newLines := make([]string, 0, len(*lines)+len(indentedBlockLines))
	newLines = append(newLines, (*lines)[:insertIdx]...)
	newLines = append(newLines, indentedBlockLines...)
	newLines = append(newLines, (*lines)[insertIdx:]...)
	*lines = newLines

	result.Applied = true
	return result
}

func (f *Fixer) applyDeleteAttribute(lines *[]string, inst types.FixInstruction) types.FixResult {
	result := types.FixResult{
		Action: types.FixActionDeleteAttribute,
	}

	if inst.Line < 1 || inst.Line > len(*lines) {
		result.Error = "invalid line number"
		return result
	}

	lineIdx := inst.Line - 1
	originalLine := (*lines)[lineIdx]
	result.OriginalLine = originalLine

	newLines := make([]string, 0, len(*lines)-1)
	newLines = append(newLines, (*lines)[:lineIdx]...)
	newLines = append(newLines, (*lines)[lineIdx+1:]...)
	*lines = newLines

	result.Applied = true
	return result
}

func (f *Fixer) getInstructionKey(inst types.FixInstruction, finding types.Finding) string {
	switch inst.Action {
	case types.FixActionAppendAttribute:
		return fmt.Sprintf("append_attr:%s:%s:%s", finding.ResourceType, finding.ResourceName, inst.Attribute)
	case types.FixActionAppendBlock:
		return fmt.Sprintf("append_block:%s:%s:%s", finding.ResourceType, finding.ResourceName, inst.BlockType)
	case types.FixActionReplaceValue:
		return fmt.Sprintf("replace:%s:%s:%s:%d", finding.ResourceType, finding.ResourceName, inst.Attribute, inst.Line)
	case types.FixActionDeleteAttribute:
		return fmt.Sprintf("delete:%s:%s:%s:%d", finding.ResourceType, finding.ResourceName, inst.Attribute, inst.Line)
	default:
		return ""
	}
}

func (f *Fixer) ApplyFixInstructions(filePath string, instructions []types.FixInstruction) error {
	content, err := os.ReadFile(filePath)
	if err != nil {
		return err
	}

	lines := strings.Split(string(content), "\n")

	sort.Slice(instructions, func(i, j int) bool {
		return instructions[i].Line > instructions[j].Line
	})

	for _, inst := range instructions {
		f.applyInstruction(&lines, inst)
	}

	newContent := strings.Join(lines, "\n")
	return os.WriteFile(filePath, []byte(newContent), 0644)
}

func GenerateDiff(original, modified string) string {
	origLines := strings.Split(original, "\n")
	modLines := strings.Split(modified, "\n")

	var diff strings.Builder
	maxLines := len(origLines)
	if len(modLines) > maxLines {
		maxLines = len(modLines)
	}

	for i := 0; i < maxLines; i++ {
		if i < len(origLines) && i < len(modLines) {
			if origLines[i] != modLines[i] {
				diff.WriteString(fmt.Sprintf("-%d: %s\n", i+1, origLines[i]))
				diff.WriteString(fmt.Sprintf("+%d: %s\n", i+1, modLines[i]))
			}
		} else if i < len(origLines) {
			diff.WriteString(fmt.Sprintf("-%d: %s\n", i+1, origLines[i]))
		} else if i < len(modLines) {
			diff.WriteString(fmt.Sprintf("+%d: %s\n", i+1, modLines[i]))
		}
	}

	return diff.String()
}
