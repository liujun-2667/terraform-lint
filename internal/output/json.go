package output

import (
	"encoding/json"

	"github.com/terraform-lint/terraform-lint/internal/types"
)

type JSONFormatter struct{}

func NewJSONFormatter() *JSONFormatter {
	return &JSONFormatter{}
}

func (f *JSONFormatter) Name() string {
	return "json"
}

func (f *JSONFormatter) Format(result *types.ScanResult) (string, error) {
	jsonResult := struct {
		FilesScanned int `json:"files_scanned"`
		Findings      []JSONFinding `json:"findings"`
		Summary       types.Summary `json:"summary"`
		Duration      string `json:"duration"`
	}{
		FilesScanned: result.FilesScanned,
		Summary:      result.Summary,
		Duration:      result.Duration,
	}

	for _, finding := range result.Findings {
		jsonFinding := JSONFinding{
			File:          finding.File,
			Line:          finding.Line,
			Column:        finding.Column,
			RuleID:       finding.RuleID,
			Severity:    string(finding.Severity),
			Category:     string(finding.Category),
			Message:        finding.Message,
			Description: finding.Description,
			FixSuggestion: finding.FixSuggestion,
			ResourceType:  finding.ResourceType,
			ResourceName:  finding.ResourceName,
		}
		jsonResult.Findings = append(jsonResult.Findings, jsonFinding)
	}

	data, err := json.MarshalIndent(jsonResult, "", "  ")
	if err != nil {
		return "", err
	}

	return string(data) + "\n", nil
}

type JSONFinding struct {
	File          string `json:"file"`
	Line          int    `json:"line"`
	Column        int    `json:"column"`
	RuleID        string `json:"rule_id"`
	Severity      string `json:"severity"`
	Category      string `json:"category"`
	Message       string `json:"message"`
	Description   string `json:"description,omitempty"`
	FixSuggestion string `json:"fix_suggestion,omitempty"`
	ResourceType  string `json:"resource_type,omitempty"`
	ResourceName  string `json:"resource_name,omitempty"`
	StartLine     int    `json:"start_line,omitempty"`
	EndLine       int    `json:"end_line,omitempty"`
}
