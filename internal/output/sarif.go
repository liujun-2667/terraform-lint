package output

import (
	"encoding/json"
	"fmt"

	"github.com/terraform-lint/terraform-lint/internal/types"
)

type SARIFFormatter struct{}

func NewSARIFFormatter() *SARIFFormatter {
	return &SARIFFormatter{}
}

func (f *SARIFFormatter) Name() string {
	return "sarif"
}

func (f *SARIFFormatter) Format(result *types.ScanResult) (string, error) {
	sarif := SARIF{
		Version: "2.1.0",
		Schema:  "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
		Runs: []Run{
			{
				Tool: Tool{
					Driver: Driver{
						Name:           "terraform-lint",
						Version:        "1.0.0",
						InformationURI: "https://github.com/terraform-lint/terraform-lint",
						Rules:          []Rule{},
					},
				},
				Results: []SARIFResult{},
			},
		},
	}

	ruleMap := make(map[string]int)
	ruleIndex := 0

	for _, finding := range result.Findings {
		if _, exists := ruleMap[finding.RuleID]; !exists {
			ruleMap[finding.RuleID] = ruleIndex
			sarif.Runs[0].Tool.Driver.Rules = append(sarif.Runs[0].Tool.Driver.Rules, Rule{
				ID: finding.RuleID,
				FullDescription: Message{
					Text: finding.Description,
				},
				DefaultConfiguration: DefaultConfiguration{
					Level: severityToSARIFLevel(finding.Severity),
				},
			})
			ruleIndex++
		}

		sarifResult := SARIFResult{
			RuleID:  finding.RuleID,
			RuleIndex: ruleMap[finding.RuleID],
			Level:   severityToSARIFLevel(finding.Severity),
			Message: Message{
				Text: finding.Message,
			},
			Locations: []Location{
				{
					PhysicalLocation: PhysicalLocation{
						ArtifactLocation: ArtifactLocation{
							URI: toFileURI(finding.File),
						},
						Region: Region{
							StartLine:   finding.Line,
							StartColumn: finding.Column,
							EndLine:     finding.Line,
						},
					},
				},
			},
		}

		if finding.FixSuggestion != "" {
			sarifResult.Suppressions = []Suppression{
				{
					Kind: "external",
				},
			}
		}

		sarif.Runs[0].Results = append(sarif.Runs[0].Results, sarifResult)
	}

	data, err := json.MarshalIndent(sarif, "", "  ")
	if err != nil {
		return "", err
	}

	return string(data) + "\n", nil
}

func severityToSARIFLevel(severity types.Severity) string {
	switch severity {
	case types.SeverityError:
		return "error"
	case types.SeverityWarning:
		return "warning"
	case types.SeverityInfo:
		return "note"
	default:
		return "none"
	}
}

func toFileURI(path string) string {
	return fmt.Sprintf("file://%s", path)
}

type SARIF struct {
	Version string `json:"version"`
	Schema  string `json:"$schema"`
	Runs    []Run  `json:"runs"`
}

type Run struct {
	Tool    Tool          `json:"tool"`
	Results []SARIFResult `json:"results"`
}

type Tool struct {
	Driver Driver `json:"driver"`
}

type Driver struct {
	Name           string `json:"name"`
	Version        string `json:"version"`
	InformationURI string `json:"informationUri"`
	Rules          []Rule `json:"rules"`
}

type Rule struct {
	ID               string               `json:"id"`
	FullDescription  Message              `json:"fullDescription"`
	DefaultConfiguration DefaultConfiguration `json:"defaultConfiguration"`
}

type DefaultConfiguration struct {
	Level string `json:"level"`
}

type SARIFResult struct {
	RuleID       string        `json:"ruleId"`
	RuleIndex    int           `json:"ruleIndex"`
	Level        string        `json:"level"`
	Message      Message       `json:"message"`
	Locations    []Location    `json:"locations"`
	Suppressions []Suppression `json:"suppressions,omitempty"`
}

type Message struct {
	Text string `json:"text"`
}

type Location struct {
	PhysicalLocation PhysicalLocation `json:"physicalLocation"`
}

type PhysicalLocation struct {
	ArtifactLocation ArtifactLocation `json:"artifactLocation"`
	Region           Region           `json:"region"`
}

type ArtifactLocation struct {
	URI string `json:"uri"`
}

type Region struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn"`
	EndLine     int `json:"endLine"`
}

type Suppression struct {
	Kind string `json:"kind"`
}
