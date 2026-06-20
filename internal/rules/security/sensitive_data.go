package security

import (
	"fmt"
	"strings"

	"github.com/terraform-lint/terraform-lint/internal/types"
	"github.com/terraform-lint/terraform-lint/internal/utils"
)

type SensitiveDataRule struct {
	types.BaseRule
}

func NewSensitiveDataRule() *SensitiveDataRule {
	return &SensitiveDataRule{
		BaseRule: types.NewBaseRule(
			"SENSITIVE_DATA",
			"Potential Sensitive Data in Plaintext",
			"Variables should not contain sensitive data like AWS keys or passwords in default values",
			types.SeverityError,
			types.CategorySecurity,
		),
	}
}

func (r *SensitiveDataRule) Check(ctx *types.RuleContext) []types.Finding {
	var findings []types.Finding

	for _, variable := range ctx.Variables {
		if r.ShouldIgnore(ctx, variable.Range.Start.Line) {
			continue
		}

		if variable.Default != nil {
			defaultStr := fmt.Sprintf("%v", variable.Default)
			if utils.LooksLikeSecret(defaultStr) {
				findings = append(findings, r.NewFinding(
					ctx,
					variable.Range.Start.Line,
					variable.Range.Start.Column,
					"Variable default value contains potential sensitive data",
					"variable",
					variable.Name,
				))
			}
		}
	}

	return findings
}

func (r *SensitiveDataRule) CanFix() bool {
	return true
}

func (r *SensitiveDataRule) GenerateFix(ctx *types.RuleContext, finding *types.Finding) ([]types.FixInstruction, error) {
	targetVar, ok := ctx.Variables[finding.ResourceName]
	if !ok {
		return nil, fmt.Errorf("variable not found: %s", finding.ResourceName)
	}

	if targetVar.Default == nil {
		return nil, nil
	}

	lines := strings.Split(string(ctx.File.Content), "\n")
	startLine := targetVar.Range.Start.Line
	endLine := targetVar.Range.End.Line

	defaultLine := -1
	for i := startLine - 1; i < endLine && i < len(lines); i++ {
		trimmed := strings.TrimSpace(lines[i])
		if strings.HasPrefix(trimmed, "default") {
			defaultLine = i + 1
			break
		}
	}

	if defaultLine == -1 {
		return nil, fmt.Errorf("default attribute not found for variable: %s", finding.ResourceName)
	}

	return []types.FixInstruction{
		{
			Action:       types.FixActionDeleteAttribute,
			ResourceType: "variable",
			ResourceName: finding.ResourceName,
			Attribute:    "default",
			Line:         defaultLine,
		},
	}, nil
}
