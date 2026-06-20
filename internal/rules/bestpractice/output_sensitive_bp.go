package bestpractice

import (
	"strings"

	"github.com/terraform-lint/terraform-lint/internal/rules"
	"github.com/terraform-lint/terraform-lint/internal/types"
)

type OutputSensitiveRule struct {
	rules.BaseRule
}

func NewOutputSensitiveRule() *OutputSensitiveRule {
	return &OutputSensitiveRule{
		BaseRule: rules.NewBaseRule(
			"OUTPUT_SENSITIVE_BP",
			"Output May Contain Sensitive Data",
			"Outputs that may contain sensitive data should be marked as sensitive",
			types.SeverityInfo,
			types.CategoryBestPractice,
		),
	}
}

func (r *OutputSensitiveRule) Check(ctx *types.RuleContext) []types.Finding {
	var findings []types.Finding

	sensitiveNames := map[string]bool{
		"password":   true,
		"secret":     true,
		"token":      true,
		"key":        true,
		"credential": true,
		"cert":       true,
		"private":    true,
	}

	for _, output := range ctx.Outputs {
		if r.ShouldIgnore(ctx, output.Range.Start.Line) {
			continue
		}

		if output.Sensitive {
			continue
		}

		nameLower := strings.ToLower(output.Name)
		for sensitive := range sensitiveNames {
			if strings.Contains(nameLower, sensitive) {
				findings = append(findings, r.NewFinding(
					ctx,
					output.Range.Start.Line,
					output.Range.Start.Column,
					"Output '"+output.Name+"' may contain sensitive data, consider marking as sensitive",
					"output",
					output.Name,
				))
				break
			}
		}
	}

	return findings
}
