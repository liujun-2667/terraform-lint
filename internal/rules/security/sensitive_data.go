package security

import (
	"fmt"
	"github.com/terraform-lint/terraform-lint/internal/rules"
	"github.com/terraform-lint/terraform-lint/internal/types"
	"github.com/terraform-lint/terraform-lint/internal/utils"
)

type SensitiveDataRule struct {
	rules.BaseRule
}

func NewSensitiveDataRule() *SensitiveDataRule {
	return &SensitiveDataRule{
		BaseRule: rules.NewBaseRule(
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
