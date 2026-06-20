package security

import (
	"github.com/terraform-lint/terraform-lint/internal/ast"
	
	"github.com/terraform-lint/terraform-lint/internal/types"
	"github.com/terraform-lint/terraform-lint/internal/utils"
)

type OutputSensitiveRule struct {
	types.BaseRule
}

func NewOutputSensitiveRule() *OutputSensitiveRule {
	return &OutputSensitiveRule{
		BaseRule: types.NewBaseRule(
			"OUTPUT_SENSITIVE",
			"Output Exposes Sensitive Data",
			"Outputs that expose sensitive data should be marked as sensitive = true",
			types.SeverityError,
			types.CategorySecurity,
		),
	}
}

func (r *OutputSensitiveRule) Check(ctx *types.RuleContext) []types.Finding {
	var findings []types.Finding

	for _, output := range ctx.Outputs {
		if r.ShouldIgnore(ctx, output.Range.Start.Line) {
			continue
		}

		if output.Sensitive {
			continue
		}

		if output.Value != nil {
			val, _, err := ast.GetAttributeValue(output.Value, nil)
			if err != nil {
				continue
			}

			if valStr, ok := val.(string); ok {
				if utils.LooksLikeSecret(valStr) {
					findings = append(findings, r.NewFinding(
						ctx,
						output.Range.Start.Line,
						output.Range.Start.Column,
						"Output exposes potential sensitive data but is not marked as sensitive",
						"output",
						output.Name,
					))
				}
			}
		}
	}

	return findings
}
