package security

import (
	"github.com/terraform-lint/terraform-lint/internal/ast"
	
	"github.com/terraform-lint/terraform-lint/internal/types"
)

type KMSRotationRule struct {
	types.BaseRule
}

func NewKMSRotationRule() *KMSRotationRule {
	return &KMSRotationRule{
		BaseRule: types.NewBaseRule(
			"KMS_ROTATION",
			"KMS Key Rotation Not Enabled",
			"KMS keys should have automatic rotation enabled",
			types.SeverityInfo,
			types.CategorySecurity,
		),
	}
}

func (r *KMSRotationRule) Check(ctx *types.RuleContext) []types.Finding {
	var findings []types.Finding

	for _, resource := range ctx.Resources {
		if resource.Type != "aws_kms_key" {
			continue
		}

		if r.ShouldIgnore(ctx, resource.Range.Start.Line) {
			continue
		}

		rotationAttr, ok := resource.Attributes["enable_key_rotation"]
		if !ok {
			findings = append(findings, r.NewFinding(
				ctx,
				resource.Range.Start.Line,
				resource.Range.Start.Column,
				"KMS key does not have automatic rotation enabled",
				resource.Type,
				resource.Name,
			))
			continue
		}

		val, _, err := ast.GetAttributeValue(rotationAttr, nil)
		if err != nil {
			continue
		}

		if enabled, ok := val.(bool); ok && !enabled {
			findings = append(findings, r.NewFinding(
				ctx,
				resource.Range.Start.Line,
				resource.Range.Start.Column,
				"KMS key automatic rotation is disabled",
				resource.Type,
				resource.Name,
			))
		}
	}

	return findings
}
