package cost

import (
	"github.com/terraform-lint/terraform-lint/internal/ast"
	
	"github.com/terraform-lint/terraform-lint/internal/types"
)

type S3IntelligentTieringRule struct {
	types.BaseRule
}

func NewS3IntelligentTieringRule() *S3IntelligentTieringRule {
	return &S3IntelligentTieringRule{
		BaseRule: types.NewBaseRule(
			"S3_INTELLIGENT_TIERING",
			"S3 Intelligent Tiering Not Configured",
			"Consider enabling S3 Intelligent Tiering for cost optimization on unpredictable access patterns",
			types.SeverityInfo,
			types.CategoryCost,
		),
	}
}

func (r *S3IntelligentTieringRule) Check(ctx *types.RuleContext) []types.Finding {
	var findings []types.Finding

	for _, resource := range ctx.Resources {
		if resource.Type != "aws_s3_bucket" {
			continue
		}

		if r.ShouldIgnore(ctx, resource.Range.Start.Line) {
			continue
		}

		hasLifecycleConfiguration := false
		hasIntelligentTiering := false

		for _, block := range resource.Blocks {
			if block.Type == "lifecycle_rule" {
				hasLifecycleConfiguration = true
				for _, innerBlock := range block.Blocks {
					if innerBlock.Type == "transition" {
						storageAttr, ok := innerBlock.Attributes["storage_class"]
						if ok {
							val, _, err := ast.GetAttributeValue(storageAttr, nil)
							if err == nil {
								if sc, ok := val.(string); ok && sc == "INTELLIGENT_TIERING" {
									hasIntelligentTiering = true
									break
								}
							}
						}
					}
				}
			}
		}

		if hasLifecycleConfiguration && !hasIntelligentTiering {
			findings = append(findings, r.NewFinding(
				ctx,
				resource.Range.Start.Line,
				resource.Range.Start.Column,
				"S3 bucket has lifecycle rules but no Intelligent Tiering transition configured - consider adding it for cost optimization",
				resource.Type,
				resource.Name,
			))
		}
	}

	return findings
}
