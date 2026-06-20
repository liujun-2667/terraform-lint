package cost

import (
	"strconv"

	"github.com/terraform-lint/terraform-lint/internal/ast"
	
	"github.com/terraform-lint/terraform-lint/internal/types"
)

type LargeVolumeSizeRule struct {
	types.BaseRule
}

func NewLargeVolumeSizeRule() *LargeVolumeSizeRule {
	return &LargeVolumeSizeRule{
		BaseRule: types.NewBaseRule(
			"LARGE_VOLUME_SIZE",
			"Large EBS Volume Size",
			"Consider if a smaller volume size would be sufficient",
			types.SeverityInfo,
			types.CategoryCost,
		),
	}
}

func (r *LargeVolumeSizeRule) Check(ctx *types.RuleContext) []types.Finding {
	var findings []types.Finding

	thresholdParam := r.GetParam("threshold", 1000)
	threshold, ok := thresholdParam.(int)
	if !ok {
		threshold = 1000
	}

	for _, resource := range ctx.Resources {
		if resource.Type != "aws_ebs_volume" {
			continue
		}

		if r.ShouldIgnore(ctx, resource.Range.Start.Line) {
			continue
		}

		sizeAttr, ok := resource.Attributes["size"]
		if !ok {
			continue
		}

		val, _, err := ast.GetAttributeValue(sizeAttr, nil)
		if err != nil {
			continue
		}

		if size, ok := val.(float64); ok && int(size) > threshold {
			findings = append(findings, r.NewFinding(
				ctx,
				resource.Range.Start.Line,
				resource.Range.Start.Column,
				"EBS volume size is "+strconv.Itoa(int(size))+" GB, consider if a smaller volume would suffice",
				resource.Type,
				resource.Name,
			))
		}
	}

	return findings
}
