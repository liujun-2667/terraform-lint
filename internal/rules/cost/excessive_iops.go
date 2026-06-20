package cost

import (
	"strconv"

	"github.com/terraform-lint/terraform-lint/internal/ast"
	"github.com/terraform-lint/terraform-lint/internal/rules"
	"github.com/terraform-lint/terraform-lint/internal/types"
)

type ExcessiveProvisionedIOPSRule struct {
	rules.BaseRule
}

func NewExcessiveProvisionedIOPSRule() *ExcessiveProvisionedIOPSRule {
	return &ExcessiveProvisionedIOPSRule{
		BaseRule: rules.NewBaseRule(
			"EXCESSIVE_PROVISIONED_IOPS",
			"Excessive Provisioned IOPS",
			"Consider if provisioned IOPS are necessary or if gp3 would be more cost-effective",
			types.SeverityInfo,
			types.CategoryCost,
		),
	}
}

func (r *ExcessiveProvisionedIOPSRule) Check(ctx *types.RuleContext) []types.Finding {
	var findings []types.Finding

	thresholdParam := r.GetParam("threshold", 5000)
	threshold, ok := thresholdParam.(int)
	if !ok {
		threshold = 5000
	}

	for _, resource := range ctx.Resources {
		if resource.Type != "aws_ebs_volume" && resource.Type != "aws_db_instance" {
			continue
		}

		if r.ShouldIgnore(ctx, resource.Range.Start.Line) {
			continue
		}

		if resource.Type == "aws_ebs_volume" {
			typeAttr, ok := resource.Attributes["type"]
			if ok {
				val, _, err := ast.GetAttributeValue(typeAttr, nil)
				if err == nil {
					if volType, ok := val.(string); ok && (volType == "io1" || volType == "io2") {
						iopsAttr, ok := resource.Attributes["iops"]
						if ok {
							iopsVal, _, err := ast.GetAttributeValue(iopsAttr, nil)
							if err == nil {
								if iops, ok := iopsVal.(float64); ok && int(iops) > threshold {
									findings = append(findings, r.NewFinding(
										ctx,
										resource.Range.Start.Line,
										resource.Range.Start.Column,
										"EBS volume has high provisioned IOPS ("+strconv.Itoa(int(iops))+"), consider gp3 for better cost-effectiveness",
										resource.Type,
										resource.Name,
									))
								}
							}
						}
					}
				}
			}
		}
	}

	return findings
}
