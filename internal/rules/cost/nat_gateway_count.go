package cost

import (
	"strconv"

	
	"github.com/terraform-lint/terraform-lint/internal/types"
)

type NATGatewayCountRule struct {
	types.BaseRule
}

func NewNATGatewayCountRule() *NATGatewayCountRule {
	return &NATGatewayCountRule{
		BaseRule: types.NewBaseRule(
			"NAT_GATEWAY_COUNT",
			"High Number of NAT Gateways",
			"Consider if all NAT gateways are necessary - they incur hourly costs",
			types.SeverityInfo,
			types.CategoryCost,
		),
	}
}

func (r *NATGatewayCountRule) Check(ctx *types.RuleContext) []types.Finding {
	var findings []types.Finding

	natCount := 0
	for _, resource := range ctx.Resources {
		if resource.Type == "aws_nat_gateway" {
			natCount++
		}
	}

	thresholdParam := r.GetParam("threshold", 2)
	threshold, ok := thresholdParam.(int)
	if !ok {
		threshold = 2
	}

	if natCount > threshold {
		for _, resource := range ctx.Resources {
			if resource.Type == "aws_nat_gateway" {
				if r.ShouldIgnore(ctx, resource.Range.Start.Line) {
					continue
				}
				findings = append(findings, r.NewFinding(
					ctx,
					resource.Range.Start.Line,
					resource.Range.Start.Column,
					"High number of NAT gateways ("+strconv.Itoa(natCount)+" total), consider optimizing",
					resource.Type,
					resource.Name,
				))
			}
		}
	}

	return findings
}
