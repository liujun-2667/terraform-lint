package cost

import (
	"github.com/terraform-lint/terraform-lint/internal/ast"
	
	"github.com/terraform-lint/terraform-lint/internal/types"
)

type UnusedLoadBalancerRule struct {
	types.BaseRule
}

func NewUnusedLoadBalancerRule() *UnusedLoadBalancerRule {
	return &UnusedLoadBalancerRule{
		BaseRule: types.NewBaseRule(
			"UNUSED_LOAD_BALANCER",
			"Potential Unused Load Balancer",
			"Load balancers with no targets incur unnecessary costs",
			types.SeverityInfo,
			types.CategoryCost,
		),
	}
}

func (r *UnusedLoadBalancerRule) Check(ctx *types.RuleContext) []types.Finding {
	var findings []types.Finding

	lbTargets := make(map[string]int)

	for _, resource := range ctx.Resources {
		if resource.Type == "aws_lb_target_group_attachment" {
			if tgAttr, ok := resource.Attributes["target_group_arn"]; ok {
				val, _, err := ast.GetAttributeValue(tgAttr, nil)
				if err == nil {
					if tgArn, ok := val.(string); ok {
						lbTargets[tgArn]++
					}
				}
			}
		}
	}

	for _, resource := range ctx.Resources {
		if resource.Type != "aws_lb_target_group" {
			continue
		}

		if r.ShouldIgnore(ctx, resource.Range.Start.Line) {
			continue
		}

		address := resource.Address
		if lbTargets[address] == 0 {
			findings = append(findings, r.NewFinding(
				ctx,
				resource.Range.Start.Line,
				resource.Range.Start.Column,
				"Target group '"+resource.Name+"' appears to have no targets attached",
				resource.Type,
				resource.Name,
			))
		}
	}

	return findings
}
