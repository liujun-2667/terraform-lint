package cost

import (
	"strings"

	"github.com/terraform-lint/terraform-lint/internal/ast"
	"github.com/terraform-lint/terraform-lint/internal/rules"
	"github.com/terraform-lint/terraform-lint/internal/types"
)

type LongRunningInstanceRule struct {
	rules.BaseRule
}

func NewLongRunningInstanceRule() *LongRunningInstanceRule {
	return &LongRunningInstanceRule{
		BaseRule: rules.NewBaseRule(
			"LONG_RUNNING_INSTANCE",
			"Potential Long-Running Instance",
			"Consider using scheduled instances for non-production workloads",
			types.SeverityInfo,
			types.CategoryCost,
		),
	}
}

func (r *LongRunningInstanceRule) Check(ctx *types.RuleContext) []types.Finding {
	var findings []types.Finding

	for _, resource := range ctx.Resources {
		if resource.Type != "aws_instance" {
			continue
		}

		if r.ShouldIgnore(ctx, resource.Range.Start.Line) {
			continue
		}

		typeAttr, ok := resource.Attributes["instance_type"]
		if ok {
			val, _, err := ast.GetAttributeValue(typeAttr, nil)
			if err == nil {
				if instanceType, ok := val.(string); ok {
					if strings.HasPrefix(instanceType, "m5.") || strings.HasPrefix(instanceType, "c5.") || strings.HasPrefix(instanceType, "r5.") {
						largeSize := strings.HasSuffix(instanceType, ".xlarge") || strings.HasSuffix(instanceType, ".2xlarge") || strings.HasSuffix(instanceType, ".4xlarge")
						if largeSize {
							findings = append(findings, r.NewFinding(
								ctx,
								resource.Range.Start.Line,
								resource.Range.Start.Column,
								"Large instance type '"+instanceType+"' - consider scheduled instances or spot for non-production workloads",
								resource.Type,
								resource.Name,
							))
						}
					}
				}
			}
		}
	}

	return findings
}
