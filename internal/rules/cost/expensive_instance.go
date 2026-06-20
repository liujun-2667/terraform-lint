package cost

import (
	"strings"

	"github.com/terraform-lint/terraform-lint/internal/ast"
	
	"github.com/terraform-lint/terraform-lint/internal/types"
)

var expensiveInstanceFamilies = map[string]bool{
	"p2":    true,
	"p3":    true,
	"p4":    true,
	"g4dn":  true,
	"g5":    true,
	"inf1":  true,
	"trn1":  true,
	"x1":    true,
	"x1e":   true,
	"x2iezn": true,
	"u-12tb1": true,
	"u-18tb1": true,
	"u-24tb1": true,
	"z1d":   true,
	"i3":    true,
	"i3en":  true,
	"i4i":   true,
	"r5b":   true,
}

type ExpensiveInstanceTypeRule struct {
	types.BaseRule
}

func NewExpensiveInstanceTypeRule() *ExpensiveInstanceTypeRule {
	return &ExpensiveInstanceTypeRule{
		BaseRule: types.NewBaseRule(
			"EXPENSIVE_INSTANCE_TYPE",
			"Expensive Instance Type Detected",
			"Consider if a cheaper instance type would be sufficient for your workload",
			types.SeverityInfo,
			types.CategoryCost,
		),
	}
}

func (r *ExpensiveInstanceTypeRule) Check(ctx *types.RuleContext) []types.Finding {
	var findings []types.Finding

	for _, resource := range ctx.Resources {
		if resource.Type != "aws_instance" {
			continue
		}

		if r.ShouldIgnore(ctx, resource.Range.Start.Line) {
			continue
		}

		typeAttr, ok := resource.Attributes["instance_type"]
		if !ok {
			continue
		}

		val, _, err := ast.GetAttributeValue(typeAttr, nil)
		if err != nil {
			continue
		}

		if instanceType, ok := val.(string); ok {
			parts := strings.Split(instanceType, ".")
			if len(parts) >= 2 {
				family := parts[0]
				if expensiveInstanceFamilies[family] {
					findings = append(findings, r.NewFinding(
						ctx,
						resource.Range.Start.Line,
						resource.Range.Start.Column,
						"Instance type '"+instanceType+"' is in an expensive family ('"+family+"'), consider reviewing if necessary",
						resource.Type,
						resource.Name,
					))
				}
			}
		}
	}

	return findings
}
