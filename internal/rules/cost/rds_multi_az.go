package cost

import (
	"strings"

	"github.com/terraform-lint/terraform-lint/internal/ast"
	"github.com/terraform-lint/terraform-lint/internal/rules"
	"github.com/terraform-lint/terraform-lint/internal/types"
)

var smallInstanceClasses = map[string]bool{
	"db.t2.micro":    true,
	"db.t2.small":    true,
	"db.t3.micro":    true,
	"db.t3.small":    true,
	"db.t4g.micro":   true,
	"db.t4g.small":   true,
	"db.t3.medium":   true,
	"db.t4g.medium":  true,
}

type RDSMultiAZSmallRule struct {
	rules.BaseRule
}

func NewRDSMultiAZSmallRule() *RDSMultiAZSmallRule {
	return &RDSMultiAZSmallRule{
		BaseRule: rules.NewBaseRule(
			"RDS_MULTI_AZ_SMALL",
			"Multi-AZ for Small RDS Instance",
			"Consider if Multi-AZ is necessary for small instance types",
			types.SeverityInfo,
			types.CategoryCost,
		),
	}
}

func (r *RDSMultiAZSmallRule) Check(ctx *types.RuleContext) []types.Finding {
	var findings []types.Finding

	for _, resource := range ctx.Resources {
		if resource.Type != "aws_db_instance" && resource.Type != "aws_rds_cluster_instance" {
			continue
		}

		if r.ShouldIgnore(ctx, resource.Range.Start.Line) {
			continue
		}

		multiAZAttr, ok := resource.Attributes["multi_az"]
		if !ok {
			continue
		}

		val, _, err := ast.GetAttributeValue(multiAZAttr, nil)
		if err != nil {
			continue
		}

		if multiAZ, ok := val.(bool); ok && multiAZ {
			classAttr, ok := resource.Attributes["instance_class"]
			if !ok {
				continue
			}

			classVal, _, err := ast.GetAttributeValue(classAttr, nil)
			if err != nil {
				continue
			}

			if instanceClass, ok := classVal.(string); ok {
				if smallInstanceClasses[instanceClass] {
					findings = append(findings, r.NewFinding(
						ctx,
						resource.Range.Start.Line,
						resource.Range.Start.Column,
						"Multi-AZ enabled for small instance type '"+instanceClass+"', consider if high availability is required",
						resource.Type,
						resource.Name,
					))
				}
			}
		}
	}

	return findings
}
