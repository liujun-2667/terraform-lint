package security

import (
	"github.com/terraform-lint/terraform-lint/internal/ast"
	
	"github.com/terraform-lint/terraform-lint/internal/types"
)

type ALBHTTPSRule struct {
	types.BaseRule
}

func NewALBHTTPSRule() *ALBHTTPSRule {
	return &ALBHTTPSRule{
		BaseRule: types.NewBaseRule(
			"ALB_HTTPS",
			"ALB Listener Uses HTTP Instead of HTTPS",
			"Load balancer listeners should use HTTPS for secure communication",
			types.SeverityWarning,
			types.CategorySecurity,
		),
	}
}

func (r *ALBHTTPSRule) Check(ctx *types.RuleContext) []types.Finding {
	var findings []types.Finding

	for _, resource := range ctx.Resources {
		if resource.Type != "aws_lb_listener" && resource.Type != "aws_alb_listener" && resource.Type != "aws_elb" {
			continue
		}

		if r.ShouldIgnore(ctx, resource.Range.Start.Line) {
			continue
		}

		if resource.Type == "aws_lb_listener" || resource.Type == "aws_alb_listener" {
			portAttr, ok := resource.Attributes["port"]
			if !ok {
				continue
			}

			val, _, err := ast.GetAttributeValue(portAttr, nil)
			if err != nil {
				continue
			}

			if port, ok := val.(float64); ok {
				if port == 80 {
					protocolAttr, ok := resource.Attributes["protocol"]
					if ok {
						protoVal, _, err := ast.GetAttributeValue(protocolAttr, nil)
						if err == nil {
							if proto, ok := protoVal.(string); ok && proto == "HTTP" {
								findings = append(findings, r.NewFinding(
									ctx,
									resource.Range.Start.Line,
									resource.Range.Start.Column,
									"Load balancer listener uses HTTP instead of HTTPS",
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

	return findings
}
