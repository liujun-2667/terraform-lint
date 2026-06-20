package security

import (
	
	"github.com/terraform-lint/terraform-lint/internal/types"
)

type InstanceNoVPCRule struct {
	types.BaseRule
}

func NewInstanceNoVPCRule() *InstanceNoVPCRule {
	return &InstanceNoVPCRule{
		BaseRule: types.NewBaseRule(
			"INSTANCE_NO_VPC",
			"EC2 Instance Not in VPC",
			"EC2 instances should be launched in a VPC, not in EC2-Classic",
			types.SeverityWarning,
			types.CategorySecurity,
		),
	}
}

func (r *InstanceNoVPCRule) Check(ctx *types.RuleContext) []types.Finding {
	var findings []types.Finding

	for _, resource := range ctx.Resources {
		if resource.Type != "aws_instance" {
			continue
		}

		if r.ShouldIgnore(ctx, resource.Range.Start.Line) {
			continue
		}

		_, hasSubnet := resource.Attributes["subnet_id"]
		_, hasVPC := resource.Attributes["vpc_security_group_ids"]

		if !hasSubnet && !hasVPC {
			findings = append(findings, r.NewFinding(
				ctx,
				resource.Range.Start.Line,
				resource.Range.Start.Column,
				"EC2 instance is not associated with a VPC (uses EC2-Classic)",
				resource.Type,
				resource.Name,
			))
		}
	}

	return findings
}
