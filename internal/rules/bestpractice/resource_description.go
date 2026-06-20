package bestpractice

import (
	
	"github.com/terraform-lint/terraform-lint/internal/types"
)

type ResourceDescriptionRule struct {
	types.BaseRule
}

func NewResourceDescriptionRule() *ResourceDescriptionRule {
	return &ResourceDescriptionRule{
		BaseRule: types.NewBaseRule(
			"RESOURCE_DESCRIPTION",
			"Resource Missing Description",
			"Consider adding a description attribute to resources for better documentation",
			types.SeverityInfo,
			types.CategoryBestPractice,
		),
	}
}

func (r *ResourceDescriptionRule) Check(ctx *types.RuleContext) []types.Finding {
	var findings []types.Finding

	describableResources := map[string]bool{
		"aws_security_group":          true,
		"aws_db_parameter_group":      true,
		"aws_cloudwatch_metric_alarm": true,
		"aws_sns_topic":             true,
		"aws_sqs_queue":             true,
		"aws_vpc":                   true,
		"aws_subnet":                true,
	}

	for _, resource := range ctx.Resources {
		if !describableResources[resource.Type] {
			continue
		}

		if r.ShouldIgnore(ctx, resource.Range.Start.Line) {
			continue
		}

		if _, ok := resource.Attributes["description"]; !ok {
			findings = append(findings, r.NewFinding(
				ctx,
				resource.Range.Start.Line,
				resource.Range.Start.Column,
				"Resource '"+resource.Name+"' is missing a description attribute",
				resource.Type,
				resource.Name,
			))
		}
	}

	return findings
}
