package security

import (
	
	"github.com/terraform-lint/terraform-lint/internal/types"
)

type ElasticsearchVPCRule struct {
	types.BaseRule
}

func NewElasticsearchVPCRule() *ElasticsearchVPCRule {
	return &ElasticsearchVPCRule{
		BaseRule: types.NewBaseRule(
			"ELASTICSEARCH_VPC",
			"Elasticsearch Domain Not in VPC",
			"Elasticsearch domains should be deployed within a VPC",
			types.SeverityWarning,
			types.CategorySecurity,
		),
	}
}

func (r *ElasticsearchVPCRule) Check(ctx *types.RuleContext) []types.Finding {
	var findings []types.Finding

	for _, resource := range ctx.Resources {
		if resource.Type != "aws_elasticsearch_domain" && resource.Type != "aws_opensearch_domain" {
			continue
		}

		if r.ShouldIgnore(ctx, resource.Range.Start.Line) {
			continue
		}

		hasVPC := false
		for _, block := range resource.Blocks {
			if block.Type == "vpc_options" {
				hasVPC = true
				break
			}
		}

		if !hasVPC {
			findings = append(findings, r.NewFinding(
				ctx,
				resource.Range.Start.Line,
				resource.Range.Start.Column,
				"Elasticsearch/OpenSearch domain is not deployed within a VPC",
				resource.Type,
				resource.Name,
			))
		}
	}

	return findings
}
