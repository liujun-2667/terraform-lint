package bestpractice

import (
	"fmt"
	"strings"

	"github.com/terraform-lint/terraform-lint/internal/ast"
	"github.com/terraform-lint/terraform-lint/internal/types"
)

type ResourceTagsRule struct {
	types.BaseRule
}

var taggableResources = map[string]bool{
	"aws_instance":          true,
	"aws_s3_bucket":       true,
	"aws_vpc":             true,
	"aws_subnet":          true,
	"aws_security_group":  true,
	"aws_ebs_volume":    true,
	"aws_eip":             true,
	"aws_nat_gateway":     true,
	"aws_internet_gateway": true,
	"aws_rds_cluster":     true,
	"aws_db_instance":     true,
	"aws_elasticache_cluster": true,
	"aws_elasticache_replication_group": true,
	"aws_dynamodb_table": true,
	"aws_lambda_function":  true,
	"aws_sqs_queue":       true,
	"aws_sns_topic":       true,
	"aws_kms_key":         true,
	"aws_cloudwatch_metric_alarm": true,
	"aws_cloudwatch_log_group": true,
	"aws_autoscaling_group": true,
	"aws_launch_configuration": true,
	"aws_launch_template": true,
	"aws_ecs_cluster":     true,
	"aws_ecs_service":     true,
	"aws_ecr_repository": true,
	"aws_eks_cluster":      true,
	"aws_redshift_cluster": true,
	"aws_elasticsearch_domain": true,
	"aws_opensearch_domain": true,
	"aws_api_gateway_rest_api": true,
	"aws_api_gateway_stage": true,
	"aws_cloudfront_distribution": true,
	"aws_route53_zone":      true,
	"aws_acm_certificate":   true,
	"aws_iam_role":         true,
	"aws_iam_policy":       true,
}

func NewResourceTagsRule() *ResourceTagsRule {
	return &ResourceTagsRule{
		BaseRule: types.NewBaseRule(
			"RESOURCE_TAGS",
			"Missing Required Tags",
			"Resources should have required tags (Environment, Owner by default)",
			types.SeverityInfo,
			types.CategoryBestPractice,
		),
	}
}

func (r *ResourceTagsRule) Check(ctx *types.RuleContext) []types.Finding {
	var findings []types.Finding

	requiredTagsParam := r.GetParam("required_tags", []string{"Environment", "Owner"})
	requiredTags, ok := requiredTagsParam.([]string)
	if !ok {
		requiredTags = []string{"Environment", "Owner"}
	}

	for _, resource := range ctx.Resources {
		if !taggableResources[resource.Type] {
			continue
		}

		if r.ShouldIgnore(ctx, resource.Range.Start.Line) {
			continue
		}

		resourceTags := make(map[string]bool)

		if tagsAttr, ok := resource.Attributes["tags"]; ok {
			val, _, err := ast.GetAttributeValue(tagsAttr, nil)
			if err == nil {
				if tagsMap, ok := val.(map[string]interface{}); ok {
					for k := range tagsMap {
						resourceTags[k] = true
					}
				}
			}
		}

		for _, block := range resource.Blocks {
			if block.Type == "tags" {
				for k := range block.Attributes {
					resourceTags[k] = true
				}
			}
		}

		for _, tag := range requiredTags {
			if !resourceTags[tag] {
				findings = append(findings, r.NewFinding(
					ctx,
					resource.Range.Start.Line,
					resource.Range.Start.Column,
					"Resource is missing required tag: "+tag,
					resource.Type,
					resource.Name,
				))
			}
		}
	}

	return findings
}

func (r *ResourceTagsRule) CanFix() bool {
	return true
}

func (r *ResourceTagsRule) GenerateFix(ctx *types.RuleContext, finding *types.Finding) ([]types.FixInstruction, error) {
	requiredTagsParam := r.GetParam("required_tags", []string{"Environment", "Owner"})
	requiredTags, ok := requiredTagsParam.([]string)
	if !ok {
		requiredTags = []string{"Environment", "Owner"}
	}

	defaultTagValues := map[string]string{
		"Environment": "dev",
		"Owner":       "team",
	}

	for _, res := range ctx.Resources {
		if res.Type != finding.ResourceType || res.Name != finding.ResourceName {
			continue
		}

		tagsLine := 0
		hasTagsAttr := false
		hasTagsMap := false

		if tagsAttr, ok := res.Attributes["tags"]; ok {
			hasTagsAttr = true
			tagsLine = tagsAttr.Range.Start.Line
			val, _, err := ast.GetAttributeValue(tagsAttr, nil)
			if err == nil {
				if _, ok := val.(map[string]interface{}); ok {
					hasTagsMap = true
				}
			}
		}

		if !hasTagsMap {
			for _, block := range res.Blocks {
				if block.Type == "tags" {
					hasTagsAttr = true
					hasTagsMap = true
					tagsLine = block.Range.Start.Line
					break
				}
			}
		}

		if !hasTagsAttr {
			var tagsLines []string
			tagsLines = append(tagsLines, "tags = {")
			for _, tag := range requiredTags {
				val := "changeme"
				if v, ok := defaultTagValues[tag]; ok {
					val = v
				}
				tagsLines = append(tagsLines, fmt.Sprintf("  %s = \"%s\"", tag, val))
			}
			tagsLines = append(tagsLines, "}")

			return []types.FixInstruction{
				{
					Action:       types.FixActionAppendAttribute,
					ResourceType: finding.ResourceType,
					ResourceName: finding.ResourceName,
					Attribute:    "tags",
					Content:      strings.Join(tagsLines, "\n"),
					Line:         finding.Line,
					Column:       finding.Column,
				},
			}, nil
		}

		if !hasTagsMap {
			return nil, nil
		}

		missingTag := strings.TrimPrefix(finding.Message, "Resource is missing required tag: ")
		if missingTag == finding.Message {
			return nil, nil
		}

		val := "changeme"
		if v, ok := defaultTagValues[missingTag]; ok {
			val = v
		}

		return []types.FixInstruction{
			{
				Action:       types.FixActionAppendAttribute,
				ResourceType: finding.ResourceType,
				ResourceName: finding.ResourceName,
				Attribute:    missingTag,
				Content:      fmt.Sprintf("%s = \"%s\"", missingTag, val),
				Line:         tagsLine,
				Column:       finding.Column,
			},
		}, nil
	}

	return nil, nil
}
