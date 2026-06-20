// rule:id=CUSTOM_001
// rule:name=Custom Tag Validation
// rule:severity=warning
// rule:category=best_practice
// rule:description=Validates that resources have custom tags

package main

import (
	"github.com/terraform-lint/terraform-lint/internal/ast"
	"github.com/terraform-lint/terraform-lint/internal/types"
)

type CustomTagValidationRule struct {
	types.BaseRule
}

var customTaggableResources = map[string]bool{
	"aws_instance":       true,
	"aws_s3_bucket":      true,
	"aws_vpc":            true,
	"aws_security_group": true,
}

func NewRule() types.Rule {
	return &CustomTagValidationRule{
		BaseRule: types.NewBaseRule(
			"CUSTOM_001",
			"Custom Tag Validation",
			"Validates that resources have required custom tags",
			types.SeverityWarning,
			types.CategoryBestPractice,
		),
	}
}

func (r *CustomTagValidationRule) Check(ctx *types.RuleContext) []types.Finding {
	var findings []types.Finding

	requiredTagsParam := r.GetParam("required_tags", []string{"Project", "Environment"})
	requiredTags, ok := requiredTagsParam.([]string)
	if !ok {
		requiredTags = []string{"Project", "Environment"}
	}

	for _, resource := range ctx.Resources {
		if !customTaggableResources[resource.Type] {
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

		for _, tag := range requiredTags {
			if !resourceTags[tag] {
				findings = append(findings, r.NewFinding(
					ctx,
					resource.Range.Start.Line,
					resource.Range.Start.Column,
					"Resource is missing required custom tag: "+tag,
					resource.Type,
					resource.Name,
				))
			}
		}
	}

	return findings
}

func (r *CustomTagValidationRule) CanFix() bool {
	return false
}
