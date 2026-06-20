package security

import (
	"encoding/json"
	"strings"

	"github.com/hashicorp/hcl/v2"
	"github.com/terraform-lint/terraform-lint/internal/ast"
	"github.com/terraform-lint/terraform-lint/internal/rules"
	"github.com/terraform-lint/terraform-lint/internal/types"
)

type ECSPrivilegedRule struct {
	rules.BaseRule
}

func NewECSPrivilegedRule() *ECSPrivilegedRule {
	return &ECSPrivilegedRule{
		BaseRule: rules.NewBaseRule(
			"ECS_PRIVILEGED",
			"ECS Task Definition Has Privileged Mode",
			"ECS task definitions should not run in privileged mode",
			types.SeverityWarning,
			types.CategorySecurity,
		),
	}
}

func (r *ECSPrivilegedRule) Check(ctx *types.RuleContext) []types.Finding {
	var findings []types.Finding

	for _, resource := range ctx.Resources {
		if resource.Type != "aws_ecs_task_definition" {
			continue
		}

		if r.ShouldIgnore(ctx, resource.Range.Start.Line) {
			continue
		}

		for _, block := range resource.Blocks {
			if block.Type == "container_definitions" {
				continue
			}
		}

		defAttr, ok := resource.Attributes["container_definitions"]
		if !ok {
			continue
		}

		val, _, err := ast.GetAttributeValue(defAttr, nil)
		if err != nil {
			continue
		}

		if defStr, ok := val.(string); ok {
			if r.hasPrivilegedMode(defStr) {
				findings = append(findings, r.NewFinding(
					ctx,
					resource.Range.Start.Line,
					resource.Range.Start.Column,
					"ECS task definition has privileged mode enabled",
					resource.Type,
					resource.Name,
				))
			}
		}
	}

	return findings
}

func (r *ECSPrivilegedRule) hasPrivilegedMode(definition string) bool {
	var definitions []map[string]interface{}
	if err := json.Unmarshal([]byte(definition), &definitions); err != nil {
		return strings.Contains(definition, `"privileged":true`) || strings.Contains(definition, `"privileged": true`)
	}

	for _, def := range definitions {
		if privileged, ok := def["privileged"].(bool); ok && privileged {
			return true
		}
	}

	return false
}
