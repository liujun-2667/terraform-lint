package rules

import (
	"github.com/terraform-lint/terraform-lint/internal/types"
)

type BaseRule struct {
	id          string
	name        string
	description string
	severity    types.Severity
	category    types.RuleCategory
	enabled     bool
	params      map[string]interface{}
}

func (r *BaseRule) ID() string {
	return r.id
}

func (r *BaseRule) Name() string {
	return r.name
}

func (r *BaseRule) Description() string {
	return r.description
}

func (r *BaseRule) Severity() types.Severity {
	return r.severity
}

func (r *BaseRule) Category() types.RuleCategory {
	return r.category
}

func (r *BaseRule) Enabled() bool {
	return r.enabled
}

func (r *BaseRule) SetEnabled(enabled bool) {
	r.enabled = enabled
}

func (r *BaseRule) SetSeverity(severity types.Severity) {
	r.severity = severity
}

func (r *BaseRule) SetParams(params map[string]interface{}) {
	r.params = params
}

func (r *BaseRule) GetParam(key string, defaultValue interface{}) interface{} {
	if r.params == nil {
		return defaultValue
	}
	if val, ok := r.params[key]; ok {
		return val
	}
	return defaultValue
}

func (r *BaseRule) CanFix() bool {
	return false
}

func (r *BaseRule) Fix(ctx *types.RuleContext, finding *types.Finding) error {
	return nil
}

func (r *BaseRule) NewFinding(
	ctx *types.RuleContext,
	line, column int,
	message string,
	resourceType, resourceName string,
) types.Finding {
	return types.Finding{
		File:         ctx.File.Path,
		Line:         line,
		Column:       column,
		RuleID:       r.id,
		Severity:     r.severity,
		Category:     r.category,
		Message:      message,
		Description:  r.description,
		ResourceType: resourceType,
		ResourceName: resourceName,
	}
}

func (r *BaseRule) ShouldIgnore(ctx *types.RuleContext, line int) bool {
	if rules, ok := ctx.IgnoreRules[line]; ok {
		for _, ruleID := range rules {
			if ruleID == r.id || ruleID == "all" {
				return true
			}
		}
	}
	return false
}

func NewBaseRule(
	id, name, description string,
	severity types.Severity,
	category types.RuleCategory,
) BaseRule {
	return BaseRule{
		id:          id,
		name:        name,
		description: description,
		severity:    severity,
		category:    category,
		enabled:     true,
	}
}
