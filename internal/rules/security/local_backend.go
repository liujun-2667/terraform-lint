package security

import (
	"github.com/terraform-lint/terraform-lint/internal/rules"
	"github.com/terraform-lint/terraform-lint/internal/types"
)

type LocalBackendRule struct {
	rules.BaseRule
}

func NewLocalBackendRule() *LocalBackendRule {
	return &LocalBackendRule{
		BaseRule: rules.NewBaseRule(
			"LOCAL_BACKEND",
			"Local Backend Configuration",
			"State files should be stored remotely (not locally) to avoid exposing sensitive data",
			types.SeverityWarning,
			types.CategorySecurity,
		),
	}
}

func (r *LocalBackendRule) Check(ctx *types.RuleContext) []types.Finding {
	var findings []types.Finding

	if ctx.Backend == nil {
		return findings
	}

	if r.ShouldIgnore(ctx, ctx.Backend.Range.Start.Line) {
		return findings
	}

	if ctx.Backend.Type == "local" {
		findings = append(findings, r.NewFinding(
			ctx,
			ctx.Backend.Range.Start.Line,
			ctx.Backend.Range.Start.Column,
			"Using local backend - state files may contain sensitive data and should not be committed to version control",
			"terraform",
			"backend",
		))
	}

	return findings
}
