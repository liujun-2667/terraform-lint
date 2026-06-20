package bestpractice

import (
	"regexp"

	
	"github.com/terraform-lint/terraform-lint/internal/types"
	"github.com/terraform-lint/terraform-lint/internal/utils"
)

type NamingConventionRule struct {
	types.BaseRule
}

func NewNamingConventionRule() *NamingConventionRule {
	return &NamingConventionRule{
		BaseRule: types.NewBaseRule(
			"NAMING_CONVENTION",
			"Naming Convention Violation",
			"Resource and variable names should follow snake_case naming convention",
			types.SeverityInfo,
			types.CategoryBestPractice,
		),
	}
}

func (r *NamingConventionRule) Check(ctx *types.RuleContext) []types.Finding {
	var findings []types.Finding
	namingRegex := r.GetParam("naming_regex", "")
	var regex *regexp.Regexp
	if namingRegex != "" {
		regex, _ = regexp.Compile(namingRegex.(string))
	}

	for _, resource := range ctx.Resources {
		if r.ShouldIgnore(ctx, resource.Range.Start.Line) {
			continue
		}

		name := resource.Name
		isValid := false
		if regex != nil {
			isValid = regex.MatchString(name)
		} else {
			isValid = utils.IsSnakeCase(name)
		}

		if !isValid {
			findings = append(findings, r.NewFinding(
				ctx,
				resource.Range.Start.Line,
				resource.Range.Start.Column,
				"Resource name '"+name+"' does not follow snake_case naming convention",
				resource.Type,
				resource.Name,
			))
		}
	}

	for _, variable := range ctx.Variables {
		if r.ShouldIgnore(ctx, variable.Range.Start.Line) {
			continue
		}

		name := variable.Name
		isValid := false
		if regex != nil {
			isValid = regex.MatchString(name)
		} else {
			isValid = utils.IsSnakeCase(name)
		}

		if !isValid {
			findings = append(findings, r.NewFinding(
				ctx,
				variable.Range.Start.Line,
				variable.Range.Start.Column,
				"Variable name '"+name+"' does not follow snake_case naming convention",
				"variable",
				variable.Name,
			))
		}
	}

	for _, output := range ctx.Outputs {
		if r.ShouldIgnore(ctx, output.Range.Start.Line) {
			continue
		}

		name := output.Name
		isValid := false
		if regex != nil {
			isValid = regex.MatchString(name)
		} else {
			isValid = utils.IsSnakeCase(name)
		}

		if !isValid {
			findings = append(findings, r.NewFinding(
				ctx,
				output.Range.Start.Line,
				output.Range.Start.Column,
				"Output name '"+name+"' does not follow snake_case naming convention",
				"output",
				output.Name,
			))
		}
	}

	return findings
}
