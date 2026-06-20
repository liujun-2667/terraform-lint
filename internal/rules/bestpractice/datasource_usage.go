package bestpractice

import (
	"github.com/terraform-lint/terraform-lint/internal/rules"
	"github.com/terraform-lint/terraform-lint/internal/types"
)

type DataSourceUsageRule struct {
	rules.BaseRule
}

func NewDataSourceUsageRule() *DataSourceUsageRule {
	return &DataSourceUsageRule{
		BaseRule: rules.NewBaseRule(
			"DATASOURCE_USAGE",
			"Hardcoded Resource Reference",
			"Consider using data sources instead of hardcoded resource IDs",
			types.SeverityInfo,
			types.CategoryBestPractice,
		),
	}
}

func (r *DataSourceUsageRule) Check(ctx *types.RuleContext) []types.Finding {
	var findings []types.Finding

	return findings
}
