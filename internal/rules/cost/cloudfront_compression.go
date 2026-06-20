package cost

import (
	"github.com/terraform-lint/terraform-lint/internal/ast"
	"github.com/terraform-lint/terraform-lint/internal/rules"
	"github.com/terraform-lint/terraform-lint/internal/types"
)

type CloudFrontCompressionRule struct {
	rules.BaseRule
}

func NewCloudFrontCompressionRule() *CloudFrontCompressionRule {
	return &CloudFrontCompressionRule{
		BaseRule: rules.NewBaseRule(
			"CLOUDFRONT_COMPRESSION",
			"CloudFront Compression Not Enabled",
			"Consider enabling automatic compression on CloudFront distribution to reduce bandwidth costs",
			types.SeverityInfo,
			types.CategoryCost,
		),
	}
}

func (r *CloudFrontCompressionRule) Check(ctx *types.RuleContext) []types.Finding {
	var findings []types.Finding

	for _, resource := range ctx.Resources {
		if resource.Type != "aws_cloudfront_distribution" {
			continue
		}

		if r.ShouldIgnore(ctx, resource.Range.Start.Line) {
			continue
		}

		compressAttr, ok := resource.Attributes["default_cache_behavior"]
		if !ok {
			defaultCacheBlock := findBlock(resource.Blocks, "default_cache_behavior")
			if defaultCacheBlock == nil {
				continue
			}
			compressAttr, ok = defaultCacheBlock.Attributes["compress"]
			if !ok {
				findings = append(findings, r.NewFinding(
					ctx,
					defaultCacheBlock.Range.Start.Line,
					defaultCacheBlock.Range.Start.Column,
					"CloudFront distribution default cache behavior does not have compress enabled - enable automatic compression to reduce bandwidth costs",
					resource.Type,
					resource.Name,
				))
				continue
			}
		}

		if compressAttr != nil {
			val, _, err := ast.GetAttributeValue(compressAttr, nil)
			if err == nil {
				if compress, ok := val.(bool); ok && !compress {
					findings = append(findings, r.NewFinding(
						ctx,
						compressAttr.Range().Start.Line,
						compressAttr.Range().Start.Column,
						"CloudFront distribution compression is explicitly disabled - consider enabling it to reduce bandwidth costs",
						resource.Type,
						resource.Name,
					))
				}
			}
		}
	}

	return findings
}

func findBlock(blocks []*types.Block, blockType string) *types.Block {
	for _, block := range blocks {
		if block.Type == blockType {
			return block
		}
	}
	return nil
}
