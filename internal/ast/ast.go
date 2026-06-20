package ast

import (
	"fmt"

	"github.com/hashicorp/hcl/v2"
	"github.com/hashicorp/hcl/v2/hclsyntax"
	"github.com/terraform-lint/terraform-lint/internal/types"
	"github.com/zclconf/go-cty/cty"
)

func ParseFile(path string, content []byte) (*types.ParsedFile, hcl.Diagnostics) {
	file, diags := hclsyntax.ParseConfig(content, path, hcl.InitialPos)
	if diags.HasErrors() {
		return &types.ParsedFile{
			Path:    path,
			Content: content,
		}, diags
	}

	parsed := &types.ParsedFile{
		Path:    path,
		Content: content,
		Body:    file.Body,
	}

	return parsed, nil
}

func ExtractResources(file *types.ParsedFile) []types.Resource {
	var resources []types.Resource

	bodyContent, _, diags := file.Body.PartialContent(&hcl.BodySchema{
		Blocks: []hcl.BlockHeaderSchema{
			{Type: "resource", LabelNames: []string{"type", "name"}},
		},
	})
	if diags.HasErrors() {
		return resources
	}

	for _, block := range bodyContent.Blocks {
		if block.Type == "resource" {
			resType := block.Labels[0]
			resName := block.Labels[1]
			attrs := make(map[string]hcl.Expression)

			syntaxBody, ok := block.Body.(*hclsyntax.Body)
			if ok {
				for name, attr := range syntaxBody.Attributes {
					attrs[name] = attr.Expr
				}
			}

			resource := types.Resource{
				Type:       resType,
				Name:       resName,
				Config:     block.Body,
				Address:    fmt.Sprintf("%s.%s", resType, resName),
				Range:      block.DefRange,
				Attributes: attrs,
				Blocks:     convertHCLBlocks(block.Body.(*hclsyntax.Body).Blocks),
			}
			resources = append(resources, resource)
		}
	}

	return resources
}

func ExtractVariables(file *types.ParsedFile) map[string]types.Variable {
	variables := make(map[string]types.Variable)

	bodyContent, _, diags := file.Body.PartialContent(&hcl.BodySchema{
		Blocks: []hcl.BlockHeaderSchema{
			{Type: "variable", LabelNames: []string{"name"}},
		},
	})
	if diags.HasErrors() {
		return variables
	}

	for _, block := range bodyContent.Blocks {
		if block.Type == "variable" {
			name := block.Labels[0]
			variable := types.Variable{
				Name:  name,
				Range: block.DefRange,
			}

			attrContent, _, _ := block.Body.PartialContent(&hcl.BodySchema{
				Attributes: []hcl.AttributeSchema{
					{Name: "description"},
					{Name: "type"},
					{Name: "default"},
					{Name: "sensitive"},
				},
			})

			if attr, ok := attrContent.Attributes["description"]; ok {
				val, _ := attr.Expr.Value(nil)
				if val.Type() == cty.String {
					variable.Description = val.AsString()
				}
			}

			if attr, ok := attrContent.Attributes["type"]; ok {
				variable.Type = attr.Expr.Range().String()
			}

			if attr, ok := attrContent.Attributes["default"]; ok {
				val, _ := attr.Expr.Value(nil)
				if !val.IsNull() {
					variable.Default = ctyValueToInterface(val)
				}
			}

			if attr, ok := attrContent.Attributes["sensitive"]; ok {
				val, _ := attr.Expr.Value(nil)
				if val.Type() == cty.Bool {
					variable.Sensitive = val.True()
				}
			}

			variables[name] = variable
		}
	}

	return variables
}

func ExtractOutputs(file *types.ParsedFile) []types.Output {
	var outputs []types.Output

	bodyContent, _, diags := file.Body.PartialContent(&hcl.BodySchema{
		Blocks: []hcl.BlockHeaderSchema{
			{Type: "output", LabelNames: []string{"name"}},
		},
	})
	if diags.HasErrors() {
		return outputs
	}

	for _, block := range bodyContent.Blocks {
		if block.Type == "output" {
			output := types.Output{
				Name:  block.Labels[0],
				Range: block.DefRange,
			}

			attrContent, _, _ := block.Body.PartialContent(&hcl.BodySchema{
				Attributes: []hcl.AttributeSchema{
					{Name: "description"},
					{Name: "value"},
					{Name: "sensitive"},
				},
			})

			if attr, ok := attrContent.Attributes["description"]; ok {
				val, _ := attr.Expr.Value(nil)
				if val.Type() == cty.String {
					output.Description = val.AsString()
				}
			}

			if attr, ok := attrContent.Attributes["value"]; ok {
				output.Value = attr.Expr
			}

			if attr, ok := attrContent.Attributes["sensitive"]; ok {
				val, _ := attr.Expr.Value(nil)
				if val.Type() == cty.Bool {
					output.Sensitive = val.True()
				}
			}

			outputs = append(outputs, output)
		}
	}

	return outputs
}

func ExtractModuleCalls(file *types.ParsedFile) []types.ModuleCall {
	var modules []types.ModuleCall

	bodyContent, _, diags := file.Body.PartialContent(&hcl.BodySchema{
		Blocks: []hcl.BlockHeaderSchema{
			{Type: "module", LabelNames: []string{"name"}},
		},
	})
	if diags.HasErrors() {
		return modules
	}

	for _, block := range bodyContent.Blocks {
		if block.Type == "module" {
			mod := types.ModuleCall{
				Name:   block.Labels[0],
				Config: block.Body,
				Range:  block.DefRange,
			}

			attrContent, _, _ := block.Body.PartialContent(&hcl.BodySchema{
				Attributes: []hcl.AttributeSchema{
					{Name: "source"},
					{Name: "version"},
				},
			})

			if attr, ok := attrContent.Attributes["source"]; ok {
				val, _ := attr.Expr.Value(nil)
				if val.Type() == cty.String {
					mod.Source = val.AsString()
				}
			}

			if attr, ok := attrContent.Attributes["version"]; ok {
				val, _ := attr.Expr.Value(nil)
				if val.Type() == cty.String {
					mod.Version = val.AsString()
				}
			}

			modules = append(modules, mod)
		}
	}

	return modules
}

func ExtractProviderConfigs(file *types.ParsedFile) []types.ProviderConfig {
	var providers []types.ProviderConfig

	bodyContent, _, diags := file.Body.PartialContent(&hcl.BodySchema{
		Blocks: []hcl.BlockHeaderSchema{
			{Type: "provider", LabelNames: []string{"name"}},
		},
	})
	if diags.HasErrors() {
		return providers
	}

	for _, block := range bodyContent.Blocks {
		if block.Type == "provider" {
			provider := types.ProviderConfig{
				Name:   block.Labels[0],
				Config: block.Body,
				Range:  block.DefRange,
			}
			providers = append(providers, provider)
		}
	}

	return providers
}

func ExtractBackendConfig(file *types.ParsedFile) *types.BackendConfig {
	terraformContent, _, diags := file.Body.PartialContent(&hcl.BodySchema{
		Blocks: []hcl.BlockHeaderSchema{
			{Type: "terraform"},
		},
	})
	if diags.HasErrors() {
		return nil
	}

	for _, tfBlock := range terraformContent.Blocks {
		backendContent, _, _ := tfBlock.Body.PartialContent(&hcl.BodySchema{
			Blocks: []hcl.BlockHeaderSchema{
				{Type: "backend", LabelNames: []string{"type"}},
			},
		})

		for _, block := range backendContent.Blocks {
			if block.Type == "backend" {
				return &types.BackendConfig{
					Type:   block.Labels[0],
					Config: block.Body,
					Range:  block.DefRange,
				}
			}
		}
	}

	return nil
}

func ExtractRequiredProviders(file *types.ParsedFile) map[string]string {
	providers := make(map[string]string)

	terraformContent, _, diags := file.Body.PartialContent(&hcl.BodySchema{
		Blocks: []hcl.BlockHeaderSchema{
			{Type: "terraform"},
		},
	})
	if diags.HasErrors() {
		return providers
	}

	for _, tfBlock := range terraformContent.Blocks {
		reqContent, _, _ := tfBlock.Body.PartialContent(&hcl.BodySchema{
			Blocks: []hcl.BlockHeaderSchema{
				{Type: "required_providers"},
			},
		})

		for _, block := range reqContent.Blocks {
			syntaxBody, ok := block.Body.(*hclsyntax.Body)
			if !ok {
				continue
			}

			for name, attr := range syntaxBody.Attributes {
				val, _ := attr.Expr.Value(nil)
				if val.Type().IsObjectType() {
					if versionVal := val.GetAttr("version"); !versionVal.IsNull() && versionVal.Type() == cty.String {
						providers[name] = versionVal.AsString()
					}
				}
			}
		}
	}

	return providers
}

func ExtractLocals(file *types.ParsedFile) map[string]interface{} {
	locals := make(map[string]interface{})

	bodyContent, _, diags := file.Body.PartialContent(&hcl.BodySchema{
		Blocks: []hcl.BlockHeaderSchema{
			{Type: "locals"},
		},
	})
	if diags.HasErrors() {
		return locals
	}

	for _, block := range bodyContent.Blocks {
		syntaxBody, ok := block.Body.(*hclsyntax.Body)
		if !ok {
			continue
		}

		for name, attr := range syntaxBody.Attributes {
			val, _ := attr.Expr.Value(nil)
			if !val.IsNull() {
				locals[name] = ctyValueToInterface(val)
			}
		}
	}

	return locals
}

func ctyValueToInterface(val cty.Value) interface{} {
	if val.IsNull() {
		return nil
	}

	switch val.Type() {
	case cty.String:
		return val.AsString()
	case cty.Number:
		f, _ := val.AsBigFloat().Float64()
		return f
	case cty.Bool:
		return val.True()
	case cty.List(cty.String):
		result := make([]string, 0)
		it := val.ElementIterator()
		for it.Next() {
			_, v := it.Element()
			result = append(result, v.AsString())
		}
		return result
	default:
		return val.GoString()
	}
}

func GetAttributeValue(attr hcl.Expression, ctx *hcl.EvalContext) (interface{}, bool, error) {
	if attr == nil {
		return nil, false, nil
	}

	val, diags := attr.Value(ctx)
	if diags.HasErrors() {
		return nil, true, fmt.Errorf("dynamic value cannot be determined statically")
	}

	if val.IsNull() {
		return nil, false, nil
	}

	return ctyValueToInterface(val), false, nil
}

func GetNestedBlock(body hcl.Body, blockType string, labels []string) *hcl.Block {
	content, _, _ := body.PartialContent(&hcl.BodySchema{
		Blocks: []hcl.BlockHeaderSchema{
			{Type: blockType, LabelNames: labels},
		},
	})

	for _, block := range content.Blocks {
		if block.Type == blockType {
			match := true
			for i, label := range labels {
				if i < len(block.Labels) && block.Labels[i] != label {
					match = false
					break
				}
			}
			if match {
				return block
			}
		}
	}

	return nil
}

func convertHCLBlocks(hclBlocks []*hclsyntax.Block) []*types.Block {
	blocks := make([]*types.Block, 0, len(hclBlocks))
	for _, hb := range hclBlocks {
		attrs := make(map[string]hcl.Expression)
		for name, attr := range hb.Body.Attributes {
			attrs[name] = attr.Expr
		}

		block := &types.Block{
			Type:       hb.Type,
			Labels:     hb.Labels,
			Attributes: attrs,
			Blocks:     convertHCLBlocks(hb.Body.Blocks),
			Range:      hb.Range(),
		}
		blocks = append(blocks, block)
	}
	return blocks
}
