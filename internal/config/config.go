package config

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/terraform-lint/terraform-lint/internal/types"
	"gopkg.in/yaml.v3"
)

type ConfigLoader struct {
	configFile string
	config     *types.Config
}

func NewConfigLoader() *ConfigLoader {
	return &ConfigLoader{}
}

func (cl *ConfigLoader) Load(configFile string) (*types.Config, error) {
	if configFile != "" {
		return cl.loadFromFile(configFile)
	}

	defaultFiles := []string{
		".tflint.yaml",
		".tflint.yml",
		"tflint.yaml",
		"tflint.yml",
		".tflint.json",
		"tflint.json",
	}

	cwd, err := os.Getwd()
	if err != nil {
		return cl.DefaultConfig(), nil
	}

	for _, file := range defaultFiles {
		fullPath := filepath.Join(cwd, file)
		if _, err := os.Stat(fullPath); err == nil {
			return cl.loadFromFile(fullPath)
		}
	}

	return cl.DefaultConfig(), nil
}

func (cl *ConfigLoader) loadFromFile(path string) (*types.Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	config := &types.Config{}
	ext := filepath.Ext(path)

	if ext == ".json" {
		if err := json.Unmarshal(data, config); err != nil {
			return nil, err
		}
	} else {
		if err := yaml.Unmarshal(data, config); err != nil {
			return nil, err
		}
	}

	cl.applyDefaults(config)
	cl.config = config
	return config, nil
}

func (cl *ConfigLoader) applyDefaults(config *types.Config) {
	if config.Global.RequiredTags == nil {
		config.Global.RequiredTags = []string{"Environment", "Owner"}
	}
	if config.Global.NamingRegex == "" {
		config.Global.NamingRegex = "^[a-z_][a-z0-9_]*$"
	}
	if config.Global.MaxConcurrency == 0 {
		config.Global.MaxConcurrency = 4
	}
	if config.IgnorePaths == nil {
		config.IgnorePaths = []string{".git/", "node_modules/", "vendor/", ".terraform/"}
	}
}

func (cl *ConfigLoader) DefaultConfig() *types.Config {
	config := &types.Config{
		Rules:       make(map[string]types.RuleConfig),
		IgnorePaths: []string{".git/", "node_modules/", "vendor/", ".terraform/"},
		Global: types.GlobalConfig{
			RequiredTags:   []string{"Environment", "Owner"},
			NamingRegex:    "^[a-z_][a-z0-9_]*$",
			MaxConcurrency: 4,
		},
	}
	return config
}

func GenerateDefaultConfig() map[string]interface{} {
	return map[string]interface{}{
		"ignore_paths": []string{".git/", "node_modules/", "vendor/", ".terraform/"},
		"global": map[string]interface{}{
			"required_tags":   []string{"Environment", "Owner"},
			"naming_regex":    "^[a-z_][a-z0-9_]*$",
			"max_concurrency": 4,
		},
		"rules": map[string]interface{}{
			"S3_BUCKET_ENCRYPTION": map[string]interface{}{
				"enabled":   true,
				"severity": "warning",
			},
			"S3_BUCKET_PUBLIC_ACL": map[string]interface{}{
				"enabled":   true,
				"severity": "error",
			},
			"SECURITY_GROUP_OPEN": map[string]interface{}{
				"enabled":   true,
				"severity": "error",
			},
			"DB_PUBLICLY_ACCESSIBLE": map[string]interface{}{
				"enabled":   true,
				"severity": "error",
			},
			"IAM_WILDCARD_ACTION": map[string]interface{}{
				"enabled":   true,
				"severity": "warning",
			},
			"RESOURCE_TAGS": map[string]interface{}{
				"enabled":   true,
				"severity": "info",
				"params": map[string]interface{}{
					"required_tags": []string{"Environment", "Owner"},
				},
			},
			"NAMING_CONVENTION": map[string]interface{}{
				"enabled":   true,
				"severity": "info",
			},
			"VARIABLE_DESCRIPTION": map[string]interface{}{
				"enabled":   true,
				"severity": "info",
			},
			"OUTPUT_DESCRIPTION": map[string]interface{}{
				"enabled":   true,
				"severity": "info",
			},
			"PROVIDER_VERSION": map[string]interface{}{
				"enabled":   true,
				"severity": "warning",
			},
			"EXPENSIVE_INSTANCE_TYPE": map[string]interface{}{
				"enabled":   true,
				"severity": "info",
			},
			"UNUSED_EIP": map[string]interface{}{
				"enabled":   true,
				"severity": "info",
			},
		},
	}
}

func MarshalYAML(config map[string]interface{}) (string, error) {
	data, err := yaml.Marshal(config)
	if err != nil {
		return "", err
	}

	header := `# terraform-lint Configuration File
# This is the default configuration file. Customize it to your needs.
# Rule severity levels: error, warning, info

`
	return header + string(data), nil
}


