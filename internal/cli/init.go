package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/terraform-lint/terraform-lint/internal/config"
)

func NewInitCommand() *cobra.Command {
	var outputFile string
	var force bool

	cmd := &cobra.Command{
		Use:   "init",
		Short: "Generate default configuration file",
		Long:  `Generate a default .tflint.yaml configuration file with all available rules and recommended settings.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if outputFile == "" {
				outputFile = ".tflint.yaml"
			}

			if _, err := os.Stat(outputFile); err == nil && !force {
				return fmt.Errorf("configuration file %s already exists, use --force to overwrite", outputFile)
			}

			defaultConfig := config.GenerateDefaultConfig()
			content, err := config.MarshalYAML(defaultConfig)
			if err != nil {
				return fmt.Errorf("marshaling config: %w", err)
			}

			if err := os.WriteFile(outputFile, []byte(content), 0644); err != nil {
				return fmt.Errorf("writing config file: %w", err)
			}

			fmt.Printf("✓ Generated default configuration file: %s\n", outputFile)
			return nil
		},
	}

	cmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file path (default: .tflint.yaml)")
	cmd.Flags().BoolVarP(&force, "force", "f", false, "Overwrite existing configuration file")

	return cmd
}
