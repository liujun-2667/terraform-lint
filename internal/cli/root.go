package cli

import (
	"github.com/spf13/cobra"
)

const Version = "1.0.0"

func NewRootCommand() *cobra.Command {
	rootCmd := &cobra.Command{
		Use:   "terraform-lint",
		Short: "Terraform HCL static analysis and security compliance tool",
		Long: `terraform-lint is a static analysis and security compliance tool for Terraform HCL files.
It scans Terraform configurations to detect security risks, best practice violations,
and cost optimization opportunities.`,
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	rootCmd.AddCommand(NewScanCommand())
	rootCmd.AddCommand(NewInitCommand())
	rootCmd.AddCommand(NewRulesCommand())
	rootCmd.AddCommand(NewVersionCommand())
	rootCmd.AddCommand(NewTestCommand())

	return rootCmd
}
