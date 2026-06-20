package cli

import (
	"fmt"

	"github.com/spf13/cobra"
)

func NewVersionCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "version",
		Short: "Print version information",
		Long:  `Print the version information for terraform-lint.`,
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Printf("terraform-lint v%s\n", Version)
			fmt.Println()
			fmt.Println("Terraform HCL static analysis and security compliance tool")
			fmt.Println("https://github.com/terraform-lint/terraform-lint")
		},
	}

	return cmd
}
