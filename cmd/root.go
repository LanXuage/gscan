package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

var (
	withARP  bool
	withICMP bool
	rootCmd  = &cobra.Command{
		Use:   "gscan",
		Short: "A Scanner. ",
		Long: `Gscan
   ____  ______ ____ _____    ____  
  / ___\/  ___// ___\\__  \  /    \ 
 / /_/  >___ \\  \___ / __ \|   |  \
 \___  /____  >\___  >____  /___|  /
/_____/     \/     \/     \/     \/ 
https://github.com/LanXuage/gosam/gscan

A Scanner. `,
		Version: "0.1.0",
		RunE: func(cmd *cobra.Command, args []string) error {
			return cmd.Help()
		},
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			debug, _ := cmd.Flags().GetBool("debug")
			if debug {
				os.Setenv("GSCAN_LOG_LEVEL", "development")
			} else {
				os.Setenv("GSCAN_LOG_LEVEL", "production")
			}
		},
	}
)

// Execute executes the root command.
func Execute() error {
	return rootCmd.Execute()
}

func init() {
	rootCmd.PersistentFlags().BoolP("debug", "D", false, "set debug log level")
	rootCmd.PersistentFlags().BoolP("help", "H", false, "help for this command")
	rootCmd.PersistentFlags().BoolP("version", "V", false, "version for gscan")
	rootCmd.PersistentFlags().Int64P("timeout", "T", 3, "timeout global")
	rootCmd.PersistentFlags().StringP("output", "O", "normal", "normal, json or xml(unrealized)")
	rootCmd.PersistentFlags().StringP("file", "F", "", "file to output(unrealized)")
	rootCmd.PersistentFlags().BoolVarP(&withARP, "arp", "A", false, "with arp scan")
	rootCmd.PersistentFlags().BoolVarP(&withICMP, "icmp", "I", false, "with icmp scan")
}
