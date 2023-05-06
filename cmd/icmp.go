package cmd

import (
	"gscan/common"
	"gscan/icmp"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var (
	icmpScanner = icmp.New()
	icmpCmd     = &cobra.Command{
		Use:   "icmp",
		Short: "ICMP Scanner",
		RunE: func(cmd *cobra.Command, args []string) error {
			logger := common.GetLogger()
			timeout, _ := cmd.Flags().GetInt64("timeout")
			logger.Debug("runE", zap.Int64("timeout", timeout))
			icmpScanner.Timeout = time.Second * time.Duration(timeout)
			host, _ := cmd.Flags().GetString("host")
			logger.Debug("runE", zap.Any("host", host))
			return nil
		},
	}
)

func init() {
	rootCmd.AddCommand(icmpCmd)
	icmpCmd.Flags().StringP("host", "h", "", "host, domain or cidr to scan")
	icmpCmd.Flags().BoolP("all", "a", false, "to scan all localnet")
}
