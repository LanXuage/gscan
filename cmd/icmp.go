package cmd

import (
	"fmt"
	"gscan/common"
	"gscan/icmp"
	"net/netip"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var (
	icmpScanner = icmp.GetICMPScanner()
	icmpCmd     = &cobra.Command{
		Use:   "icmp",
		Short: "ICMP Scanner",
		RunE: func(cmd *cobra.Command, args []string) error {
			logger := common.GetLogger()

			timeout, _ := cmd.Flags().GetInt64("timeout")
			logger.Debug("runE", zap.Int64("timeout", timeout))
			icmpScanner.Timeout = time.Second * time.Duration(timeout)

			// 单IP or CIDR
			if host, err := cmd.Flags().GetString("host"); err == nil {
				logger.Debug("runE", zap.Any("host", host))
				if ip, err := netip.ParseAddr(host); err == nil {
					logger.Debug("icmp", zap.Any("ip", ip))
					fmt.Printf("IP\t\t\tStatus\n")
					timeoutCh := icmpScanner.ScanOne(ip)
					icmpPrintf(timeoutCh, icmpScanner.ResultCh)
				} else if prefix, err := netip.ParsePrefix(host); err == nil {
					logger.Debug("runE", zap.Any("prefix", prefix))
					fmt.Printf("IP\t\t\tStatus\n")
					timeoutCh := icmpScanner.ScanListByPrefix(prefix)
					icmpPrintf(timeoutCh, icmpScanner.ResultCh)
				}
			}

			// 多IP
			if ips, err := cmd.Flags().GetString("hosts"); err == nil {
				fmt.Println(ips)
			}

			return nil
		},
	}
)

func icmpPrintf(timeoutCh chan struct{}, resultCh chan *icmp.ICMPScanResult) {
	for {
		select {
		case result := <-icmpScanner.ResultCh:
			if result.IsActive {
				fmt.Printf("%s\t\tActive\n", result.IP)
			} else {
				fmt.Printf("%s\t\tDied(Maybe)\n", result.IP)
			}
		case <-timeoutCh:
			return
		}
	}
}

func init() {
	rootCmd.AddCommand(icmpCmd)
	icmpCmd.Flags().StringP("host", "h", "", "host, domain or cidr to scan")
	icmpCmd.Flags().StringP("file", "f", "", "host, domain and cidr")
	icmpCmd.Flags().StringArrayP("hosts", "a", []string{}, "scan hosts without same lan")
}
