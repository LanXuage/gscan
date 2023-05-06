package cmd

import (
	"fmt"
	"gscan/arp"
	"gscan/common"
	"net/netip"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var (
	arpCmd = &cobra.Command{
		Use:   "arp",
		Short: "ARP Scanner",
		RunE: func(cmd *cobra.Command, args []string) error {
			arpScanner := arp.GetARPScanner()
			defer arpScanner.Close()
			start := time.Now()
			logger := common.GetLogger()
			timeout, _ := cmd.Flags().GetInt64("timeout")
			logger.Debug("runE", zap.Int64("timeout", timeout))
			arpScanner.Timeout = time.Second * time.Duration(timeout)
			hosts, _ := cmd.Flags().GetStringArray("host")
			logger.Debug("runE", zap.Any("host", hosts))
			if len(hosts) == 0 {
				all, _ := cmd.Flags().GetBool("all")
				if all {
					timeoutCh := arpScanner.ScanLocalNet()
					normalPrintf(timeoutCh, arpScanner.ResultCh)
				} else {
					cmd.Help()
				}
			}
			ips := []netip.Addr{}
			for _, host := range hosts {
				if ip, err := netip.ParseAddr(host); err != nil {
					if prefix, err := netip.ParsePrefix(host); err != nil {
						logger.Debug("arp", zap.Any("ip", ip))
						if tmp, err := ParseAddr(host); err == nil {
							ips = append(ips, tmp...)
						} else {
							fmt.Println(err)
						}
					} else {
						logger.Debug("runE", zap.Any("prefix", prefix))
						timeoutCh := arpScanner.ScanPrefix(prefix)
						normalPrintf(timeoutCh, arpScanner.ResultCh)
					}
				} else {
					timeoutCh := arpScanner.ScanMany([]netip.Addr{ip})
					normalPrintf(timeoutCh, arpScanner.ResultCh)
				}
			}
			if len(ips) > 0 {
				timeoutCh := arpScanner.ScanMany(ips)
				normalPrintf(timeoutCh, arpScanner.ResultCh)
			}
			fmt.Printf("Cost: %v\n", time.Since(start))
			return nil
		},
	}
)

func normalPrintf(timeoutCh chan struct{}, resultCh chan *arp.ARPScanResult) {
	for {
		select {
		case result := <-resultCh:
			fmt.Printf("%s\t%v\t%s\n", result.IP, result.Mac, result.Vendor)
		case <-timeoutCh:
			return
		}
	}
}

func init() {
	rootCmd.AddCommand(arpCmd)
	arpCmd.Flags().StringArrayP("host", "h", []string{}, "hosts, domains or CIDRs to scan")
	arpCmd.Flags().BoolP("all", "a", false, "to scan all localnet")
}
