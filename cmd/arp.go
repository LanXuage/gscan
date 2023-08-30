package cmd

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/LanXuage/gscan/common"
	"github.com/LanXuage/gscan/scanner"

	"github.com/LanXuage/gscan/core/arp"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var (
	arpCmd = &cobra.Command{
		Use:   "arp",
		Short: "ARP Scanner",
		RunE: func(cmd *cobra.Command, args []string) error {
			arpScanner := arp.GetARPScanner()
			start := time.Now()
			fmt.Printf("%-39s %-17s %-73s\n", "IP", "MAC", "VENDOR")
			logger := common.GetLogger()
			timeout, _ := cmd.Flags().GetInt64("timeout")
			logger.Debug("runE", zap.Int64("timeout", timeout))
			hosts, _ := cmd.Flags().GetStringArray("host")
			logger.Debug("runE", zap.Any("host", hosts))
			if len(hosts) == 0 {
				all, _ := cmd.Flags().GetBool("all")
				if all {
					task := arpScanner.ScanLocalNet()
					normalPrintf(task, timeout)
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
						task := arpScanner.ScanPrefix(prefix)
						normalPrintf(task, timeout)
					}
				} else {
					ips = append(ips, ip)
				}
			}
			if len(ips) > 0 {
				task := arpScanner.Scan(ips)
				normalPrintf(task, timeout)
			}
			fmt.Printf("Cost: %v\n", time.Since(start))
			return nil
		},
	}
)

func normalPrintf(task scanner.ScanTask, timeout int64) {
	for result := range task.GetResults(time.Millisecond * time.Duration(timeout)) {
		arpResult := result.(*arp.ARPScanResult)
		fmt.Printf("%-39s %-17v %-73s\n", arpResult.IP, arpResult.Mac, arpResult.Vendor)
	}
}

func init() {
	rootCmd.AddCommand(arpCmd)
	arpCmd.Flags().StringArrayP("host", "h", []string{}, "hosts, domains or CIDRs to scan")
	arpCmd.Flags().BoolP("all", "a", false, "to scan all localnet")
}
