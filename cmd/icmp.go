package cmd

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/LanXuage/gscan/common"
	"github.com/LanXuage/gscan/icmp"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var (
	icmpScanner = icmp.GetICMPScanner()
	icmpCmd     = &cobra.Command{
		Use:   "icmp",
		Short: "ICMP Scanner",
		RunE: func(cmd *cobra.Command, args []string) error {
			defer icmpScanner.Close()
			logger := common.GetLogger()
			start := time.Now()
			timeout, _ := cmd.Flags().GetInt64("timeout")
			logger.Debug("runE", zap.Int64("timeout", timeout))
			icmpScanner.Timeout = time.Millisecond * time.Duration(timeout)

			if hosts, err := cmd.Flags().GetStringArray("hosts"); err == nil {
				if len(hosts) == 0 {
					cmd.Help()
					return nil
				}
				fmt.Printf("IP\t\t\tStatus\n")
				for _, host := range hosts {
					if len(host) == 0 {
						return nil
					}
					logger.Debug("runE", zap.Any("host", host))
					if ip, err := netip.ParseAddr(host); err == nil {
						logger.Debug("icmp", zap.Any("ip", ip))
						ipList := []netip.Addr{}
						ipList = append(ipList, ip)
						timeoutCh := icmpScanner.ScanList(ipList)
						icmpPrintf(timeoutCh, icmpScanner.ResultCh)
					}
					if prefix, err := netip.ParsePrefix(host); err == nil {
						logger.Debug("runE", zap.Any("prefix", prefix))
						timeoutCh := icmpScanner.ScanListByPrefix(prefix)
						icmpPrintf(timeoutCh, icmpScanner.ResultCh)
					}
					if ips, err := ParseAddr(host); err == nil {
						logger.Debug("runE", zap.Any("ips", ips))
						timeoutCh := icmpScanner.ScanList(ips)
						icmpPrintf(timeoutCh, icmpScanner.ResultCh)
					}
				}
				fmt.Printf("Cost: %v\n", time.Since(start))
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
				fmt.Printf("%s\t\tAlive\n", result.IP)
			}
		case <-timeoutCh:
			return
		}
	}
}

func init() {
	rootCmd.AddCommand(icmpCmd)
	icmpCmd.Flags().StringArrayP("hosts", "h", []string{}, "host, domain or cidr to scan")
	icmpCmd.Flags().StringP("file", "f", "", "host, domain and cidr")
}
