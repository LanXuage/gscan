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
	icmpCmd = &cobra.Command{
		Use:   "icmp",
		Short: "ICMP Scanner",
		RunE: func(cmd *cobra.Command, args []string) error {
			icmpScanner := icmp.GetICMPScanner()
			defer icmpScanner.Close()
			logger := common.GetLogger()
			start := time.Now()
			timeout, _ := cmd.Flags().GetInt64("timeout")
			logger.Debug("runE", zap.Int64("timeout", timeout))
			icmpScanner.Timeout = time.Millisecond * time.Duration(timeout)

			if hosts, err := cmd.Flags().GetStringArray("hosts"); err == nil {
				icmpScanner.Init()
				if len(hosts) != 0 {
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
					return nil
				}
			}

			if ttl, _ := cmd.Flags().GetString("ttl"); ttl != "" {
				icmpScanner.Choice = 2
				icmpScanner.Init()
				logger.Debug("UDPTTL", zap.Any("ip", ttl))

				ip, err := netip.ParseAddr(ttl)
				if err == nil {
					fmt.Printf("traceroute to %s, %d hops max, Timeout: %v\n", ip, icmpScanner.TTL, icmpScanner.Timeout)
					timeoutCh := icmpScanner.ScanOne(ip)
					select {
					case result := <-icmpScanner.TResultCh:
						fmt.Printf("IP: %s", result.IP.As4())
					case <-timeoutCh:
						fmt.Printf("Cost: %v\n", time.Since(start))
						return nil
					}
				}
				return nil
			}

			cmd.Help()
			return nil
		},
	}
)

func icmpPrintf(timeoutCh chan struct{}, resultCh chan *icmp.ICMPScanResult) {
	for {
		select {
		case result := <-resultCh:
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
	icmpCmd.Flags().StringP("ttl", "t", "", "traceroute by udp")
}
