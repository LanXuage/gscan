package cmd

import (
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/LanXuage/gscan/arp"
	"github.com/LanXuage/gscan/common"
	"github.com/LanXuage/gscan/port"
	"github.com/LanXuage/gscan/service"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var (
	serviceCmd = &cobra.Command{
		Use:   "service",
		Short: "Service Scanner",
		RunE: func(cmd *cobra.Command, args []string) error {
			serviceScanner := service.GetServiceScanner()
			arpScanner := arp.GetARPScanner()
			start := time.Now()
			fmt.Printf("%-39s ", "IP")
			if withARP {
				fmt.Printf("%-17s %-73s ", "MAC", "VENDOR")
			}
			fmt.Printf("%-24s %-5s\n", "PORT", "SERVICE")
			logger := common.GetLogger()
			timeout, _ := cmd.Flags().GetInt64("timeout")
			logger.Debug("runE", zap.Int64("timeout", timeout))
			serviceScanner.Timeout = time.Millisecond * time.Duration(timeout)
			if timeout > 2000 {
				arpScanner.Timeout = 2000 * time.Microsecond
			} else {
				arpScanner.Timeout = time.Millisecond * time.Duration(timeout)
			}
			hosts, _ := cmd.Flags().GetStringArray("host")
			logger.Debug("runE", zap.Any("host", hosts))
			if len(hosts) == 0 {
				all, _ := cmd.Flags().GetBool("all")
				if all {
					timeoutCh := serviceScanner.ScanLocalNet()
					normalPrintfService(timeoutCh, serviceScanner.ResultCh)
				} else {
					cmd.Help()
				}
			}
			if withARP {
				timeoutCh := arpScanner.ScanLocalNet()
			L1:
				for {
					select {
					case <-arpScanner.ResultCh:
						continue
					case <-timeoutCh:
						break L1
					}
				}
			}
			ports, _ := cmd.Flags().GetStringArray("port")
			if len(ports) != 0 {
				serviceScanner.PortScanType = port.CUSTOM_PORTS
				for _, port := range ports {
					tmp, _ := ParsePort(port)
					serviceScanner.Ports = append(serviceScanner.Ports, tmp...)
				}
				logger.Debug("runE", zap.Any("ports", serviceScanner.Ports))
			}
			ips := []netip.Addr{}
			for _, host := range hosts {
				if ip, err := netip.ParseAddr(host); err != nil {
					if prefix, err := netip.ParsePrefix(host); err != nil {
						logger.Debug("runE", zap.Any("ip", ip))
						if tmp, err := ParseAddr(host); err == nil {
							ips = append(ips, tmp...)
						} else {
							fmt.Println(err)
						}
					} else {
						logger.Debug("runE", zap.Any("prefix", prefix))
						timeoutCh := serviceScanner.ScanPrefix(prefix)
						normalPrintfService(timeoutCh, serviceScanner.ResultCh)
					}
				} else {
					timeoutCh := serviceScanner.ScanMany([]netip.Addr{ip})
					normalPrintfService(timeoutCh, serviceScanner.ResultCh)
				}
			}
			timeoutCh := serviceScanner.ScanMany(ips)
			normalPrintfService(timeoutCh, serviceScanner.ResultCh)
			fmt.Printf("Cost: %v\n", time.Since(start))
			return nil
		},
	}
)

func normalPrintfService(timeoutCh chan struct{}, resultCh chan *service.ServiceResult) {
	for {
		select {
		case result := <-resultCh:
			fmt.Printf("%-39s ", result.IP)
			if withARP {
				var vendor any = ""
				h, ok := arp.GetARPScanner().AHMap.Get(result.IP)
				if ok {
					prefix1, prefix2 := common.GetOuiPrefix(h)
					vendor, ok = arp.GetARPScanner().OMap.Load(prefix2)
					if !ok {
						vendor, _ = arp.GetARPScanner().OMap.Load(prefix1)
					}
				} else {
					h = net.HardwareAddr{}
				}
				fmt.Printf("%-17v %-73s ", h, vendor)
			}
			fmt.Printf("%s/%-20v %-5s\n", "tcp", result.Port, result.CPE)
		case <-timeoutCh:
			return
		}
	}
}

func init() {
	rootCmd.AddCommand(serviceCmd)
	serviceCmd.Flags().StringArrayP("host", "h", []string{}, "host, domain or cidr to scan")
	serviceCmd.Flags().BoolP("all", "a", false, "to scan all localnet")
	serviceCmd.Flags().StringArrayP("port", "p", []string{}, "port to scan")
}
