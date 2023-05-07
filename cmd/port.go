package cmd

import (
	"fmt"
	"gscan/arp"
	"gscan/common"
	"gscan/port"
	"net"
	"net/netip"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var (
	portCmd = &cobra.Command{
		Use:   "port",
		Short: "PORT Scanner",
		RunE: func(cmd *cobra.Command, args []string) error {
			tcpScanner := port.GetTCPScanner()
			defer tcpScanner.Close()
			arpScanner := arp.GetARPScanner()
			defer arpScanner.Close()
			start := time.Now()
			fmt.Printf("%-39s ", "IP")
			if withARP {
				fmt.Printf("%-17s %-73s ", "MAC", "VENDOR")
			}
			fmt.Printf("%-24s %-5s\n", "PORT", "STATE")
			logger := common.GetLogger()
			timeout, _ := cmd.Flags().GetInt64("timeout")
			logger.Debug("runE", zap.Int64("timeout", timeout))
			tcpScanner.Timeout = time.Millisecond * time.Duration(timeout)
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
					timeoutCh := tcpScanner.ScanLocalNet()
					normalPrintfTCP(timeoutCh, tcpScanner.ResultCh)
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
			tcpScanner.UseFullTCP, _ = cmd.Flags().GetBool("full")
			ports, _ := cmd.Flags().GetStringArray("port")
			if len(ports) != 0 {
				tcpScanner.PortScanType = port.CUSTOM_PORTS
				for _, port := range ports {
					tmp, _ := ParsePort(port)
					tcpScanner.Ports = append(tcpScanner.Ports, tmp...)
				}
				logger.Debug("runE", zap.Any("ports", tcpScanner.Ports))
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
						timeoutCh := tcpScanner.ScanPrefix(prefix)
						normalPrintfTCP(timeoutCh, tcpScanner.ResultCh)
					}
				} else {
					timeoutCh := tcpScanner.ScanMany([]netip.Addr{ip})
					normalPrintfTCP(timeoutCh, tcpScanner.ResultCh)
				}
			}
			timeoutCh := tcpScanner.ScanMany(ips)
			normalPrintfTCP(timeoutCh, tcpScanner.ResultCh)
			fmt.Printf("Cost: %v\n", time.Since(start))
			return nil
		},
	}
)

func normalPrintfTCP(timeoutCh chan struct{}, resultCh chan *port.TCPResult) {
	for {
		select {
		case result := <-resultCh:
			fmt.Printf("%-39s ", result.IP)
			if withARP {
				vendor := ""
				h, ok := arp.GetARPScanner().AHMap.Get(result.IP)
				if ok {
					prefix1, prefix2 := common.GetOuiPrefix(h)
					vendor = arp.GetARPScanner().OMap[prefix2]
					if len(vendor) == 0 {
						vendor = arp.GetARPScanner().OMap[prefix1]
					}
				} else {
					h = net.HardwareAddr{}
				}
				fmt.Printf("%-17v %-73s ", h, vendor)
			}
			fmt.Printf("%s/%-20v %-5s\n", "tcp", result.Port, "open")
		case <-timeoutCh:
			return
		}
	}
}

func init() {
	rootCmd.AddCommand(portCmd)
	portCmd.Flags().StringArrayP("host", "h", []string{}, "host, domain or cidr to scan")
	portCmd.Flags().BoolP("all", "a", false, "to scan all localnet")
	portCmd.Flags().BoolP("udp", "u", false, "to scan udp")
	portCmd.Flags().BoolP("full", "f", false, "to scan by full tcp connect")
	portCmd.Flags().StringArrayP("port", "p", []string{}, "port to scan")
}
