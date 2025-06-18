package cmd

import (
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/LanXuage/gscan/arp"
	"github.com/LanXuage/gscan/common"
	"github.com/LanXuage/gscan/port"

	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var (
	portCmd = &cobra.Command{
		Use:   "port",
		Short: "PORT Scanner",
		RunE: func(cmd *cobra.Command, args []string) error {
			tcpScanner := port.GetTCPScanner()
			// defer tcpScanner.Close()
			arpScanner := arp.GetARPScanner()
			// defer arpScanner.Close()
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
			tcpScanner.Scanner.(*port.TCPScanner).UseFullTCP, _ = cmd.Flags().GetBool("full")
			ports, _ := cmd.Flags().GetStringArray("port")
			iScanner := tcpScanner.Scanner.(*port.TCPScanner)
			if len(ports) != 0 {
				iScanner.PortScanType = port.CUSTOM_PORTS
				for _, port := range ports {
					tmp, _ := ParsePort(port)
					iScanner.Ports = append(iScanner.Ports, tmp...)
				}
				logger.Debug("runE", zap.Any("ports", iScanner.Ports))
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
					ips = append(ips, ip)
				}
			}
			timeoutCh := tcpScanner.ScanMany(ips)
			normalPrintfTCP(timeoutCh, tcpScanner.ResultCh)
			fmt.Printf("Cost: %v\n", time.Since(start))
			return nil
		},
	}
)

func normalPrintfTCP(timeoutCh chan struct{}, resultCh chan interface{}) {
	arpScanner := arp.GetARPScanner()
	for {
		select {
		case tmp := <-resultCh:
			result := tmp.(*port.TCPResult)
			fmt.Printf("%-39s ", result.IP)
			if withARP {
				var vendor any = ""
				h, ok := arpScanner.Scanner.(*arp.ARPScanner).AHMap.Get(result.IP)
				if ok {
					prefix1, prefix2 := common.GetOuiPrefix(h)
					vendor, ok = arpScanner.Scanner.(*arp.ARPScanner).OMap.Load(prefix2)
					if !ok {
						vendor, _ = arpScanner.Scanner.(*arp.ARPScanner).OMap.Load(prefix1)
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
