package ports

import "github.com/google/gopacket/layers"

func GetDefaultPorts() *[]layers.TCPPort {
	return &[]layers.TCPPort{
		DEFAULT_DB2,
		DEFAULT_ELASTICSEARCH,
		DEFAULT_FTP,
		DEFAULT_MONGODB,
		DEFAULT_MYSQL,
		DEFAULT_HTTP,
		DEFAULT_HTTPS,
		DEFAULT_SSH,
	}
}
