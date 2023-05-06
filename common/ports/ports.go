package ports

import "github.com/google/gopacket/layers"

const (
	DEFAULT_SOURCEPORT layers.TCPPort = 12345

	// Default Ports for Databases
	DEFAULT_SQLSERVER     layers.TCPPort = 1433
	DEFAULT_MYSQL         layers.TCPPort = 3306
	DEFAULT_ORACLE        layers.TCPPort = 1521
	DEFAULT_REDIS         layers.TCPPort = 6379
	DEFAULT_MONGODB       layers.TCPPort = 27017
	DEFAULT_DB2           layers.TCPPort = 5000
	DEFAULT_POSTGRESQL    layers.TCPPort = 5432
	DEFAULT_ELASTICSEARCH layers.TCPPort = 9200

	// Default Ports for otherservice
	DEFAULT_FTP      layers.TCPPort = 21
	DEFAULT_SSH      layers.TCPPort = 22
	DEFAULT_SMB      layers.TCPPort = 445
	DEFAULT_RDP      layers.TCPPort = 3389
	DEFAULT_HTTP     layers.TCPPort = 80
	DEFAULT_HTTPS    layers.TCPPort = 443
	DEFAULT_WEBLOGIC layers.TCPPort = 7001
	DEFAULT_WEB2     layers.TCPPort = 8080
	DEFAULT_WEB3     layers.TCPPort = 8888
)
