package common

import "github.com/oschwald/geoip2-golang"

var GEOIP2_DB *geoip2.Reader

func init() {
	GEOIP2_DB = getGeoIP2DB()
}

func getGeoIP2DB() *geoip2.Reader {
	reader, _ := geoip2.Open("GeoIP2-City.mmdb")
	return reader
}
