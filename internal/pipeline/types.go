package pipeline

import "time"

var FCMDomains = []string{
	"mtalk.google.com",
	"mtalk4.google.com",
	"mtalk-staging.google.com",
	"mtalk-dev.google.com",
	"alt1-mtalk.google.com",
	"alt2-mtalk.google.com",
	"alt3-mtalk.google.com",
	"alt4-mtalk.google.com",
	"alt5-mtalk.google.com",
	"alt6-mtalk.google.com",
	"alt7-mtalk.google.com",
	"alt8-mtalk.google.com",
}

const FCMPort = 5228

var DNSServers = []string{
	"216.239.32.10",
	"216.239.34.10",
	"216.239.36.10",
	"216.239.38.10",
	"168.95.192.1",
	"168.95.1.1",
	"1.1.1.1",
	"9.9.9.9",
	"101.101.101.101",
	"8.8.8.8",
}

var ChinaBackboneV4 = []string{
	"202.112.0.0/16", "202.113.0.0/16",
	"1.0.0.0/8", "14.1.0.0/16", "14.208.0.0/12",
	"111.206.0.0/16", "111.207.0.0/16", "111.208.0.0/14",
	"180.149.0.0/16", "180.150.0.0/15",
	"219.158.0.0/17", "219.158.128.0/17",
	"220.195.0.0/15", "221.12.0.0/16", "221.13.0.0/16",
	"221.176.0.0/12", "223.5.0.0/16",
	"202.106.0.0/16", "202.99.0.0/16", "202.106.192.0/14",
	"117.144.0.0/16", "117.128.0.0/10", "183.128.0.0/11", "223.0.0.0/12",
	"43.254.0.0/16", "106.120.0.0/14",
}

var TaiwanBackboneV4 = []string{
	"1.160.0.0/12", "61.224.0.0/13", "111.240.0.0/12", "114.32.0.0/12",
	"220.136.0.0/13", "27.240.0.0/13", "39.8.0.0/13", "42.72.0.0/13",
	"140.112.0.0/12",
}

var ChinaBackboneV6 = []string{
	"2001:da8::/32", "240e::/12", "2408::/12", "2400::/12", "2402::/14",
	"2408::/10", "240c::/12", "2401:da00::/32", "2402:4e00::/22",
}

type ProbeResult struct {
	IP      string
	Latency time.Duration
	OK      bool
	Error   string
}

type Result struct {
	SeedV4     int
	SeedV6     int
	SelectedV4 []string
	SelectedV6 []string
}
