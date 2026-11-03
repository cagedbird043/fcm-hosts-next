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

// HarvestNames 是 ECS 采集时查询的域名；各 altN 对应不同的 mobile-gtalk 池。
var HarvestNames = []string{
	"mtalk.google.com",
	"alt1-mtalk.google.com",
	"alt3-mtalk.google.com",
	"alt5-mtalk.google.com",
	"alt7-mtalk.google.com",
}

// DNSServers 必须能从 bj-edge 直接访问。阿里和 DNSPod 会把 ECS 透传给 Google 权威，
// 境外子网能查到海外 PoP；Google 权威 DNS 和 101.101.101.101 在大陆不可达，不放进来。
var DNSServers = []string{
	"223.5.5.5",
	"119.29.29.29",
	"168.95.192.1",
	"168.95.1.1",
	"1.1.1.1",
	"9.9.9.9",
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

// GlobalV4 / GlobalV6 是海外家宽和运营商网段（美、日、韩、新、港、欧、澳、巴西），
// 让 Google 返回各地 PoP；离 bj-edge 最近的未必在亚洲，由 TCP 实测决定。
var GlobalV4 = []string{
	"73.0.0.0/8", "24.0.0.0/12", "126.0.0.0/8", "153.128.0.0/9", "175.192.0.0/10",
	"116.88.0.0/14", "112.118.0.0/15", "79.192.0.0/10", "86.0.0.0/11", "1.120.0.0/13",
	"177.0.0.0/8",
}

var ChinaBackboneV6 = []string{
	"2001:da8::/32", "240e::/12", "2408::/12", "2400::/12", "2402::/14",
	"2408::/10", "240c::/12", "2401:da00::/32", "2402:4e00::/22",
}

var GlobalV6 = []string{
	"2601::/24", "2600:1700::/28", "2602:fe00::/24", "2603:3000::/24", "2604:2d80::/32",
	"2605:6000::/24", "2001:268::/32", "2400:4050::/32", "2001:e60::/32", "2406:3000::/32",
	"2001:b000::/24", "2003::/24", "2a00:2380::/28", "2001:8000::/24", "2401:7400::/32",
	"2a02:2e0::/32", "2804::/24", "2405:200::/32", "2403:5800::/32", "2a01:e00::/26",
}

type ProbeResult struct {
	IP      string
	Latency time.Duration
	OK      bool
	Error   string
}

// synRetransmit 是 Linux 首个 SYN 的重传超时：丢一次握手包，建连就要多等这么久。
const synRetransmit = time.Second

// Candidate 是精测阶段对单个 IP 多次 TCP 握手采样的统计。
type Candidate struct {
	IP      string
	Samples int
	Lost    int
	Median  time.Duration
	P90     time.Duration
}

func (c Candidate) LossRate() float64 {
	if c.Samples == 0 {
		return 1
	}
	return float64(c.Lost) / float64(c.Samples)
}

// Score 是预期建连耗时：中位 RTT 加上丢包触发 SYN 重传的期望代价。
func (c Candidate) Score() time.Duration {
	return c.Median + time.Duration(c.LossRate()*float64(synRetransmit))
}

type Result struct {
	SeedV4     int
	SeedV6     int
	SelectedV4 []Candidate
	SelectedV6 []Candidate
}
