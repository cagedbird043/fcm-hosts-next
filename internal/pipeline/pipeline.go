package pipeline

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/cagedbird043/fcm-hosts-next/internal/dnsprobe"
)

type Options struct {
	WorkDir       string
	Timeout       time.Duration
	DNSDelay      time.Duration
	Workers       int
	TopN          int
	Candidates    int
	Samples       int
	SampleGap     time.Duration
	SampleTimeout time.Duration
	DNS           bool
	Existing      bool
	ProbePort     int
	Verbose       bool
}

func DefaultOptions() Options {
	return Options{
		WorkDir:       ".",
		Timeout:       1500 * time.Millisecond,
		DNSDelay:      0,
		Workers:       100,
		TopN:          len(FCMDomains),
		Candidates:    40,
		Samples:       20,
		SampleGap:     250 * time.Millisecond,
		SampleTimeout: synRetransmit,
		DNS:           true,
		Existing:      true,
		ProbePort:     FCMPort,
	}
}

func Run(ctx context.Context, opt Options) (Result, error) {
	if opt.Workers <= 0 {
		opt.Workers = 100
	}
	if opt.TopN <= 0 {
		opt.TopN = len(FCMDomains)
	}
	if opt.Timeout == 0 {
		opt.Timeout = 1500 * time.Millisecond
	}
	if opt.ProbePort == 0 {
		opt.ProbePort = FCMPort
	}
	if opt.Candidates < opt.TopN {
		opt.Candidates = opt.TopN
	}
	if opt.Samples <= 0 {
		opt.Samples = 1
	}
	if opt.SampleTimeout == 0 {
		opt.SampleTimeout = synRetransmit
	}

	seeds4 := []string{}
	seeds6 := []string{}
	if opt.DNS {
		d4, d6 := harvestDNS(ctx, opt)
		seeds4 = append(seeds4, d4...)
		seeds6 = append(seeds6, d6...)
	}
	if opt.Existing {
		e4, e6 := loadExistingSeeds(opt.WorkDir)
		seeds4 = append(seeds4, e4...)
		seeds6 = append(seeds6, e6...)
	}
	seeds4 = uniqueIPs(seeds4)
	seeds6 = uniqueIPs(seeds6)
	if opt.Verbose {
		fmt.Printf("seeds: v4=%d v6=%d\n", len(seeds4), len(seeds6))
	}

	v4 := selectFamily(ctx, seeds4, opt, false)
	v6 := selectFamily(ctx, seeds6, opt, true)
	return Result{SeedV4: len(seeds4), SeedV6: len(seeds6), SelectedV4: v4, SelectedV6: v6}, nil
}

func harvestDNS(ctx context.Context, opt Options) ([]string, []string) {
	client := dnsprobe.Client{Timeout: 5 * time.Second}
	v4Subnets := append(append(append([]string{}, ChinaBackboneV4...), TaiwanBackboneV4...), GlobalV4...)
	v6Subnets := append(append([]string{}, ChinaBackboneV6...), GlobalV6...)
	type job struct {
		ns, name, subnet string
		qtype            uint16
		v6               bool
	}
	type got struct {
		ips []string
		err error
		job job
	}
	jobs := []job{}
	for _, ns := range DNSServers {
		for _, name := range HarvestNames {
			for _, subnet := range v4Subnets {
				jobs = append(jobs, job{ns: ns, name: name, subnet: subnet, qtype: dnsprobe.TypeA})
			}
			for _, subnet := range v6Subnets {
				jobs = append(jobs, job{ns: ns, name: name, subnet: subnet, qtype: dnsprobe.TypeAAAA, v6: true})
			}
		}
	}
	limit := opt.Workers
	if limit <= 0 {
		limit = 40
	}
	if limit > 40 {
		limit = 40
	}
	sem := make(chan struct{}, limit)
	out := make(chan got, len(jobs))
	var wg sync.WaitGroup
	for _, j := range jobs {
		j := j
		wg.Add(1)
		go func() {
			defer wg.Done()
			select {
			case sem <- struct{}{}:
				defer func() { <-sem }()
			case <-ctx.Done():
				out <- got{err: ctx.Err(), job: j}
				return
			}
			ips, err := client.QueryECS(ctx, j.ns, j.name, j.qtype, j.subnet)
			out <- got{ips: ips, err: err, job: j}
			if opt.DNSDelay > 0 {
				time.Sleep(opt.DNSDelay)
			}
		}()
	}
	wg.Wait()
	close(out)
	v4, v6 := []string{}, []string{}
	for r := range out {
		if opt.Verbose {
			kind := "A"
			if r.job.v6 {
				kind = "AAAA"
			}
			fmt.Printf("dns %s %s %s %s -> %d", r.job.ns, kind, r.job.name, r.job.subnet, len(r.ips))
			if r.err != nil {
				fmt.Printf(" err=%v", r.err)
			}
			fmt.Println()
		}
		if r.err != nil {
			continue
		}
		if r.job.v6 {
			v6 = append(v6, r.ips...)
		} else {
			v4 = append(v4, r.ips...)
		}
	}
	return uniqueIPs(v4), uniqueIPs(v6)
}

func loadExistingSeeds(dir string) ([]string, []string) {
	files := []string{"fcm_ipv4.hosts", "fcm_ipv6.hosts", "fcm_dual.hosts", "raw_ips_v4.txt", "raw_ips_v6.txt", "seeds.txt"}
	v4, v6 := []string{}, []string{}
	for _, f := range files {
		path := f
		if dir != "" && dir != "." {
			path = strings.TrimRight(dir, "/") + "/" + f
		}
		fh, err := os.Open(path)
		if err != nil {
			continue
		}
		s := bufio.NewScanner(fh)
		for s.Scan() {
			fields := strings.Fields(s.Text())
			if len(fields) == 0 || strings.HasPrefix(fields[0], "#") {
				continue
			}
			ip := fields[0]
			addr, err := netip.ParseAddr(ip)
			if err != nil {
				continue
			}
			if addr.Is4() {
				v4 = append(v4, ip)
			} else if addr.Is6() {
				v6 = append(v6, ip)
			}
		}
		_ = fh.Close()
	}
	return uniqueIPs(v4), uniqueIPs(v6)
}

// selectFamily 分两段：全部候选单次握手粗筛出 Candidates 个，再逐个多次采样精测，
// 按预期建连耗时挑 TopN 个，每个 /24（IPv6 为 /64）只取一个。
func selectFamily(ctx context.Context, seeds []string, opt Options, is6 bool) []Candidate {
	if len(seeds) == 0 {
		return nil
	}
	all := batchProbe(ctx, seeds, opt)
	short := shortlist(all, opt.Candidates)
	refined := refine(ctx, short, opt)
	picked := pickDistinct(refined, opt.TopN)
	if opt.Verbose {
		fmt.Printf("refine v6=%v shortlist=%d picked=%d\n", is6, len(short), len(picked))
		sorted := append([]Candidate{}, refined...)
		sortByScore(sorted)
		chosen := map[string]bool{}
		for _, c := range picked {
			chosen[c.IP] = true
		}
		for _, c := range sorted {
			mark := " "
			if chosen[c.IP] {
				mark = "*"
			}
			fmt.Printf("%s %-28s %s\n", mark, c.IP, describe(c))
		}
	}
	return picked
}

func describe(c Candidate) string {
	return fmt.Sprintf("median=%dms p90=%dms loss=%d/%d score=%dms",
		c.Median.Milliseconds(), c.P90.Milliseconds(), c.Lost, c.Samples, c.Score().Milliseconds())
}

func batchProbe(ctx context.Context, ips []string, opt Options) []ProbeResult {
	jobs := make(chan string)
	results := make(chan ProbeResult, len(ips))
	workers := opt.Workers
	if workers > len(ips) {
		workers = len(ips)
	}
	if workers <= 0 {
		workers = 1
	}
	var wg sync.WaitGroup
	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for ip := range jobs {
				results <- probeOne(ctx, ip, opt.ProbePort, opt.Timeout)
			}
		}()
	}
	for _, ip := range ips {
		jobs <- ip
	}
	close(jobs)
	wg.Wait()
	close(results)
	out := make([]ProbeResult, 0, len(ips))
	ok := 0
	for r := range results {
		if r.OK {
			ok++
		}
		out = append(out, r)
	}
	if opt.Verbose {
		fmt.Printf("probe %d -> ok=%d fail=%d\n", len(ips), ok, len(ips)-ok)
	}
	return out
}

func probeOne(ctx context.Context, ip string, port int, timeout time.Duration) ProbeResult {
	start := time.Now()
	var d net.Dialer
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	addr := net.JoinHostPort(ip, fmt.Sprint(port))
	conn, err := d.DialContext(ctx, "tcp", addr)
	lat := time.Since(start)
	if err != nil {
		return ProbeResult{IP: ip, Latency: lat, OK: false, Error: err.Error()}
	}
	_ = conn.Close()
	return ProbeResult{IP: ip, Latency: lat, OK: true}
}

// shortlist 取粗筛延迟最低的 n 个 IP。
func shortlist(results []ProbeResult, n int) []string {
	best := map[string]ProbeResult{}
	for _, r := range results {
		if !r.OK {
			continue
		}
		if old, ok := best[r.IP]; !ok || r.Latency < old.Latency {
			best[r.IP] = r
		}
	}
	oks := make([]ProbeResult, 0, len(best))
	for _, r := range best {
		oks = append(oks, r)
	}
	sort.Slice(oks, func(i, j int) bool {
		if oks[i].Latency == oks[j].Latency {
			return oks[i].IP < oks[j].IP
		}
		return oks[i].Latency < oks[j].Latency
	})
	if len(oks) > n {
		oks = oks[:n]
	}
	out := make([]string, 0, len(oks))
	for _, r := range oks {
		out = append(out, r.IP)
	}
	return out
}

// refine 对每个 IP 间隔采样 Samples 次握手；超时设为 SYN 重传时间，重传才成功的算丢包。
func refine(ctx context.Context, ips []string, opt Options) []Candidate {
	workers := opt.Workers
	if workers > len(ips) {
		workers = len(ips)
	}
	if workers <= 0 {
		return nil
	}
	out := make([]Candidate, len(ips))
	sem := make(chan struct{}, workers)
	var wg sync.WaitGroup
	for i, ip := range ips {
		wg.Add(1)
		go func(i int, ip string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			lats := make([]time.Duration, 0, opt.Samples)
			for s := 0; s < opt.Samples && ctx.Err() == nil; s++ {
				if s > 0 {
					select {
					case <-time.After(opt.SampleGap):
					case <-ctx.Done():
					}
				}
				if r := probeOne(ctx, ip, opt.ProbePort, opt.SampleTimeout); r.OK {
					lats = append(lats, r.Latency)
				}
			}
			out[i] = summarize(ip, opt.Samples, lats)
		}(i, ip)
	}
	wg.Wait()
	return out
}

func summarize(ip string, samples int, lats []time.Duration) Candidate {
	c := Candidate{IP: ip, Samples: samples, Lost: samples - len(lats)}
	if len(lats) == 0 {
		return c
	}
	sort.Slice(lats, func(i, j int) bool { return lats[i] < lats[j] })
	c.Median = lats[len(lats)/2]
	c.P90 = lats[(len(lats)*9)/10]
	return c
}

func sortByScore(cs []Candidate) {
	sort.Slice(cs, func(i, j int) bool {
		if cs[i].Score() == cs[j].Score() {
			return cs[i].IP < cs[j].IP
		}
		return cs[i].Score() < cs[j].Score()
	})
}

// pickDistinct 按 Score 选 n 个 IP，丢包过半的不要。先每个网段只取一个；
// 网段不够时再从剩余 IP 补齐，保证每个域名尽量各占一个独立 IP。
func pickDistinct(cs []Candidate, n int) []Candidate {
	usable := make([]Candidate, 0, len(cs))
	for _, c := range cs {
		if c.Lost < c.Samples && c.Lost*2 <= c.Samples {
			usable = append(usable, c)
		}
	}
	sortByScore(usable)
	out := make([]Candidate, 0, n)
	taken := map[string]bool{}
	blocks := map[netip.Prefix]bool{}
	for _, c := range usable {
		if len(out) == n {
			return out
		}
		b, ok := block(c.IP)
		if !ok || blocks[b] {
			continue
		}
		blocks[b] = true
		taken[c.IP] = true
		out = append(out, c)
	}
	for _, c := range usable {
		if len(out) == n {
			break
		}
		if !taken[c.IP] {
			taken[c.IP] = true
			out = append(out, c)
		}
	}
	return out
}

// block 返回 IP 所在的 /24（IPv4）或 /64（IPv6）。
func block(ip string) (netip.Prefix, bool) {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return netip.Prefix{}, false
	}
	bits := 64
	if addr.Is4() {
		bits = 24
	}
	p, err := addr.WithZone("").Prefix(bits)
	return p, err == nil
}

func uniqueIPs(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, ip := range in {
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			continue
		}
		s := addr.String()
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
