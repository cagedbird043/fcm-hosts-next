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
	WorkDir   string
	Target    string
	Timeout   time.Duration
	DNSDelay  time.Duration
	Workers   int
	TopN      int
	Expand    bool
	DNS       bool
	Existing  bool
	ProbePort int
	Verbose   bool
}

func DefaultOptions() Options {
	return Options{
		WorkDir:   ".",
		Target:    "mtalk.google.com",
		Timeout:   1500 * time.Millisecond,
		DNSDelay:  0,
		Workers:   100,
		TopN:      len(FCMDomains),
		Expand:    true,
		DNS:       true,
		Existing:  true,
		ProbePort: FCMPort,
	}
}

func Run(ctx context.Context, opt Options) (Result, error) {
	if opt.Workers <= 0 {
		opt.Workers = 100
	}
	if opt.TopN <= 0 {
		opt.TopN = len(FCMDomains)
	}
	if opt.Target == "" {
		opt.Target = "mtalk.google.com"
	}
	if opt.Timeout == 0 {
		opt.Timeout = 1500 * time.Millisecond
	}
	if opt.ProbePort == 0 {
		opt.ProbePort = FCMPort
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
	v4Subnets := append([]string{}, ChinaBackboneV4...)
	v4Subnets = append(v4Subnets, TaiwanBackboneV4...)
	type job struct {
		ns, subnet string
		qtype      uint16
		v6         bool
	}
	type got struct {
		ips []string
		err error
		job job
	}
	jobs := []job{}
	for _, ns := range DNSServers {
		for _, subnet := range v4Subnets {
			jobs = append(jobs, job{ns: ns, subnet: subnet, qtype: dnsprobe.TypeA})
		}
		for _, subnet := range ChinaBackboneV6 {
			jobs = append(jobs, job{ns: ns, subnet: subnet, qtype: dnsprobe.TypeAAAA, v6: true})
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
			ips, err := client.QueryECS(ctx, j.ns, opt.Target, j.qtype, j.subnet)
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
			fmt.Printf("dns %s %s %s -> %d", r.job.ns, kind, r.job.subnet, len(r.ips))
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

func selectFamily(ctx context.Context, seeds []string, opt Options, is6 bool) []string {
	if len(seeds) == 0 {
		return nil
	}
	initial := batchProbe(ctx, seeds, opt)
	all := append([]ProbeResult{}, initial...)
	if opt.Expand {
		expanded := expandSuccessful(initial, is6)
		expanded = subtract(expanded, seeds)
		if opt.Verbose {
			fmt.Printf("expand v6=%v new=%d\n", is6, len(expanded))
		}
		if len(expanded) > 0 {
			all = append(all, batchProbe(ctx, expanded, opt)...)
		}
	}
	return topIPs(all, opt.TopN)
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

func expandSuccessful(results []ProbeResult, is6 bool) []string {
	seenBlocks := map[string]bool{}
	out := []string{}
	for _, r := range results {
		if !r.OK {
			continue
		}
		addr, err := netip.ParseAddr(r.IP)
		if err != nil {
			continue
		}
		if is6 && addr.Is6() {
			base := ipv6Block124(addr)
			key := base.String()
			if seenBlocks[key] {
				continue
			}
			seenBlocks[key] = true
			out = append(out, expandIPv6Block124(base)...)
		} else if !is6 && addr.Is4() {
			parts := strings.Split(r.IP, ".")
			if len(parts) != 4 {
				continue
			}
			key := strings.Join(parts[:3], ".")
			if seenBlocks[key] {
				continue
			}
			seenBlocks[key] = true
			var last int
			_, _ = fmt.Sscanf(parts[3], "%d", &last)
			start, end := last-10, last+10
			if start < 1 {
				start = 1
			}
			if end > 254 {
				end = 254
			}
			for i := start; i <= end; i++ {
				out = append(out, fmt.Sprintf("%s.%d", key, i))
			}
		}
	}
	return uniqueIPs(out)
}

func ipv6Block124(addr netip.Addr) netip.Addr {
	a := addr.As16()
	a[15] &= 0xf0
	base := netip.AddrFrom16(a)
	if z := addr.Zone(); z != "" {
		base = base.WithZone(z)
	}
	return base
}

func expandIPv6Block124(base netip.Addr) []string {
	a := base.As16()
	out := make([]string, 0, 16)
	for i := 0; i < 16; i++ {
		b := a
		b[15] = (b[15] & 0xf0) | byte(i)
		out = append(out, netip.AddrFrom16(b).String())
	}
	return out
}

func topIPs(results []ProbeResult, n int) []string {
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
	sort.SliceStable(oks, func(i, j int) bool {
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

func subtract(in, minus []string) []string {
	m := map[string]bool{}
	for _, x := range minus {
		m[x] = true
	}
	out := []string{}
	for _, x := range in {
		if !m[x] {
			out = append(out, x)
		}
	}
	return out
}
