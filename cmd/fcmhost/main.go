package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/cagedbird043/fcm-hosts-next/internal/pipeline"
	"github.com/cagedbird043/fcm-hosts-next/internal/render"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run() error {
	if len(os.Args) < 2 {
		usage()
		return fmt.Errorf("missing command")
	}
	switch os.Args[1] {
	case "run":
		fs := flag.NewFlagSet("run", flag.ExitOnError)
		opt := pipeline.DefaultOptions()
		fs.StringVar(&opt.WorkDir, "workdir", ".", "directory containing seeds and output hosts")
		fs.BoolVar(&opt.DNS, "dns", true, "collect DNS ECS seeds")
		fs.BoolVar(&opt.Existing, "existing", true, "load existing hosts/raw seeds")
		fs.BoolVar(&opt.Expand, "expand", true, "expand nearby IPs after first successful probe")
		fs.IntVar(&opt.Workers, "workers", opt.Workers, "concurrent TCP probes")
		fs.IntVar(&opt.TopN, "top", opt.TopN, "selected IPs per address family")
		fs.DurationVar(&opt.Timeout, "timeout", opt.Timeout, "TCP probe timeout")
		fs.BoolVar(&opt.Verbose, "v", false, "verbose logs")
		if err := fs.Parse(os.Args[2:]); err != nil {
			return err
		}
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Minute)
		defer cancel()
		res, err := pipeline.Run(ctx, opt)
		if err != nil {
			return err
		}
		if err := render.WriteAll(opt.WorkDir, res); err != nil {
			return err
		}
		fmt.Printf("done: seeds v4=%d v6=%d selected v4=%d v6=%d\n", res.SeedV4, res.SeedV6, len(res.SelectedV4), len(res.SelectedV6))
		return nil
	case "version":
		fmt.Println("fcmhost go")
		return nil
	default:
		usage()
		return fmt.Errorf("unknown command %q", os.Args[1])
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: fcmhost run [flags]")
	fmt.Fprintln(os.Stderr, "       fcmhost version")
}
