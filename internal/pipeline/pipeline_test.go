package pipeline

import (
	"testing"
	"time"
)

func TestPickDistinctOnePerBlockThenFill(t *testing.T) {
	cs := []Candidate{
		{IP: "1.1.1.1", Samples: 20, Median: 10},
		{IP: "1.1.1.2", Samples: 20, Median: 11},
		{IP: "2.2.2.2", Samples: 20, Median: 50},
	}
	got := pickDistinct(cs, 2)
	if len(got) != 2 || got[0].IP != "1.1.1.1" || got[1].IP != "2.2.2.2" {
		t.Fatalf("same /24 picked twice: %v", got)
	}
	got = pickDistinct(cs, 3)
	if len(got) != 3 || got[2].IP != "1.1.1.2" {
		t.Fatalf("fill from leftover IPs failed: %v", got)
	}
}

func TestPickDistinctIPv6BlockIs64(t *testing.T) {
	cs := []Candidate{
		{IP: "2404:6800:4008:c00::bc", Samples: 20, Median: 10},
		{IP: "2404:6800:4008:c00::bd", Samples: 20, Median: 11},
		{IP: "2404:6800:4008:c01::bc", Samples: 20, Median: 12},
	}
	got := pickDistinct(cs, 2)
	if len(got) != 2 || got[1].IP != "2404:6800:4008:c01::bc" {
		t.Fatalf("got=%v", got)
	}
}

func TestPickDistinctLossOutweighsSmallRTTGain(t *testing.T) {
	ms := time.Millisecond
	cs := []Candidate{
		{IP: "1.1.1.1", Samples: 20, Lost: 4, Median: 170 * ms}, // 20% 丢包：期望 +200ms
		{IP: "2.2.2.2", Samples: 20, Lost: 0, Median: 230 * ms},
		{IP: "3.3.3.3", Samples: 20, Lost: 11, Median: 100 * ms}, // 丢包过半，淘汰
		{IP: "4.4.4.4", Samples: 20, Lost: 20},
	}
	got := pickDistinct(cs, 4)
	if len(got) != 2 || got[0].IP != "2.2.2.2" || got[1].IP != "1.1.1.1" {
		t.Fatalf("got=%v", got)
	}
}
