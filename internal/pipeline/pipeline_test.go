package pipeline

import "testing"

func TestExpandSuccessfulIPv4(t *testing.T) {
	got := expandSuccessful([]ProbeResult{{IP: "1.2.3.188", OK: true}}, false)
	if len(got) != 21 {
		t.Fatalf("len=%d", len(got))
	}
	if got[0] != "1.2.3.178" || got[len(got)-1] != "1.2.3.198" {
		t.Fatalf("range=%s..%s", got[0], got[len(got)-1])
	}
}

func TestExpandSuccessfulIPv6(t *testing.T) {
	got := expandSuccessful([]ProbeResult{{IP: "2607:f8b0:400e:c1b::bc", OK: true}}, true)
	if len(got) != 16 {
		t.Fatalf("len=%d", len(got))
	}
	if got[0] != "2607:f8b0:400e:c1b::b0" || got[15] != "2607:f8b0:400e:c1b::bf" {
		t.Fatalf("range=%s..%s", got[0], got[15])
	}
}

func TestTopIPs(t *testing.T) {
	got := topIPs([]ProbeResult{{IP: "1.1.1.1", OK: true, Latency: 20}, {IP: "1.1.1.2", OK: true, Latency: 10}, {IP: "1.1.1.3", OK: false}}, 1)
	if len(got) != 1 || got[0] != "1.1.1.2" {
		t.Fatalf("got=%v", got)
	}
}
