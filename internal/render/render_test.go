package render

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cagedbird043/fcm-hosts-next/internal/pipeline"
)

func TestWriteAllDualStack(t *testing.T) {
	dir := t.TempDir()
	r := pipeline.Result{SeedV4: 2, SeedV6: 2, SelectedV4: []pipeline.Candidate{{IP: "1.1.1.1", Samples: 20}}, SelectedV6: []pipeline.Candidate{{IP: "2001:db8::1", Samples: 20}}}
	if err := WriteAll(dir, r); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "fcm_dual.hosts"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	for _, want := range []string{"# Type: Dual Stack (IPv4 + IPv6)", "# Seeds: IPv4=2, IPv6=2", "1.1.1.1 mtalk.google.com", "2001:db8::1 mtalk.google.com"} {
		if !strings.Contains(s, want) {
			t.Fatalf("missing %q in\n%s", want, s)
		}
	}
}
