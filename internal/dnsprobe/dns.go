package dnsprobe

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/netip"
	"strings"
	"time"
)

const (
	TypeA    uint16 = 1
	TypeAAAA uint16 = 28
)

type Client struct {
	Timeout time.Duration
}

func (c Client) QueryECS(ctx context.Context, server, name string, qtype uint16, ecsCIDR string) ([]string, error) {
	if c.Timeout == 0 {
		c.Timeout = 5 * time.Second
	}
	id, packet, err := buildQuery(name, qtype, ecsCIDR)
	if err != nil {
		return nil, err
	}
	d := net.Dialer{Timeout: c.Timeout}
	conn, err := d.DialContext(ctx, "udp", net.JoinHostPort(server, "53"))
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(c.Timeout))
	if _, err := conn.Write(packet); err != nil {
		return nil, err
	}
	buf := make([]byte, 4096)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	return parseResponse(buf[:n], id, qtype)
}

func buildQuery(name string, qtype uint16, ecsCIDR string) (uint16, []byte, error) {
	id, err := randomID()
	if err != nil {
		return 0, nil, err
	}
	var out []byte
	out = appendU16(out, id)
	out = appendU16(out, 0x0100)
	out = appendU16(out, 1)
	out = appendU16(out, 0)
	out = appendU16(out, 0)
	out = appendU16(out, 1)
	qname, err := encodeName(name)
	if err != nil {
		return 0, nil, err
	}
	out = append(out, qname...)
	out = appendU16(out, qtype)
	out = appendU16(out, 1)
	ecs, err := encodeECS(ecsCIDR)
	if err != nil {
		return 0, nil, err
	}
	var opts []byte
	opts = appendU16(opts, 8)
	opts = appendU16(opts, uint16(len(ecs)))
	opts = append(opts, ecs...)
	out = append(out, 0)
	out = appendU16(out, 41)
	out = appendU16(out, 1232)
	out = appendU32(out, 0)
	out = appendU16(out, uint16(len(opts)))
	out = append(out, opts...)
	return id, out, nil
}

func randomID() (uint16, error) {
	n, err := rand.Int(rand.Reader, big.NewInt(65536))
	if err != nil {
		return 0, err
	}
	return uint16(n.Int64()), nil
}

func encodeName(name string) ([]byte, error) {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return []byte{0}, nil
	}
	var out []byte
	for _, part := range strings.Split(name, ".") {
		if len(part) == 0 || len(part) > 63 {
			return nil, fmt.Errorf("invalid dns label %q", part)
		}
		out = append(out, byte(len(part)))
		out = append(out, part...)
	}
	out = append(out, 0)
	return out, nil
}

func encodeECS(cidr string) ([]byte, error) {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		return nil, err
	}
	prefix = prefix.Masked()
	addr := prefix.Addr()
	bits := prefix.Bits()
	family := uint16(1)
	var packed []byte
	if addr.Is4() {
		a := addr.As4()
		packed = a[:]
	} else if addr.Is6() {
		family = 2
		a := addr.As16()
		packed = a[:]
	} else {
		return nil, fmt.Errorf("unsupported ECS address %s", cidr)
	}
	n := (bits + 7) / 8
	if n > len(packed) {
		return nil, fmt.Errorf("invalid prefix length %d", bits)
	}
	out := make([]byte, 4+n)
	binary.BigEndian.PutUint16(out[0:2], family)
	out[2] = byte(bits)
	out[3] = 0
	copy(out[4:], packed[:n])
	return out, nil
}

func parseResponse(buf []byte, id, qtype uint16) ([]string, error) {
	if len(buf) < 12 {
		return nil, errors.New("short dns response")
	}
	if binary.BigEndian.Uint16(buf[0:2]) != id {
		return nil, errors.New("dns id mismatch")
	}
	rcode := buf[3] & 0x0f
	if rcode != 0 {
		return nil, fmt.Errorf("dns rcode %d", rcode)
	}
	qd := int(binary.BigEndian.Uint16(buf[4:6]))
	an := int(binary.BigEndian.Uint16(buf[6:8]))
	off := 12
	var err error
	for i := 0; i < qd; i++ {
		off, err = skipName(buf, off)
		if err != nil {
			return nil, err
		}
		off += 4
		if off > len(buf) {
			return nil, errors.New("truncated question")
		}
	}
	var ips []string
	for i := 0; i < an; i++ {
		off, err = skipName(buf, off)
		if err != nil {
			return nil, err
		}
		if off+10 > len(buf) {
			return nil, errors.New("truncated answer")
		}
		typ := binary.BigEndian.Uint16(buf[off : off+2])
		rdlen := int(binary.BigEndian.Uint16(buf[off+8 : off+10]))
		off += 10
		if off+rdlen > len(buf) {
			return nil, errors.New("truncated rdata")
		}
		rdata := buf[off : off+rdlen]
		off += rdlen
		if typ == TypeA && qtype == TypeA && rdlen == net.IPv4len {
			ips = append(ips, net.IP(rdata).String())
		}
		if typ == TypeAAAA && qtype == TypeAAAA && rdlen == net.IPv6len {
			ips = append(ips, net.IP(rdata).String())
		}
	}
	return unique(ips), nil
}

func skipName(buf []byte, off int) (int, error) {
	for {
		if off >= len(buf) {
			return 0, errors.New("truncated name")
		}
		l := buf[off]
		if l&0xc0 == 0xc0 {
			if off+1 >= len(buf) {
				return 0, errors.New("truncated compression")
			}
			return off + 2, nil
		}
		if l == 0 {
			return off + 1, nil
		}
		off += int(l) + 1
	}
}

func appendU16(b []byte, v uint16) []byte {
	return append(b, byte(v>>8), byte(v))
}

func appendU32(b []byte, v uint32) []byte {
	return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

func unique(in []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}
