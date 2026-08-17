package scan

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

// TestRandomAddrInPrefix verifies the random-IP-in-CIDR logic stays
// inside the prefix and preserves the address family, across several
// v4 and v6 prefix lengths (including byte-aligned and non-aligned).
func TestRandomAddrInPrefix(t *testing.T) {
	cases := []string{
		"35.191.0.0/16",          // v4 byte-aligned
		"64.233.160.0/19",        // v4 non-aligned (3-bit host in byte 2)
		"203.0.113.42/32",        // v4 single host
		"2001:4860:4001:3::/120", // v6 byte-aligned, 256 hosts
		"2404:6800:4000:800::/64", // v6 large
	}
	for _, cidr := range cases {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			t.Fatalf("parse %s: %v", cidr, err)
		}
		prefix = prefix.Masked()
		want4 := prefix.Addr().Is4()
		for i := 0; i < 200; i++ {
			addr := randomAddrInPrefix(prefix)
			if !prefix.Contains(addr) {
				t.Errorf("%s: addr %s outside prefix", cidr, addr)
			}
			if addr.Is4() != want4 {
				t.Errorf("%s: addr %s family mismatch (want v4=%v)", cidr, addr, want4)
			}
		}
	}
}

// TestLoadIPRangesReal loads the actual gscan_quic range files (v4 + v6)
// from ~/gscan_quic/iprange/ if present, and checks GetIP returns
// parseable addresses of the right family. Skipped on machines without
// those files (e.g. CI, the Cloudflare side) — it's a smoke test of the
// real data shape, not a unit test.
func TestLoadIPRangesReal(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home dir")
	}
	v4Path := filepath.Join(home, "gscan_quic", "iprange", "iprange_gws_a.txt")
	v6Path := filepath.Join(home, "gscan_quic", "iprange", "iprange_gws_6_a.txt")
	if _, err := os.Stat(v4Path); err != nil {
		t.Skipf("no %s", v4Path)
	}
	if _, err := os.Stat(v6Path); err != nil {
		t.Skipf("no %s", v6Path)
	}

	// v4 only
	src, err := LoadIPRanges([]string{v4Path})
	if err != nil {
		t.Fatalf("load v4: %v", err)
	}
	if src.Len() == 0 {
		t.Fatal("v4 loaded 0 prefixes")
	}
	for i := 0; i < 50; i++ {
		ip := src.GetIP()
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			t.Errorf("v4 GetIP %q: %v", ip, err)
		}
		if !addr.Is4() {
			t.Errorf("v4 GetIP %q: not v4", ip)
		}
	}

	// v4 + v6 mixed (the scanner's actual config)
	mixed, err := LoadIPRanges([]string{v4Path, v6Path})
	if err != nil {
		t.Fatalf("load mixed: %v", err)
	}
	if mixed.Len() <= src.Len() {
		t.Fatalf("mixed (%d) should have more prefixes than v4-only (%d)", mixed.Len(), src.Len())
	}
	saw4, saw6 := false, false
	for i := 0; i < 500; i++ {
		addr, err := netip.ParseAddr(mixed.GetIP())
		if err != nil {
			t.Errorf("mixed GetIP: %v", err)
			continue
		}
		if addr.Is4() {
			saw4 = true
		} else {
			saw6 = true
		}
	}
	if !saw4 {
		t.Error("mixed source never returned a v4 address in 500 draws")
	}
	if !saw6 {
		t.Error("mixed source never returned a v6 address in 500 draws")
	}
}
