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
		"35.191.0.0/16",           // v4 byte-aligned
		"64.233.160.0/19",         // v4 non-aligned (3-bit host in byte 2)
		"203.0.113.42/32",         // v4 single host
		"2001:4860:4001:3::/120",  // v6 byte-aligned, 256 hosts
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

func TestIPRangeFamilySelection(t *testing.T) {
	path := filepath.Join(t.TempDir(), "ranges.txt")
	if err := os.WriteFile(path, []byte("192.0.2.0/24\n2001:db8::/120\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	src, err := LoadIPRanges([]string{path})
	if err != nil {
		t.Fatal(err)
	}

	for name, test := range map[string]struct {
		getIP func() (string, bool)
		is4   bool
	}{
		"IPv4": {src.GetIPv4, true},
		"IPv6": {src.GetIPv6, false},
	} {
		t.Run(name, func(t *testing.T) {
			for range 100 {
				ip, ok := test.getIP()
				if !ok {
					t.Fatal("returned no address")
				}
				addr, err := netip.ParseAddr(ip)
				if err != nil {
					t.Fatal(err)
				}
				if addr.Is4() != test.is4 {
					t.Fatalf("returned wrong address family: %s", ip)
				}
			}
		})
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
		ip, ok := src.GetIPv4()
		if !ok {
			t.Fatal("GetIPv4 returned no address")
		}
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
	for name, getIP := range map[string]func() (string, bool){
		"v4": mixed.GetIPv4,
		"v6": mixed.GetIPv6,
	} {
		ip, ok := getIP()
		if !ok {
			t.Fatalf("mixed GetIP%s returned no address", name)
		}
		addr, err := netip.ParseAddr(ip)
		if err != nil {
			t.Fatalf("mixed GetIP%s: %v", name, err)
		}
		if (name == "v4") != addr.Is4() {
			t.Errorf("mixed GetIP%s returned %s", name, ip)
		}
	}
}
