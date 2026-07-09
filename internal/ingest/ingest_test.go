package ingest

import "testing"

func TestSanitizeNetErr(t *testing.T) {
	cases := []struct{ in, want string }{
		{
			"read ip4 192.168.1.110->74.125.207.126: i/o timeout",
			"read ip4 74.125.207.126: i/o timeout",
		},
		{
			"read tcp [2001:db8::a1]:52344->[2404:6800:4004::5e]:443: i/o timeout",
			"read tcp [2404:6800:4004::5e]:443: i/o timeout",
		},
		{
			"write udp 10.0.0.2:5353->8.8.8.8:53: broken pipe",
			"write udp 8.8.8.8:53: broken pipe",
		},
		{
			"dial tcp 74.125.207.126:443: connect: connection refused",
			"dial tcp 74.125.207.126:443: connect: connection refused",
		},
		{
			"sni=example.com error=read ip6 [2001:db8::a1]:5000->[2404::1]:443: i/o timeout",
			"sni=example.com error=read ip6 [2404::1]:443: i/o timeout",
		},
		{
			"tls: handshake failure",
			"tls: handshake failure",
		},
	}
	for _, c := range cases {
		if got := SanitizeNetErr(c.in); got != c.want {
			t.Errorf("SanitizeNetErr(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}
