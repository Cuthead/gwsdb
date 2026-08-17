package recheck

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// PingCount is the number of ICMP echo requests sent per Ping call
// (matches gscan_quic's ScanCountPerIP convention — a few attempts so
// transient packet loss doesn't flunk an otherwise-reachable IP).
const PingCount = 3

// IANA protocol numbers used by icmp.ParseMessage.
const (
	protocolICMP   = 1  // IPv4 ICMP
	protocolICMPv6 = 58 // IPv6 ICMP
)

// PingTimeout bounds a single Ping call (all PingCount attempts
// together). It's deliberately short: this is a reachability gate for
// the TCP/SNI probe, not a latency measurement — a slow ping means
// the path is congested enough that the SNI probe would likely time
// out anyway.
const PingTimeout = 2 * time.Second

// PingResult is the outcome of an ICMP echo probe.
type PingResult struct {
	OK    bool
	RTTMs int
	Err   string
}

// Ping sends ICMP echo requests to ip and waits for a reply. It uses
// unprivileged ICMP (SOCK_DGRAM) via "udp4"/"udp6" so it does NOT need
// root — on Linux the process just needs its gid in
// /proc/sys/net/ipv4/ping_group_range (default 0 2147483647, i.e. all
// groups). If unprivileged sockets fail, it falls back to raw sockets
// ("ip4:icmp"/"ip6:ipv6-icmp") if running as root. If both fail, Ping
// returns OK=true so the caller proceeds to the TCP probe rather than
// treating a local socket configuration issue as "host unreachable".
func Ping(ctx context.Context, ip string) PingResult {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return PingResult{Err: fmt.Sprintf("parse ip: %v", err)}
	}

	var network, bindAddr string
	var reqType, replyType icmp.Type
	var proto int
	if addr.Is4() {
		network = "udp4"
		bindAddr = "0.0.0.0"
		reqType = ipv4.ICMPTypeEcho
		replyType = ipv4.ICMPTypeEchoReply
		proto = protocolICMP
	} else {
		network = "udp6"
		bindAddr = "::"
		reqType = ipv6.ICMPTypeEchoRequest
		replyType = ipv6.ICMPTypeEchoReply
		proto = protocolICMPv6
	}

	conn, err := icmp.ListenPacket(network, bindAddr)
	if err != nil {
		// Fallback to raw socket if running with root / CAP_NET_RAW.
		if addr.Is4() {
			network = "ip4:icmp"
		} else {
			network = "ip6:ipv6-icmp"
		}
		conn, err = icmp.ListenPacket(network, bindAddr)
		if err != nil {
			// Can't open either ICMP socket type — treat as "ping unavailable,
			// don't gate" rather than marking the remote IP unreachable.
			return PingResult{OK: true, Err: fmt.Sprintf("socket: %v", err)}
		}
	}
	defer conn.Close()

	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(PingTimeout)
	}
	_ = conn.SetDeadline(deadline)

	echo := icmp.Echo{ID: os.Getpid() & 0xffff, Seq: 1, Data: []byte("gwsdb-ping")}
	body, err := (&icmp.Message{Type: reqType, Code: 0, Body: &echo}).Marshal(nil)
	if err != nil {
		return PingResult{Err: fmt.Sprintf("marshal: %v", err)}
	}

	var dstAddr net.Addr
	if network == "udp4" || network == "udp6" {
		dstAddr = &net.UDPAddr{IP: net.ParseIP(addr.String())}
	} else {
		dstAddr = &net.IPAddr{IP: net.ParseIP(addr.String())}
	}

	for range PingCount {
		start := time.Now()
		if _, err := conn.WriteTo(body, dstAddr); err != nil {
			continue
		}
		buf := make([]byte, 1500)
		n, _, err := conn.ReadFrom(buf)
		if err != nil {
			continue
		}
		rm, err := icmp.ParseMessage(proto, buf[:n])
		if err != nil {
			continue
		}
		if rm.Type == replyType {
			return PingResult{OK: true, RTTMs: int(time.Since(start).Milliseconds())}
		}
	}
	return PingResult{Err: "no reply"}
}
