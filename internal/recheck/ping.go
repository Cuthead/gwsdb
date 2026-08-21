package recheck

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"time"

	"github.com/cuthead/gwsdb/internal/ingest"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
)

// PingCount is the number of ICMP echo requests sent per Ping call,
// any one reply counting as success (fail only when every attempt
// fails). ICMP has no kernel retransmit — one lost datagram fails a
// single-attempt ping outright, and measured GFW path loss toward
// Google ranges is ~25% per datagram. Three application-level retries
// cut the false-failure rate to ~1.6% while staying far below the
// volume that invites ICMP throttling (reply RTT is stable at
// ~250ms when unthrottled, so a lost reply never arrives late).
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
// out anyway. Used as the fallback window when the config carries no
// ScanMaxPingRTT.
const PingTimeout = 2 * time.Second

// PingConfig carries the top-level gscan_quic ping gate settings:
// MaxRTT bounds each attempt's wait (and the overall budget,
// gscan_quic's Ping(ip, gs.ScanMaxPingRTT)), MinRTT flunks
// suspiciously fast replies as forged (gscan_quic's "rtt_too_low").
// Zero/negative values disable each check; MaxRTT <= 0 falls back to
// PingTimeout.
type PingConfig struct {
	MaxRTT time.Duration
	MinRTT time.Duration
}

// pingWindow returns one attempt's wait bound.
func (c PingConfig) pingWindow() time.Duration {
	if c.MaxRTT > 0 {
		return c.MaxRTT
	}
	return PingTimeout
}

// PingBudget is the total time a full Ping call (all PingCount attempts)
// may take with the default window. Callers bounding Ping with a context
// should use cfg.PingBudget(), not PingTimeout, so every attempt gets
// its own window.
const PingBudget = PingTimeout * PingCount

// PingBudget returns the total time a full Ping call (all PingCount
// attempts) may take under this config.
func (c PingConfig) PingBudget() time.Duration {
	return c.pingWindow() * PingCount
}

// PingResult is the outcome of an ICMP echo probe.
type PingResult struct {
	OK    bool
	RTTMs int
	Err   string
}

// Ping sends ICMP echo requests to ip and waits for a reply. It prefers
// raw sockets ("ip4:icmp"/"ip6:ipv6-icmp", root/CAP_NET_RAW) and falls
// back to unprivileged datagram ICMP ("udp4"/"udp6", gid within
// /proc/sys/net/ipv4/ping_group_range) when raw is unavailable — the
// GWSDB_PING_RAW=0 env var forces the datagram path for A/B testing.
// If both fail, Ping returns OK=true so the caller proceeds to the TCP
// probe rather than treating a local socket configuration issue as
// "host unreachable".
func Ping(ctx context.Context, ip string, cfg PingConfig) PingResult {
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		return PingResult{Err: fmt.Sprintf("parse ip: %v", err)}
	}
	window := cfg.pingWindow()

	var bindAddr string
	var reqType, replyType icmp.Type
	var proto int
	if addr.Is4() {
		bindAddr = "0.0.0.0"
		reqType = ipv4.ICMPTypeEcho
		replyType = ipv4.ICMPTypeEchoReply
		proto = protocolICMP
	} else {
		bindAddr = "::"
		reqType = ipv6.ICMPTypeEchoRequest
		replyType = ipv6.ICMPTypeEchoReply
		proto = protocolICMPv6
	}

	rawFirst := os.Getenv("GWSDB_PING_RAW") != "0"

	datagramNetwork := "udp4"
	rawNetwork := "ip4:icmp"
	if !addr.Is4() {
		datagramNetwork = "udp6"
		rawNetwork = "ip6:ipv6-icmp"
	}

	var conn *icmp.PacketConn
	network := rawNetwork
	tryDial := func() error {
		var err error
		conn, err = icmp.ListenPacket(network, bindAddr)
		return err
	}
	if rawFirst {
		if err := tryDial(); err != nil {
			network = datagramNetwork
			err = tryDial()
			if err != nil {
				return PingResult{OK: true, Err: fmt.Sprintf("socket: %v", err)}
			}
		}
	} else {
		network = datagramNetwork
		if err := tryDial(); err != nil {
			network = rawNetwork
			err = tryDial()
			if err != nil {
				return PingResult{OK: true, Err: fmt.Sprintf("socket: %v", err)}
			}
		}
	}
	defer conn.Close()

	// Overall deadline: caller's ctx if it has one, else PingCount windows.
	// Each attempt below gets its own read deadline so one lost reply
	// consumes only its window, not the whole budget.
	deadline, ok := ctx.Deadline()
	if !ok {
		deadline = time.Now().Add(window * PingCount)
	}

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

	var lastErr error
	var lastType icmp.Type
	for range PingCount {
		if !time.Now().Before(deadline) {
			// Overall budget exhausted before this attempt could get a
			// full window — no point sending an echo nobody can wait for.
			break
		}
		start := time.Now()
		_ = conn.SetDeadline(deadline)
		if _, err := conn.WriteTo(body, dstAddr); err != nil {
			lastErr = err
			continue
		}
		// Bound this attempt's read to one window, clamped to the overall
		// deadline; a lost reply costs one window and moves on to the
		// next echo instead of eating the remaining budget.
		readDeadline := time.Now().Add(window)
		if readDeadline.After(deadline) {
			readDeadline = deadline
		}
		_ = conn.SetReadDeadline(readDeadline)
		buf := make([]byte, 1500)
		n, from, err := conn.ReadFrom(buf)
		if err != nil {
			lastErr = err
			continue
		}
		payload := buf[:n]
		if network == rawNetwork && addr.Is4() {
			// Linux raw v4 sockets deliver the whole IP packet; macOS/BSD
			// strip the header in the kernel. Detect by the IPv4 version
			// nibble instead of trusting the platform: an IP header starts
			// 0x4x, bare ICMP starts with the type byte (echo reply = 0).
			// Raw v6 sockets never include the IPv6 header (RFC 3542), so
			// no stripping there.
			if len(payload) >= 20 && payload[0]>>4 == 4 {
				payload = payload[payload[0]&0x0f*4:]
			}
		}
		// Raw sockets see every ICMP packet on the wire (not just ours),
		// so match the reply against both the expected type and the
		// probed address to avoid crediting someone else's echo.
		if fromAddr, ok := from.(*net.IPAddr); ok && network == rawNetwork && !fromAddr.IP.Equal(net.ParseIP(addr.String())) {
			continue
		}
		rm, err := icmp.ParseMessage(proto, payload)
		if err != nil {
			lastErr = err
			continue
		}
		if rm.Type == replyType {
			rtt := time.Since(start)
			// gscan_quic's ScanMinPingRTT gate: a reply faster than
			// physically possible is treated as a forged/injected one —
			// keep waiting instead of crediting it.
			if cfg.MinRTT > 0 && rtt < cfg.MinRTT {
				continue
			}
			return PingResult{OK: true, RTTMs: int(rtt.Milliseconds())}
		}
		lastType = rm.Type
	}
	if lastErr != nil {
		return PingResult{Err: ingest.SanitizeNetErr(lastErr.Error())}
	}
	if lastType != nil {
		return PingResult{Err: fmt.Sprintf("got icmp %v", lastType)}
	}
	return PingResult{Err: ingest.SanitizeNetErr(os.ErrDeadlineExceeded.Error())}
}
