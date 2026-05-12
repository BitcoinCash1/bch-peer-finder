// peer.go — Per-peer evaluation: handshake, getaddr, mempool probe, ping RTT.
package main

import (
	"context"
	"encoding/binary"
	"errors"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"time"
)

// PeerResult is the outcome of probing one peer.
type PeerResult struct {
	Address         string    `json:"address"`
	Timestamp       time.Time `json:"timestamp"`
	HandshakeOK     bool      `json:"handshake_ok"`
	ProtocolVersion int32     `json:"protocol_version"`
	Services        uint64    `json:"services"`
	UserAgent       string    `json:"user_agent"`
	StartHeight     int32     `json:"start_height"`
	MempoolCount    int       `json:"mempool_count"`
	AddrsReceived   int       `json:"addrs_received"`
	LatencyMs       int       `json:"latency_ms"`
	Score           int       `json:"score"`
	Software        Software  `json:"software"`
	Error           string    `json:"error,omitempty"`
}

// evaluatePeer probes a single peer and returns a PeerResult.
//
// Phases:
//  1. TCP dial (5s timeout)
//  2. Send version, await peer's version, send sendaddrv2 + verack
//  3. Send filterload + mempool + getaddr + ping
//  4. Read messages for `probeWindow`, collecting addr/inv/pong data
//
// New peer addresses we learn via addr/addrv2 are pushed into the AddrManager.
// When acceptIPv6 is false (default), only routable IPv4 peers are admitted —
// this matches the original behaviour. Set it to true to also accept IPv6.
func evaluatePeer(ctx context.Context, address string, am *AddrManager, probeWindow time.Duration, acceptIPv6 bool) PeerResult {
	res := PeerResult{Address: address, Timestamp: time.Now()}

	tcpAddr, err := net.ResolveTCPAddr("tcp", address)
	if err != nil {
		res.Error = "resolve: " + err.Error()
		return res
	}

	// Phase 1 — connect
	dialer := net.Dialer{Timeout: 5 * time.Second}
	conn, err := dialer.DialContext(ctx, "tcp", address)
	if err != nil {
		res.Error = "dial: " + err.Error()
		return res
	}
	defer conn.Close()

	// Hard cap on total time spent on this peer.
	totalDeadline := time.Now().Add(5*time.Second + probeWindow + 5*time.Second)
	_ = conn.SetDeadline(totalDeadline)

	// Phase 2 — version handshake.
	ourNonce := rand.Uint64()
	verPayload := buildVersion(tcpAddr, ourNonce, "/bch-peer-finder:0.1.0/", 0, time.Now().Unix())
	if err := writeMessage(conn, "version", verPayload); err != nil {
		res.Error = "send version: " + err.Error()
		return res
	}

	theirVersion, err := readUntilVersion(conn)
	if err != nil {
		res.Error = "recv version: " + err.Error()
		return res
	}

	// Per BIP-155, sendaddrv2 must arrive between version and verack.
	_ = writeMessage(conn, "sendaddrv2", nil)
	if err := writeMessage(conn, "verack", nil); err != nil {
		res.Error = "send verack: " + err.Error()
		return res
	}

	res.HandshakeOK = true
	res.ProtocolVersion = theirVersion.Version
	res.Services = theirVersion.Services
	res.UserAgent = theirVersion.UserAgent
	res.StartHeight = theirVersion.StartHeight

	// Phase 3 — request data.
	// filterload first so the mempool command will be honoured.
	_ = writeMessage(conn, "filterload", buildMatchAllFilter())
	_ = writeMessage(conn, "mempool", nil)
	_ = writeMessage(conn, "getaddr", nil)

	pingNonce := rand.Uint64()
	pingPayload := make([]byte, 8)
	binary.LittleEndian.PutUint64(pingPayload, pingNonce)
	pingSent := time.Now()
	_ = writeMessage(conn, "ping", pingPayload)

	// Phase 4 — read messages for the probe window.
	probeDeadline := time.Now().Add(probeWindow)
	_ = conn.SetReadDeadline(probeDeadline)

	gotPong := false
	for time.Now().Before(probeDeadline) {
		cmd, payload, err := readMessage(conn)
		if err != nil {
			break
		}
		switch cmd {

		case "addr":
			if addrs, err := decodeAddr(payload); err == nil {
				for _, a := range addrs {
					if s, ok := admitPeerAddr(a, acceptIPv6); ok {
						am.Add(s)
						res.AddrsReceived++
					}
				}
			}

		case "addrv2":
			if addrs, err := decodeAddrV2(payload); err == nil {
				for _, a := range addrs {
					if s, ok := admitPeerAddr(a, acceptIPv6); ok {
						am.Add(s)
						res.AddrsReceived++
					}
				}
			}

		case "inv":
			if n, err := decodeInvTxCount(payload); err == nil {
				res.MempoolCount += n
			}

		case "pong":
			if !gotPong && len(payload) >= 8 {
				if binary.LittleEndian.Uint64(payload[:8]) == pingNonce {
					res.LatencyMs = int(time.Since(pingSent).Milliseconds())
					gotPong = true
				}
			}

		case "ping":
			// Be polite — echo the nonce back so the peer doesn't drop us.
			_ = writeMessage(conn, "pong", payload)

		default:
			// Drain anything else (sendcmpct, feefilter, sendheaders, xversion …).
		}
	}

	return res
}

// isRoutableIPv4 returns true when ip is a public, dialable IPv4 address.
// We drop loopback, unspecified (0.0.0.0), link-local, multicast, broadcast,
// and RFC 1918 private ranges — none of which make sense as `addnode=` peers.
func isRoutableIPv4(ip net.IP) bool {
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsPrivate() {
		return false
	}
	if v4[0] == 0 || v4[0] == 127 || v4[0] >= 224 { // 0.x, 127.x, multicast/reserved
		return false
	}
	if v4[0] == 169 && v4[1] == 254 { // link-local already caught, belt+braces
		return false
	}
	if v4[0] == 100 && v4[1] >= 64 && v4[1] <= 127 { // CGNAT 100.64.0.0/10
		return false
	}
	return true
}

// isRoutableIPv6 returns true when ip is a public, dialable IPv6 address.
// Drops loopback (::1), unspecified (::), link-local (fe80::/10), unique-local
// (fc00::/7), multicast, IPv4-mapped (::ffff:0:0/96), documentation (2001:db8::/32)
// and the discard prefix (100::/64). 6to4 / Teredo (2002::/16, 2001::/32) are
// kept — they're publicly routable even if not ideal.
func isRoutableIPv6(ip net.IP) bool {
	if ip.To4() != nil {
		return false // not an IPv6 address
	}
	v16 := ip.To16()
	if v16 == nil {
		return false
	}
	if ip.IsLoopback() || ip.IsUnspecified() ||
		ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsInterfaceLocalMulticast() || ip.IsMulticast() ||
		ip.IsPrivate() {
		return false
	}
	// 2001:db8::/32 documentation prefix
	if v16[0] == 0x20 && v16[1] == 0x01 && v16[2] == 0x0d && v16[3] == 0xb8 {
		return false
	}
	// 100::/64 discard-only address block
	if v16[0] == 0x01 && v16[1] == 0x00 &&
		v16[2] == 0 && v16[3] == 0 && v16[4] == 0 && v16[5] == 0 &&
		v16[6] == 0 && v16[7] == 0 {
		return false
	}
	return true
}

// admitPeerAddr decides whether a peer learned via addr/addrv2 should be
// pushed back into the AddrManager, returning the canonical "ip:port" form
// (IPv6 properly bracketed) when the address passes routability checks.
// IPv6 admission is gated on acceptIPv6 so the default crawl stays IPv4-only.
func admitPeerAddr(a PeerAddr, acceptIPv6 bool) (string, bool) {
	if v4 := a.IP.To4(); v4 != nil {
		if !isRoutableIPv4(v4) {
			return "", false
		}
		return net.JoinHostPort(v4.String(), strconv.Itoa(int(a.Port))), true
	}
	if !acceptIPv6 {
		return "", false
	}
	if !isRoutableIPv6(a.IP) {
		return "", false
	}
	return net.JoinHostPort(a.IP.String(), strconv.Itoa(int(a.Port))), true
}

// readUntilVersion drains messages until we see a `version`. Useful when peers
// send sendaddrv2/wtxidrelay or other handshake frames before/after version.
func readUntilVersion(conn net.Conn) (*VersionInfo, error) {
	for i := 0; i < 10; i++ {
		cmd, payload, err := readMessage(conn)
		if err != nil {
			return nil, err
		}
		if cmd == "version" {
			return decodeVersion(payload)
		}
	}
	return nil, errors.New("no version message in first 10 frames")
}

// ---------------------------------------------------------------------------
// Filtering + scoring
// ---------------------------------------------------------------------------

// Software represents a BCH client implementation.
type Software int

const (
	SoftwareUnknown Software = iota
	SoftwareBCHN
	SoftwareBchd
	SoftwareKnuth
)

func (s Software) String() string {
	switch s {
	case SoftwareBCHN:
		return "bchn"
	case SoftwareBchd:
		return "bchd"
	case SoftwareKnuth:
		return "knuth"
	default:
		return "unknown"
	}
}

// isBCHUserAgent returns true if a user-agent string belongs to a real BCH
// implementation. Critical: BSV and eCash share BCH's magic bytes so we MUST
// disambiguate here, otherwise the output would be polluted with wrong-chain
// nodes that an `addnode=` directive can't talk to.
func isBCHUserAgent(ua string) bool {
	if ua == "" {
		return false
	}
	lower := strings.ToLower(ua)

	// Hard rejects — these are other chains masquerading on shared magic.
	// (BSV, eCash, and Bitcoin ABC all share BCH's network magic bytes
	// because they forked from BCH. Magic-byte matching alone is not
	// enough to identify the chain — user-agent is.)
	badSubstr := []string{
		"bitcoin sv", "/sv:", "bsv",
		"ecash", "/abc:", "bitcoin abc",
		"bitcoin not abc",
	}
	for _, b := range badSubstr {
		if strings.Contains(lower, b) {
			return false
		}
	}

	// Whitelist of confirmed BCH clients
	goodSubstr := []string{
		"bitcoin cash node", // BCHN
		"bchn",
		"bchd",
		"bch unlimited", // Bitcoin Unlimited's BCH client
		"flowee",        // Flowee the Hub (BCH)
		"bitcoin verde", // Verde (BCH)
		"knuth",         // Knuth (kth)
	}
	for _, g := range goodSubstr {
		if strings.Contains(lower, g) {
			return true
		}
	}

	return false
}

// parseVersion extracts major.minor.patch from user-agent string like "/Bitcoin Cash Node:29.0.0(EB32.0)/"
func parseVersion(ua string) (major, minor, patch int) {
	colonIndex := strings.Index(ua, ":")
	if colonIndex == -1 {
		return 0, 0, 0
	}
	versionStr := ua[colonIndex+1:]
	endIndex := strings.IndexAny(versionStr, "(/")
	if endIndex != -1 {
		versionStr = versionStr[:endIndex]
	}
	parts := strings.Split(versionStr, ".")
	if len(parts) >= 1 {
		major, _ = strconv.Atoi(parts[0])
	}
	if len(parts) >= 2 {
		minor, _ = strconv.Atoi(parts[1])
	}
	if len(parts) >= 3 {
		patch, _ = strconv.Atoi(parts[2])
	}
	return
}

// computeScore turns a probe result into a single integer for ranking.
//
// Heuristic (tunable in main):
//
//	mempool_count        →  *2  (the headline signal; well-synced ⇒ big mempool)
//	NODE_NETWORK         →  +700
//	NODE_BITCOIN_CASH    →  +400
//	BCHN client          →  +650 + version_bonus (0-100 relative to peers)
//	bchd  client         →  +500 + version_bonus (0-100 relative to peers)
//	knuth  client        →  +500 + version_bonus (0-100 relative to peers)
//	tip within 6 blocks  →  +2000  (≤100 still gets +1000; >1000 zeros score)
//	addrs shared         →  + min(2*n, 200)  (signals willingness to gossip)
//	protocol ≥ 70015     →  +100
//	latency penalty      →  -ms/5
//	addrs shared         →  + min(2*n, 200)  (signals willingness to gossip)
//	protocol ≥ 70015     →  +100
//	latency penalty      →  -ms/5
func computeScore(r *PeerResult, refHeight int32, versionStats map[Software]struct{ min, max int }) int {
	if !r.HandshakeOK || !isBCHUserAgent(r.UserAgent) {
		return 0
	}

	score := r.MempoolCount * 2
	if r.MempoolCount > 100 {
		score += 500 // bonus for clearly non-empty mempool
	}

	if r.Services&NodeNetwork != 0 {
		score += 700
	}
	// BitcoinCash does not bloom filtered connections anymore since protocol version 70011
	// if r.Services&NodeBloom != 0 {
	// 	score += 200
	// }
	if r.Services&NodeBitcoinCash != 0 {
		score += 400
	}

	// Extra points for known-good BCH implementations, fully up-to-date spec.
	switch r.Software {
	case SoftwareBCHN:
		score += 650
	case SoftwareBchd:
		score += 500
	case SoftwareKnuth:
		score += 500
	}

	// Version bonus: relative within software (0-100 points)
	if r.Software != SoftwareUnknown && versionStats != nil {
		if stats, ok := versionStats[r.Software]; ok && stats.max > stats.min {
			major, _, _ := parseVersion(r.UserAgent)
			bonus := ((major - stats.min) * 100) / (stats.max - stats.min)
			score += bonus
		}
	}

	if refHeight > 0 && r.StartHeight > 0 {
		diff := refHeight - r.StartHeight
		if diff < 0 {
			diff = -diff
		}
		switch {
		case diff <= 6:
			score += 2000
		case diff <= 100:
			score += 1000
		case diff > 1000:
			return 0 // far behind — useless as addnode peer
		}
	}

	if r.AddrsReceived > 0 {
		bonus := 2 * r.AddrsReceived
		if bonus > 200 {
			bonus = 200
		}
		score += bonus
	}

	if r.ProtocolVersion >= 70015 {
		score += 100
	}

	if r.LatencyMs > 0 {
		score -= r.LatencyMs / 5
	}

	if score < 0 {
		score = 0
	}
	return score
}
