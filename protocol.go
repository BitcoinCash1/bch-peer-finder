// protocol.go — Bitcoin Cash P2P wire protocol primitives.
//
// References:
//   - https://github.com/gcash/bchd/blob/master/wire
//   - https://reference.cash/protocol/network/messages
//   - BCHN src/protocol.h, src/net_processing.cpp
//   - BIP-155 (addrv2)
package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
)

// MainnetMagic is the BCH mainnet network magic (on the wire, little-endian).
// In BCHN chainparams.cpp: pchMessageStart = {0xe3, 0xe1, 0xf3, 0xe8}.
// Note: BSV and eCash share these magic bytes (both forked from BCH).
// We disambiguate by user-agent string later.
var MainnetMagic = [4]byte{0xe3, 0xe1, 0xf3, 0xe8}

const (
	HeaderSize     = 24
	CommandSize    = 12
	MaxMessageSize = 32 * 1024 * 1024 // 32 MiB

	// Service flags (from BCHN src/protocol.h ServiceFlags)
	NodeNetwork        uint64 = 1 << 0
	NodeGetUTXO        uint64 = 1 << 1
	NodeBloom          uint64 = 1 << 2 // Not used in Bitcoin Cash anymore (BCHN)
	NodeXThin          uint64 = 1 << 4
	NodeBitcoinCash    uint64 = 1 << 5 // a.k.a. NODE_CASH
	NodeGraphene       uint64 = 1 << 6
	NodeNetworkLimited uint64 = 1 << 10

	// Inventory types
	InvTx           uint32 = 1
	InvBlock        uint32 = 2
	InvFilteredBlk  uint32 = 3
	InvCompactBlock uint32 = 4

	// Try to use the latest protocol version (both BCHN and BCHD should support this)
	ProtocolVersion int32 = 70016
)

// ---------------------------------------------------------------------------
// Hashing / checksums
// ---------------------------------------------------------------------------

func doubleSHA256(b []byte) [32]byte {
	h1 := sha256.Sum256(b)
	return sha256.Sum256(h1[:])
}

func payloadChecksum(payload []byte) [4]byte {
	h := doubleSHA256(payload)
	var c [4]byte
	copy(c[:], h[:4])
	return c
}

// ---------------------------------------------------------------------------
// Message framing
// ---------------------------------------------------------------------------

// writeMessage frames and writes a single P2P message.
func writeMessage(w io.Writer, command string, payload []byte) error {
	if len(command) > CommandSize {
		return fmt.Errorf("command %q too long", command)
	}
	var header [HeaderSize]byte
	copy(header[0:4], MainnetMagic[:])
	copy(header[4:4+CommandSize], command) // null-padded by the zero array
	binary.LittleEndian.PutUint32(header[16:20], uint32(len(payload)))
	cs := payloadChecksum(payload)
	copy(header[20:24], cs[:])

	if _, err := w.Write(header[:]); err != nil {
		return err
	}
	if len(payload) > 0 {
		if _, err := w.Write(payload); err != nil {
			return err
		}
	}
	return nil
}

// readMessage reads and validates a single P2P message frame.
func readMessage(r io.Reader) (string, []byte, error) {
	var header [HeaderSize]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return "", nil, err
	}
	if !bytes.Equal(header[0:4], MainnetMagic[:]) {
		return "", nil, fmt.Errorf("bad magic %x", header[0:4])
	}
	cmdBytes := header[4 : 4+CommandSize]
	nul := bytes.IndexByte(cmdBytes, 0)
	if nul < 0 {
		nul = CommandSize
	}
	command := string(cmdBytes[:nul])

	length := binary.LittleEndian.Uint32(header[16:20])
	if length > MaxMessageSize {
		return command, nil, fmt.Errorf("oversize msg %d", length)
	}
	var wantCS [4]byte
	copy(wantCS[:], header[20:24])

	payload := make([]byte, length)
	if length > 0 {
		if _, err := io.ReadFull(r, payload); err != nil {
			return command, nil, err
		}
		if payloadChecksum(payload) != wantCS {
			return command, nil, errors.New("checksum mismatch")
		}
	}
	return command, payload, nil
}

// ---------------------------------------------------------------------------
// Compact-size (varint) encoding
// ---------------------------------------------------------------------------

func readVarInt(r io.Reader) (uint64, error) {
	var b [1]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, err
	}
	switch b[0] {
	case 0xff:
		var buf [8]byte
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return 0, err
		}
		return binary.LittleEndian.Uint64(buf[:]), nil
	case 0xfe:
		var buf [4]byte
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return 0, err
		}
		return uint64(binary.LittleEndian.Uint32(buf[:])), nil
	case 0xfd:
		var buf [2]byte
		if _, err := io.ReadFull(r, buf[:]); err != nil {
			return 0, err
		}
		return uint64(binary.LittleEndian.Uint16(buf[:])), nil
	default:
		return uint64(b[0]), nil
	}
}

func writeVarInt(w io.Writer, n uint64) error {
	switch {
	case n < 0xfd:
		_, err := w.Write([]byte{byte(n)})
		return err
	case n <= 0xffff:
		buf := [3]byte{0xfd}
		binary.LittleEndian.PutUint16(buf[1:], uint16(n))
		_, err := w.Write(buf[:])
		return err
	case n <= 0xffffffff:
		buf := [5]byte{0xfe}
		binary.LittleEndian.PutUint32(buf[1:], uint32(n))
		_, err := w.Write(buf[:])
		return err
	default:
		buf := [9]byte{0xff}
		binary.LittleEndian.PutUint64(buf[1:], n)
		_, err := w.Write(buf[:])
		return err
	}
}

func writeVarString(w io.Writer, s string) error {
	if err := writeVarInt(w, uint64(len(s))); err != nil {
		return err
	}
	_, err := w.Write([]byte(s))
	return err
}

func readVarString(r io.Reader, maxLen uint64) (string, error) {
	n, err := readVarInt(r)
	if err != nil {
		return "", err
	}
	if n > maxLen {
		return "", fmt.Errorf("var string len %d > %d", n, maxLen)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return "", err
	}
	return string(buf), nil
}

// ---------------------------------------------------------------------------
// version / verack
// ---------------------------------------------------------------------------

// VersionInfo is what we keep from the peer's version message.
type VersionInfo struct {
	Version     int32
	Services    uint64
	Timestamp   int64
	UserAgent   string
	StartHeight int32
	Relay       bool
}

// netAddr is the 26-byte network-address sub-record used inside the version
// message (no timestamp).
type netAddr struct {
	Services uint64
	IP       [16]byte // IPv4 stored as IPv4-mapped IPv6
	Port     uint16   // big-endian on the wire
}

func (a netAddr) encode(buf *bytes.Buffer) {
	_ = binary.Write(buf, binary.LittleEndian, a.Services)
	buf.Write(a.IP[:])
	_ = binary.Write(buf, binary.BigEndian, a.Port)
}

// buildVersion constructs the payload of a `version` message we initiate.
func buildVersion(remote *net.TCPAddr, nonce uint64, userAgent string, startHeight int32, ts int64) []byte {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.LittleEndian, ProtocolVersion)
	_ = binary.Write(&buf, binary.LittleEndian, uint64(0)) // our services: 0 (we don't serve)
	_ = binary.Write(&buf, binary.LittleEndian, ts)

	// addr_recv (the peer, as we perceive them)
	recv := netAddr{Services: NodeNetwork | NodeBitcoinCash}
	if remote != nil {
		copy(recv.IP[:], to16(remote.IP))
		recv.Port = uint16(remote.Port)
	}
	recv.encode(&buf)

	// addr_from (us — we lie / leave blank, common practice)
	from := netAddr{}
	from.encode(&buf)

	_ = binary.Write(&buf, binary.LittleEndian, nonce)
	_ = writeVarString(&buf, userAgent)
	_ = binary.Write(&buf, binary.LittleEndian, startHeight)
	buf.WriteByte(0) // relay = false (we don't want unsolicited txs)
	return buf.Bytes()
}

// decodeVersion parses a peer's version message payload.
func decodeVersion(payload []byte) (*VersionInfo, error) {
	r := bytes.NewReader(payload)
	v := &VersionInfo{}
	if err := binary.Read(r, binary.LittleEndian, &v.Version); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &v.Services); err != nil {
		return nil, err
	}
	if err := binary.Read(r, binary.LittleEndian, &v.Timestamp); err != nil {
		return nil, err
	}
	// skip addr_recv (26 bytes) and addr_from (26 bytes)
	skip := make([]byte, 26)
	if _, err := io.ReadFull(r, skip); err != nil {
		return nil, err
	}
	if r.Len() >= 26 {
		if _, err := io.ReadFull(r, skip); err != nil {
			return nil, err
		}
	}
	// nonce
	if r.Len() >= 8 {
		var nonce uint64
		if err := binary.Read(r, binary.LittleEndian, &nonce); err != nil {
			return nil, err
		}
	}
	// user agent
	if r.Len() > 0 {
		ua, err := readVarString(r, 256)
		if err == nil {
			v.UserAgent = ua
		}
	}
	if r.Len() >= 4 {
		_ = binary.Read(r, binary.LittleEndian, &v.StartHeight)
	}
	if r.Len() >= 1 {
		var b byte
		_ = binary.Read(r, binary.LittleEndian, &b)
		v.Relay = b != 0
	} else {
		v.Relay = true // legacy default
	}
	return v, nil
}

// ---------------------------------------------------------------------------
// addr (legacy) and addrv2 (BIP-155)
// ---------------------------------------------------------------------------

// PeerAddr is what we extract from addr / addrv2 messages.
type PeerAddr struct {
	IP   net.IP
	Port uint16
}

func decodeAddr(payload []byte) ([]PeerAddr, error) {
	r := bytes.NewReader(payload)
	count, err := readVarInt(r)
	if err != nil {
		return nil, err
	}
	if count > 1000 {
		return nil, fmt.Errorf("addr count %d > 1000", count)
	}
	out := make([]PeerAddr, 0, count)
	for i := uint64(0); i < count; i++ {
		var raw [30]byte // 4 ts + 8 svc + 16 ip + 2 port
		if _, err := io.ReadFull(r, raw[:]); err != nil {
			return out, err
		}
		ip := make(net.IP, 16)
		copy(ip, raw[12:28])
		port := binary.BigEndian.Uint16(raw[28:30])
		if port == 0 {
			continue
		}
		// If this is an IPv4-mapped IPv6 address, unwrap it so the caller
		// can cheaply tell the two families apart with ip.To4().
		if v4 := ip.To4(); v4 != nil {
			ip = v4
		}
		out = append(out, PeerAddr{IP: ip, Port: port})
	}
	return out, nil
}

func decodeAddrV2(payload []byte) ([]PeerAddr, error) {
	r := bytes.NewReader(payload)
	count, err := readVarInt(r)
	if err != nil {
		return nil, err
	}
	if count > 1000 {
		return nil, fmt.Errorf("addrv2 count %d > 1000", count)
	}
	out := make([]PeerAddr, 0, count)
	for i := uint64(0); i < count; i++ {
		// time (4) + services (varint) + networkID (1) + addr (varbytes) + port (2 BE)
		var ts [4]byte
		if _, err := io.ReadFull(r, ts[:]); err != nil {
			return out, err
		}
		if _, err := readVarInt(r); err != nil { // services
			return out, err
		}
		var netID [1]byte
		if _, err := io.ReadFull(r, netID[:]); err != nil {
			return out, err
		}
		addrLen, err := readVarInt(r)
		if err != nil {
			return out, err
		}
		if addrLen > 64 {
			return out, fmt.Errorf("addrv2 addr len %d too large", addrLen)
		}
		addrBytes := make([]byte, addrLen)
		if _, err := io.ReadFull(r, addrBytes); err != nil {
			return out, err
		}
		var portB [2]byte
		if _, err := io.ReadFull(r, portB[:]); err != nil {
			return out, err
		}
		port := binary.BigEndian.Uint16(portB[:])
		if port == 0 {
			continue
		}
		// We surface IPv4 (netID=1) and IPv6 (netID=2). The caller decides
		// whether to keep IPv6 based on user preference. Tor/I2P/CJDNS
		// (netID 3/4/5/6) are intentionally skipped — they aren't dialable
		// from a plain TCP `addnode=`.
		switch netID[0] {
		case 1: // IPV4
			if len(addrBytes) == 4 {
				ip := make(net.IP, 4)
				copy(ip, addrBytes)
				out = append(out, PeerAddr{IP: ip, Port: port})
			}
		case 2: // IPV6
			if len(addrBytes) == 16 {
				ip := make(net.IP, 16)
				copy(ip, addrBytes)
				out = append(out, PeerAddr{IP: ip, Port: port})
			}
		}
	}
	return out, nil
}

// ---------------------------------------------------------------------------
// inv (used here to count mempool tx hashes)
// ---------------------------------------------------------------------------

// decodeInv returns a count of tx-typed inventory items (we don't need the hashes).
func decodeInvTxCount(payload []byte) (int, error) {
	r := bytes.NewReader(payload)
	count, err := readVarInt(r)
	if err != nil {
		return 0, err
	}
	if count > 50000 {
		return 0, fmt.Errorf("inv count %d too large", count)
	}
	n := 0
	for i := uint64(0); i < count; i++ {
		var raw [36]byte // 4 type + 32 hash
		if _, err := io.ReadFull(r, raw[:]); err != nil {
			return n, err
		}
		invType := binary.LittleEndian.Uint32(raw[0:4])
		if invType == InvTx {
			n++
		}
	}
	return n, nil
}

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// to16 converts an IPv4 address to 16-byte IPv4-mapped-IPv6 form
// (the legacy on-wire representation).
func to16(ip net.IP) []byte {
	if v4 := ip.To4(); v4 != nil {
		out := make([]byte, 16)
		out[10], out[11] = 0xff, 0xff
		copy(out[12:], v4)
		return out
	}
	if v16 := ip.To16(); v16 != nil {
		return v16
	}
	return make([]byte, 16)
}
