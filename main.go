// main.go — BCH peer-finder entry point.
//
// Pipeline:
//
//	DNS seeds ─┐
//	           ├─► AddrManager ──► N workers ──► PeerResult ──► scoreboard
//	addr msgs ─┘                       │
//	                                   ▼
//	                                addnode= output
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// ---------------------------------------------------------------------------
// AddrManager — thread-safe FIFO of candidate peers, deduping by ip:port.
// ---------------------------------------------------------------------------

type AddrManager struct {
	mu       sync.Mutex
	known    map[string]struct{}
	queued   []string
	tried    map[string]struct{}
	maxKnown int
}

func NewAddrManager(maxKnown int) *AddrManager {
	return &AddrManager{
		known:    make(map[string]struct{}),
		tried:    make(map[string]struct{}),
		maxKnown: maxKnown,
	}
}

// Add registers a new candidate. Returns true if it's new.
func (a *AddrManager) Add(addr string) bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	if _, ok := a.known[addr]; ok {
		return false
	}
	if len(a.known) >= a.maxKnown {
		return false
	}
	a.known[addr] = struct{}{}
	a.queued = append(a.queued, addr)
	return true
}

// Exhausted returns true when every known address has been tried and the queue
// is empty — i.e., no new work can arrive unless a worker adds more addresses.
func (a *AddrManager) Exhausted() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.queued) == 0 && len(a.tried) >= len(a.known)
}

// Next pulls the head of the queue. Returns ("", false) when empty.
func (a *AddrManager) Next() (string, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	for len(a.queued) > 0 {
		addr := a.queued[0]
		a.queued = a.queued[1:]
		if _, done := a.tried[addr]; done {
			continue
		}
		a.tried[addr] = struct{}{}
		return addr, true
	}
	return "", false
}

func (a *AddrManager) Stats() (known, tried, pending int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return len(a.known), len(a.tried), len(a.queued)
}

// ---------------------------------------------------------------------------
// Worker pool
// ---------------------------------------------------------------------------

func runWorkers(ctx context.Context, n int, am *AddrManager, results chan<- PeerResult,
	probeWindow time.Duration, acceptIPv6 bool, noDiscovery bool, evaluated *atomic.Int64) {

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}
				addr, ok := am.Next()
				if !ok {
					// queue temporarily empty — back off
					select {
					case <-ctx.Done():
						return
					case <-time.After(250 * time.Millisecond):
					}
					continue
				}
				res := evaluatePeer(ctx, addr, am, probeWindow, acceptIPv6, noDiscovery)
				evaluated.Add(1)
				select {
				case results <- res:
				case <-ctx.Done():
					return
				}
			}
		}()
	}
	wg.Wait()
	close(results)
}

// ---------------------------------------------------------------------------
// Reference height estimation (median of recent peer start_heights)
// ---------------------------------------------------------------------------

type heightTracker struct {
	mu      sync.Mutex
	heights []int32
}

func (h *heightTracker) Add(v int32) {
	if v <= 0 {
		return
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	h.heights = append(h.heights, v)
	// Keep only the most recent 200 samples to track chain tip movement.
	if len(h.heights) > 200 {
		h.heights = h.heights[len(h.heights)-200:]
	}
}

func (h *heightTracker) Median() int32 {
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.heights) == 0 {
		return 0
	}
	c := append([]int32{}, h.heights...)
	sort.Slice(c, func(i, j int) bool { return c[i] < c[j] })
	return c[len(c)/2]
}

// ---------------------------------------------------------------------------
// Output
// ---------------------------------------------------------------------------

func writeOutputs(results []PeerResult, allPeers []PeerResult, refHeight int32, total int64, addnodeFile, jsonFile string, topN int, showUserAgents bool) error {
	// Rank
	sort.SliceStable(results, func(i, j int) bool { return results[i].Score > results[j].Score })

	// Console table
	fmt.Println()
	fmt.Println("================ TOP BCH PEERS ================")
	fmt.Printf(" rank │ score │ mempool │ height  │  rtt   │   fee-filter    │ bip155 │ proto │ user-agent\n")
	fmt.Println("──────┼───────┼─────────┼─────────┼────────┼─────────────────┼────────┼───────┼────────────")
	for i, r := range results {
		if i >= topN {
			break
		}
		ua := r.UserAgent
		if len(ua) > 40 {
			ua = ua[:40] + "…"
		}
		rtt := "    - "
		if r.LatencyMs > 0 {
			rtt = fmt.Sprintf("%4dms", r.LatencyMs)
		}
		feeStr := "             -"
		if r.FeeFilter > 0 {
			feeStr = fmt.Sprintf("%8d sat/kB", r.FeeFilter)
		}
		bip155 := "  no  "
		if r.BIP155 {
			bip155 = "  yes "
		}
		fmt.Printf(" %4d │ %5d │ %7d │ %7d │ %s │ %s │ %s │ %5d │ %s\n",
			i+1, r.Score, r.MempoolCount, r.StartHeight, rtt, feeStr, bip155, r.ProtocolVersion, ua)
	}
	fmt.Println()

	if showUserAgents {
		// Collect user-agent counts
		uaCounts := make(map[string]int)
		for _, r := range allPeers {
			uaCounts[r.UserAgent]++
		}

		// Sort by count descending
		type uaCount struct {
			ua    string
			count int
		}
		var uas []uaCount
		for ua, count := range uaCounts {
			uas = append(uas, uaCount{ua, count})
		}
		sort.Slice(uas, func(i, j int) bool {
			return uas[i].count > uas[j].count
		})

		// Print table
		fmt.Println("=========== OBSERVED USER-AGENTS ===========")
		fmt.Printf(" count │ user-agent\n")
		fmt.Println("───────┼────────────────────────────────────────────")
		for _, u := range uas {
			fmt.Printf(" %5d │ %s\n", u.count, u.ua)
		}
		fmt.Println()
	}

	// addnode= file
	if addnodeFile != "" {
		f, err := os.Create(addnodeFile)
		if err != nil {
			return err
		}
		defer f.Close()
		fmt.Fprintf(f, "# bch-peer-finder output — %s\n", time.Now().UTC().Format(time.RFC3339))
		fmt.Fprintf(f, "# reference tip height: %d\n", refHeight)
		fmt.Fprintf(f, "# peers evaluated:       %d\n", total)
		fmt.Fprintf(f, "# scored BCH peers:      %d\n", len(results))
		fmt.Fprintf(f, "# top %d, ranked by score\n\n", topN)
		for i, r := range results {
			if i >= topN {
				break
			}
			fmt.Fprintf(f, "# score=%d mempool=%d height=%d latency=%dms proto=%d bip155=%v ua=%s\n",
				r.Score, r.MempoolCount, r.StartHeight, r.LatencyMs, r.ProtocolVersion, r.BIP155, r.UserAgent)
			fmt.Fprintf(f, "addnode=%s\n\n", r.Address)
		}
		fmt.Printf("addnode list  -> %s\n", addnodeFile)
	}

	// JSON dump (everything we kept)
	if jsonFile != "" {
		f, err := os.Create(jsonFile)
		if err != nil {
			return err
		}
		defer f.Close()
		enc := json.NewEncoder(f)
		enc.SetIndent("", "  ")
		if err := enc.Encode(map[string]any{
			"generated_at":     time.Now().UTC(),
			"reference_height": refHeight,
			"peers_evaluated":  total,
			"scored_bch_peers": len(results),
			"results":          results,
		}); err != nil {
			return err
		}
		fmt.Printf("full JSON     -> %s\n", jsonFile)
	}

	return nil
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------

func main() {
	start := time.Now()

	var (
		workers     = flag.Int("workers", 80, "concurrent peer probes")
		duration    = flag.Duration("duration", 3*time.Minute, "total crawl time")
		probeWindow = flag.Duration("probe", 12*time.Second, "per-peer read window after handshake")
		topN        = flag.Int("top", 50, "number of peers to keep in the output")
		addnodeFile = flag.String("out", "bch-addnodes.conf", "addnode= output file (empty to skip)")
		jsonFile    = flag.String("json", "bch-peers.json", "full JSON output file (empty to skip)")
		maxKnown    = flag.Int("max-known", 50000, "ceiling on candidate addresses tracked")
		acceptIPv6  = flag.Bool("ipv6", false, "also crawl and rank IPv6 peers (default IPv4 only)")
		userAgents  = flag.Bool("user-agents", false, "show all observed user-agents with counter")
		noDiscovery = flag.Bool("no-discovery", false, "only probe the bootstrap seed addresses, ignore addr/addrv2 messages")
	)
	flag.Parse()

	// Cancel on Ctrl-C or after the deadline.
	ctx, cancel := context.WithTimeout(context.Background(), *duration)
	defer cancel()
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigCh
		fmt.Println("\nshutdown signal received — wrapping up…")
		cancel()
	}()

	fmt.Println("bch-peer-finder starting")
	if *acceptIPv6 {
		fmt.Println("ipv6 enabled — including IPv6 peers")
	}
	if *userAgents {
		fmt.Println("user-agents enabled — all observed user-agents will be displayed")
	}
	fmt.Println("resolving DNS seeds…")
	bootstrap := ResolveSeeds(ctx, *acceptIPv6)
	if len(bootstrap) == 0 {
		fmt.Fprintln(os.Stderr, "no bootstrap addresses (DNS failure?) — exiting")
		os.Exit(1)
	}
	fmt.Printf("  %d unique seed addrs\n\n", len(bootstrap))

	am := NewAddrManager(*maxKnown)
	for _, a := range bootstrap {
		am.Add(a)
	}

	results := make(chan PeerResult, 256)
	heights := &heightTracker{}
	evaluated := &atomic.Int64{}

	// Worker pool
	go runWorkers(ctx, *workers, am, results, *probeWindow, *acceptIPv6, *noDiscovery, evaluated)

	// Periodic progress + early-exit when all known peers have been tried.
	progressTicker := time.NewTicker(10 * time.Second)
	defer progressTicker.Stop()
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-progressTicker.C:
				k, t, p := am.Stats()
				elapsed := int(time.Since(start).Seconds())
				fmt.Printf("[t+%4ds] evaluated=%d  known=%d  tried=%d  pending=%d  median_height=%d\n",
					elapsed, evaluated.Load(), k, t, p, heights.Median())
				if am.Exhausted() {
					fmt.Println("\nall known peers tried — finishing early…")
					cancel()
					return
				}
			}
		}
	}()

	// Drain results, accumulate good ones.
	var good []PeerResult
	var allPeers []PeerResult
	for r := range results {
		heights.Add(r.StartHeight)
		ref := heights.Median()

		// Determine software type (known BCH nodes)
		if isBCHUserAgent(r.UserAgent) {
			uaLower := strings.ToLower(r.UserAgent)
			switch {
			case strings.Contains(uaLower, "bitcoin cash node"):
				r.Software = SoftwareBCHN
			case strings.Contains(uaLower, "bchd"):
				r.Software = SoftwareBchd
			case strings.Contains(uaLower, "knuth"):
				r.Software = SoftwareKnuth
			case strings.Contains(uaLower, "flowee"):
				r.Software = SoftwareFlowee
			case strings.Contains(uaLower, "bitcoin verde"):
				r.Software = SoftwareBitcoinVerde
			case strings.Contains(uaLower, "bitcoin unlimited"):
				r.Software = SoftwareBitcoinUnlimited
			}
		}

		r.Score = computeScore(&r, ref, nil, false, 0) // temp score
		if r.HandshakeOK {
			allPeers = append(allPeers, r)
			if r.Score > 0 {
				good = append(good, r)
			}
		}
	}

	// Compute version stats per software for relative version scoring.
	// Each software is compared only against itself: BCHN vs BCHN, bchd vs bchd, etc.
	versionStats := make(map[Software]struct{ min, max int })
	for _, r := range good {
		if r.Software == SoftwareUnknown {
			continue
		}
		major, minor, patch := parseVersion(r.UserAgent)
		versionValue := major*10000 + minor*100 + patch
		if stats, ok := versionStats[r.Software]; ok {
			if versionValue < stats.min {
				stats.min = versionValue
			}
			if versionValue > stats.max {
				stats.max = versionValue
			}
			versionStats[r.Software] = stats
		} else {
			versionStats[r.Software] = struct{ min, max int }{versionValue, versionValue}
		}
	}

	refHeight := heights.Median()

	// Detect whether the network mempool is currently non-empty:
	// if at least 20 good peers report a non-zero mempool count, treat it as filled.
	nonEmptyMempool := 0
	for _, r := range good {
		if r.MempoolCount > 0 {
			nonEmptyMempool++
		}
	}
	mempoolFilled := nonEmptyMempool >= 20

	// Compute mean mempool count across peers that reported at least one tx,
	// so peers with empty mempools don't drag the baseline down.
	var mempoolMean int
	if mempoolFilled {
		sum, n := 0, 0
		for _, r := range good {
			if r.MempoolCount > 0 {
				sum += r.MempoolCount
				n++
			}
		}
		if n > 0 {
			mempoolMean = sum / n
		}
	}

	// Re-score with final reference height, version stats, and mempool signal.
	for i := range good {
		good[i].Score = computeScore(&good[i], refHeight, versionStats, mempoolFilled, mempoolMean)
	}

	fmt.Printf("\ncrawl complete — %d peers evaluated, %d scored as BCH-good, tip≈%d\n",
		evaluated.Load(), len(good), refHeight)

	if err := writeOutputs(good, allPeers, refHeight, evaluated.Load(), *addnodeFile, *jsonFile, *topN, *userAgents); err != nil {
		fmt.Fprintf(os.Stderr, "output error: %v\n", err)
		os.Exit(1)
	}
}
