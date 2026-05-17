// seeds.go — Bootstrap addresses for BCH mainnet peer discovery.
package main

import (
	"context"
	"fmt"
	"net"
	"time"
)

// MainnetDNSSeeds are the DNS seeders maintained for the BCH mainnet
var MainnetDNSSeeds = []string{
	"seed.flowee.cash",
	"btccash-seeder.bitcoinunlimited.info",
	"seed.bchd.cash",
	"seed.bch.loping.net",
	"bchseed.c3-soft.com",
	"bch.bitjson.com",
}

// MainnetHardcodedSeeds is an optional fallback used when DNS resolution fails
// completely. Populate this if you want the tool to bootstrap behind a
// firewall that blocks DNS but allows outbound 8333. Values must be "ip:port".
//
// BCHN ships the full seed list as a packed binary blob in
// src/chainparamsseeds.h — too large to inline here verbatim. The four entries
// below are intentionally a tiny safety net; once DNS works you'll get
// hundreds within seconds.
//
// Values must be "ip:port"
var MainnetHardcodedSeeds = []string{
	// Add IPs here if you want offline-DNS bootstrap, e.g.:
	// "66.172.112.151:8333",
	// "66.172.112.154:8333",
	// "66.172.112.251:8333",
}

const DefaultMainnetPort = 8333

// ResolveSeeds fans out to the DNS seeders concurrently and returns every
// address it can pull, formatted as "ip:port" (IPv6 properly bracketed).
// IPv6 results are only included when acceptIPv6 is true.
func ResolveSeeds(ctx context.Context, acceptIPv6 bool) []string {
	type result struct {
		addrs []string
		seed  string
		err   error
	}
	ch := make(chan result, len(MainnetDNSSeeds))

	resolver := &net.Resolver{}
	for _, seed := range MainnetDNSSeeds {
		go func(host string) {
			c, cancel := context.WithTimeout(ctx, 10*time.Second)
			defer cancel()
			ips, err := resolver.LookupIPAddr(c, host)
			if err != nil {
				ch <- result{seed: host, err: err}
				return
			}
			out := make([]string, 0, len(ips))
			for _, ip := range ips {
				if v4 := ip.IP.To4(); v4 != nil {
					out = append(out, net.JoinHostPort(v4.String(), fmt.Sprint(DefaultMainnetPort)))
				} else if acceptIPv6 && ip.IP.To16() != nil {
					out = append(out, net.JoinHostPort(ip.IP.String(), fmt.Sprint(DefaultMainnetPort)))
				}
			}
			ch <- result{addrs: out, seed: host}
		}(seed)
	}

	seen := map[string]struct{}{}
	var all []string
	for i := 0; i < len(MainnetDNSSeeds); i++ {
		r := <-ch
		if r.err != nil {
			fmt.Printf("  ! DNS seed %s: %v\n", r.seed, r.err)
			continue
		}
		fmt.Printf("  + DNS seed %s: %d addrs\n", r.seed, len(r.addrs))
		for _, a := range r.addrs {
			if _, dup := seen[a]; !dup {
				seen[a] = struct{}{}
				all = append(all, a)
			}
		}
	}

	// Fold in any hardcoded fallback addresses.
	for _, a := range MainnetHardcodedSeeds {
		if _, dup := seen[a]; !dup {
			seen[a] = struct{}{}
			all = append(all, a)
		}
	}

	return all
}
