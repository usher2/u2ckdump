package main

import (
	"strings"

	"golang.org/x/net/publicsuffix"
)

// parentDomains returns parent and suffix domains
// for example:
// parentDomains("www.google.com") -> "google.com", ""
// parentDomains("www.google.co.uk") -> "google.co.uk", "co.uk"
func parentDomains(domain string) (string, string) {
	parent, err := publicsuffix.EffectiveTLDPlusOne(domain)
	if err != nil {
		// logger.Debug.Printf("parentDomains Error: %s -> %s\n", domain, err)

		parent = domain
	}

	// logger.Debug.Printf("parentDomains: %s -> %s\n", domain, parent)

	if _, _, ok := strings.Cut(parent, "."); !ok {
		return "", ""
	}

	suffix, icann := publicsuffix.PublicSuffix(domain)
	if icann {
		return parent, ""
	}

	// logger.Debug.Printf("suffixDomains: %s -> %s\n", domain, suffix)

	if _, _, ok := strings.Cut(suffix, "."); !ok {
		return parent, ""
	}

	// logger.Debug.Printf("suffix/parent Domains: %s, %s\n", parent, suffix)

	return parent, suffix
}
