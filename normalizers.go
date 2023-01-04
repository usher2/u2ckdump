package main

import (
	"net/url"
	"strings"

	"golang.org/x/net/idna"
)

// NormalizeDomain - normilize domain name.
func NormalizeDomain(domain string) string {
	if c := strings.IndexByte(domain, '/'); c >= 0 {
		domain = domain[:c]
	}

	if c := strings.IndexByte(domain, '\\'); c >= 0 {
		domain = domain[:c]
	}

	domain = strings.Replace(domain, ",", ".", -1)
	domain = strings.Replace(domain, " ", "", -1)
	domain = strings.TrimPrefix(domain, "*.")
	domain = strings.TrimSuffix(domain, ".")
	domain, _ = idna.ToASCII(domain)
	domain = strings.ToLower(domain)

	return domain
}

// NormalizeURL - normilize URL.
func NormalizeURL(u string) string {
	u = strings.Replace(u, "\\", "/", -1)

	nurl, err := url.Parse(u)
	if err != nil {
		Error.Printf("URL parse error: %s\n", err)

		return u
	}

	domain := nurl.Hostname()
	port := nurl.Port()

	nurl.Host = NormalizeDomain(domain)
	if port != "" {
		nurl.Host = nurl.Host + ":" + port
	}

	nurl.Fragment = ""

	return nurl.String()
}
