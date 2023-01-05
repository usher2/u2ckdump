package main

import (
	"net/url"
	"strings"

	"golang.org/x/net/idna"

	"github.com/usher2/u2ckdump/internal/logger"
)

func NormalizeDomain(domain string) string {
	domain = strings.Replace(domain, ",", ".", -1)
	domain = strings.Replace(domain, " ", "", -1)
	if c := strings.IndexByte(domain, '/'); c >= 0 {
		domain = domain[:c]
	}
	if c := strings.IndexByte(domain, '\\'); c >= 0 {
		domain = domain[:c]
	}
	domain = strings.TrimPrefix(domain, "*.")
	domain = strings.TrimSuffix(domain, ".")
	domain, _ = idna.ToASCII(domain)
	domain = strings.ToLower(domain)
	return domain
}

func NormalizeUrl(u string) string {
	u = strings.Replace(u, "\\", "/", -1)
	_url, err := url.Parse(u)
	if err != nil {
		logger.Error.Printf("URL parse error: %s\n", err.Error())
		// add as is
		return u
	} else {
		port := ""
		domain := _url.Hostname()
		colon := strings.LastIndexByte(domain, ':')
		if colon != -1 && validOptionalPort(domain[colon:]) {
			domain, port = domain[:colon], domain[colon+1:]
		}
		domain = NormalizeDomain(domain)
		_url.Host = domain
		if port != "" {
			_url.Host = _url.Host + ":" + port
		}
		_url.Fragment = ""
		return _url.String()
	}
}
