package main

import (
	"net/url"
	"regexp"
	"strings"

	"golang.org/x/net/idna"

	"github.com/usher2/u2ckdump/internal/logger"
)

// NormalizeDomain takes a domain name string containing misprints and
// attempts to construct the correct domain name. It trims unnecessary characters,
// replaces common errors, and converts the domain to ASCII and lowercase.
// If there is an error during the conversion to ASCII, it is ignored and the original
// domain is returned instead.
func NormalizeDomain(domain string) string {
	// Remove the protocol or its misspellings, if present
	domain = removeMisspelledProtocol(domain)

	// Remove any content after the first '/' or '\' character.
	domain = trimAfterChar(domain, '/')
	domain = trimAfterChar(domain, '\\')

	// Replace common misprints and unnecessary characters.
	domain = strings.Replace(domain, ",", ".", -1)
	domain = strings.Replace(domain, " ", "", -1)
	//	domain = strings.Replace(domain, "_", "-", -1)      // Replace underscore with hyphen.
	//	domain = strings.Replace(domain, "wwww", "www", -1) // Fix common "wwww" misprint.
	domain = strings.TrimPrefix(domain, "*.")
	domain = strings.TrimSuffix(domain, ".")

	// Convert domain to ASCII and ignore any errors.
	asciiDomain, _ := idna.ToASCII(domain)

	// Convert domain to lowercase.
	lowerDomain := strings.ToLower(asciiDomain)

	return lowerDomain
}

// NormalizeURL takes a URL string containing misprints and
// attempts to construct the correct URL. It fixes common misprints,
// normalizes the domain using the NormalizeDomain function, and
// removes any URL fragments.
func NormalizeURL(u string) string {
	// Fix the misspelled protocol, if present
	u = replaceMisspelledProtocol(u)

	// Replace backslashes with forward slashes.
	u = strings.Replace(u, "\\", "/", -1)

	// Parse the URL.
	nurl, err := url.Parse(u)
	if err != nil {
		// Log the error and return the original URL if parsing fails.
		logger.Error.Printf("URL parse error: %s\n", err)

		return u
	}

	// Normalize the domain.
	domain := nurl.Hostname()
	port := nurl.Port()
	nurl.Host = NormalizeDomain(domain)

	// Add the port back to the normalized domain, if present.
	if port != "" {
		nurl.Host = nurl.Host + ":" + port
	}

	// Remove any URL fragments.
	nurl.Fragment = ""

	// Return the normalized URL.
	return nurl.String()
}

// protocolPattern - regexp for remove misspelled protocol.
var protocolPattern = regexp.MustCompile(`^(https?):?[/\\]*|^(http?):?[/\\]*|^//`)

// removeMisspelledProtocol removes common misspellings of the "http://" or "https://" prefix
// from the input domain string if it is present.
func removeMisspelledProtocol(s string) string {
	return protocolPattern.ReplaceAllString(s, "")
}

// replaceMisspelledProtocol replaces common misspellings of the "http://" or "https://" prefix
// in the input URL string with the correct protocol.
func replaceMisspelledProtocol(s string) string {
	return protocolPattern.ReplaceAllStringFunc(s, func(match string) string {
		if strings.Contains(match, "https") {
			return "https://"
		}
		return "http://"
	})
}

// trimAfterChar trims the input string after the first occurrence of the specified character.
// If the character is not found, the original string is returned.
func trimAfterChar(s string, char byte) string {
	if idx := strings.IndexByte(s, char); idx >= 0 {
		return s[:idx]
	}
	return s
}
