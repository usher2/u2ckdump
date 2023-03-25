package main

import (
	"io"
	"os"
	"testing"

	"github.com/usher2/u2ckdump/internal/logger"
)

func init() {
	logger.LogInit(io.Discard, os.Stdout, os.Stderr, os.Stderr)
}

// TestNormalizeDomain tests the NormalizeDomain function.
func TestNormalizeDomain(t *testing.T) {
	testCases := []struct {
		input    string
		expected string
	}{
		{"example.com", "example.com"},
		{"http://example.com", "example.com"},
		{"http:\\example.com", "example.com"},
		{"http//example.com", "example.com"},
		{"//example.com", "example.com"},
		{"http:/example.com", "example.com"},
		{"http/exmaple.com", "exmaple.com"},
		{"http://example.com/test", "example.com"},
		{"Example,com", "example.com"},
		{"example . com", "example.com"},
		{"*.example.com", "example.com"},
		{"example.com.", "example.com"},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			result := NormalizeDomain(tc.input)
			if result != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, result)
			}
		})
	}
}

// TestNormalizeURL tests the NormalizeURL function.
func TestNormalizeURL(t *testing.T) {
	testCases := []struct {
		input    string
		expected string
	}{
		{"http://example.com", "http://example.com"},
		{"https://example.com", "https://example.com"},
		{"http:\\\\example.com", "http://example.com"},
		{"http:/example.com", "http://example.com"},
		{"http:example.com", "http://example.com"},
		{"http://Example,com", "http://example.com"},
		{"http://example.com/test%t", "http://example.com/test%t"},
		{"http://example.com/test#fragment", "http://example.com/test"},
		{"https://example.com:8080", "https://example.com:8080"},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			result := NormalizeURL(tc.input)
			if result != tc.expected {
				t.Errorf("expected %q, got %q", tc.expected, result)
			}
		})
	}
}
