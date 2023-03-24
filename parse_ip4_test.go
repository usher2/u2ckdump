package main

import (
	"encoding/binary"
	"net"
	"testing"
)

// IPv4StrToInt converts a string containing an IPv4 address to its uint32 representation.
var testCases = []struct {
	input    string
	expected uint32
}{
	{"0.0.0.0", 0x00000000},
	{"255.255.255.255", 0xFFFFFFFF},
	{"192.168.0.1", 0xC0A80001},
	{"1.1.1.1", 0x01010101},
	{"127.0.0.1", 0x7F000001},
	{"256.0.0.1", 0xFFFFFFFF},
	{"255.255.255.256", 0xFFFFFFFF},
	{"255.255.255", 0xFFFFFFFF},
	{"255.255.255.255.255", 0xFFFFFFFF},
	{"255..255.255", 0xFFFFFFFF},
	{"255.255..255", 0xFFFFFFFF},
	{"255.255.255.", 0xFFFFFFFF},
	{"", 0xFFFFFFFF},
}

// IPv4StrToInt converts a string containing an IPv4 address to its uint32 representation.
// The implementation is based on the net.ParseIP function.
func ip2int(s string) uint32 {
	ip := net.ParseIP(s)
	if ip == nil {
		return 0xFFFFFFFF
	}

	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}

	return binary.BigEndian.Uint32(ip)
}

// Benchmark_ip2int benchmarks the ip2int function.
func Benchmark_ip2int(b *testing.B) {
	for i := 0; i < b.N; i++ {
		for _, ip := range testCases {
			ip2int(ip.input)
		}
	}
}

// Benchmark_parseIp4 benchmarks the IPv4StrToInt function.
func Benchmark_parseIp4(b *testing.B) {
	for i := 0; i < b.N; i++ {
		for _, ip := range testCases {
			IPv4StrToInt(ip.input)
		}
	}
}

// TestIPv4StrToInt tests the IPv4StrToInt function.
func TestIPv4StrToInt(t *testing.T) {
	for _, tc := range testCases {
		result := IPv4StrToInt(tc.input)
		if result != tc.expected {
			t.Errorf("ipv4StrToInt(%q) = %x; want %x", tc.input, result, tc.expected)
		}
	}
}
