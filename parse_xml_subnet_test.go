package main

import "testing"

func TestExtractAndApplySubnetIPv6UsesIPv6Index(t *testing.T) {
	dump := NewDump()
	pack := &PackedContent{ID: 42}
	record := &Content{
		SubnetIPv6: []SubnetIPv6{{SubnetIPv6: "2001:db8::/32"}},
	}

	dump.ExtractAndApplySubnetIPv6(record, pack)

	if _, ok := dump.subnetIPv4Index["2001:db8::/32"]; ok {
		t.Fatal("IPv6 subnet was inserted into IPv4 subnet index")
	}

	ids, ok := dump.subnetIPv6Index["2001:db8::/32"]
	if !ok {
		t.Fatal("IPv6 subnet was not inserted into IPv6 subnet index")
	}

	if !containsInt32(ids, pack.ID) {
		t.Fatalf("IPv6 subnet index does not contain content id %d: %v", pack.ID, ids)
	}
}

func TestExtractAndApplyUpdateSubnetIPv6RemovesFromIPv6Index(t *testing.T) {
	dump := NewDump()
	pack := &PackedContent{
		ID:         42,
		SubnetIPv6: []SubnetIPv6{{SubnetIPv6: "2001:db8::/32"}},
	}
	dump.InsertToSubnetIPv6Index("2001:db8::/32", pack.ID)

	dump.ExtractAndApplyUpdateSubnetIPv6(&Content{}, pack)

	if _, ok := dump.subnetIPv6Index["2001:db8::/32"]; ok {
		t.Fatal("removed IPv6 subnet is still present in IPv6 subnet index")
	}
}

func containsInt32(values []int32, want int32) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}

	return false
}
