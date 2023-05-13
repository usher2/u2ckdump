package main

import "sync/atomic"

var Summary atomic.Value

type SummaryValues struct {
	UpdateTime                    int64
	ContentEntries                int            `json:"content_entries"`                    // Number of content entries
	EntryTypes                    map[string]int `json:"entry_types"`                        // Number of content entries by entry type
	DecisionOrgs                  map[string]int `json:"decision_orgs"`                      // Number of content entries by decision org
	IPv4Entries                   int            `json:"ipv4_entries"`                       // Number of IPv4 entries
	IPv6Entries                   int            `json:"ipv6_entries"`                       // Number of IPv6 entries
	DomainEntries                 int            `json:"domain_entries"`                     // Number of domain entries
	URLEntries                    int            `json:"url_entries"`                        // Number of URL entries
	SubnetIPv4Entries             int            `json:"subnet_ipv4_entries"`                // Number of IPv4 subnets
	SubnetIPv6Entries             int            `json:"subnet_ipv6_entries"`                // Number of IPv6 subnets
	BlockTypeURL                  int            `json:"block_type_url"`                     // Number of URL block types
	BlockTypeHTTPS                int            `json:"block_type_https"`                   // Number of HTTPS block types
	BlockTypeDomain               int            `json:"block_type_domain"`                  // Number of domain block types
	BlockTypeMask                 int            `json:"block_type_mask"`                    // Number of mask block types
	BlockTypeIP                   int            `json:"block_type_ip"`                      // Number of IP block types
	LargestSizeOfContent          int            `json:"largest_size_of_content"`            // Largest size of content
	LargestSizeOfContentCintentID int32          `json:"largest_size_of_content_content_id"` // Content ID with largest size of content
	MaxItemReferences             int            `json:"max_item_references"`                // Max number of references to a single item
	MaxItemReferencesString       string         `json:"max_item_references_string"`         // String representation of max number of references to a single item
}
