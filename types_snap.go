package main

// Block types: url, https, domain, mask, ip.
const (
	BlockTypeURL = iota
	BlockTypeHTTPS
	BlockTypeDomain
	BlockTypeMask
	BlockTypeIP
)

// PackedContent - packed version of Content.
type PackedContent struct {
	ID                 int32
	EntryType          int32 // for protobuf
	EntryTypeString    string
	BlockType          int32 // for protobuf
	RegistryUpdateTime int64
	Decision           uint64
	DecisionOrg        string
	URL                []URL
	IPv4               []IPv4
	IPv6               []IPv6
	SubnetIPv4         []SubnetIPv4
	SubnetIPv6         []SubnetIPv6
	Domain             []Domain
	Payload            []byte // It is a protobuf message.
	RecordHash         uint64
}

// Content - store for <content> with hash.
type Content struct {
	ID          int32        `json:"id"`
	EntryType   int32        `json:"et"`
	UrgencyType int32        `json:"ut,omitempty"`
	Decision    Decision     `json:"d"`
	IncludeTime int64        `json:"it"`
	Ts          int64        `json:"ts,omitempty"`
	BlockType   string       `json:"bt,omitempty"`
	Hash        string       `json:"h"`
	URL         []URL        `json:"url,omitempty"`
	IPv4        []IPv4       `json:"ip4,omitempty"`
	IPv6        []IPv6       `json:"ip6,omitempty"`
	SubnetIPv4  []SubnetIPv4 `json:"sb4,omitempty"`
	SubnetIPv6  []SubnetIPv6 `json:"sb6,omitempty"`
	Domain      []Domain     `json:"dm,omitempty"`
	HTTPSBlock  int          `json:"hb"`
	RecordHash  uint64       `json:"u2h"`
}

// SubnetIPv6 - store for <ipv6Subnet>.
type SubnetIPv6 struct {
	SubnetIPv6 string `json:"sb6"`
	Ts         int64  `json:"ts,omitempty"`
}

// SubnetIPv4 - store for <ipSubnet>.
type SubnetIPv4 struct {
	SubnetIPv4 string `json:"sb4"`
	Ts         int64  `json:"ts,omitempty"`
}

// Domain - store for <domain>.
type Domain struct {
	Domain string `json:"dm"`
	Ts     int64  `json:"ts,omitempty"`
}

// URL - store for <url>.
type URL struct {
	URL string `json:"u"`
	Ts  int64  `json:"ts,omitempty"`
}

// IPv4 - store for <ip>.
type IPv4 struct {
	IPv4 uint32 `json:"ip4"`
	Ts   int64  `json:"ts,omitempty"`
}

// IPv6 - store for <ip6>
type IPv6 struct {
	IPv6 []byte `json:"ip6"`
	Ts   int64  `json:"ts,omitempty"`
}

// Decision - <decision> and store for <decision>
type Decision struct {
	Date   string `xml:"date,attr" json:"dd"`
	Number string `xml:"number,attr" json:"dn"`
	Org    string `xml:"org,attr" json:"do"`
}
