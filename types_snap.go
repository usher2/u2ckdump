package main

// Block types: url, https, domain, mask, ip.
const (
	BlockTypeURL = iota
	BlockTypeHTTPS
	BlockTypeDomain
	BlockTypeMask
	BlockTypeIP
)

// MinContent - packed version of Content.
type MinContent struct {
	ID                 int32
	BlockType          int32 // for protobuf
	RegistryUpdateTime int64
	Decision           uint64
	URL                []URL
	IP4                []IP4
	IP6                []IP6
	Subnet4            []Subnet4
	Subnet6            []Subnet6
	Domain             []Domain
	Pack               []byte
	U2Hash             uint64
}

// Content - store for <content> with hash.
type Content struct {
	ID          int32     `json:"id"`
	EntryType   int32     `json:"et"`
	UrgencyType int32     `json:"ut,omitempty"`
	Decision    Decision  `json:"d"`
	IncludeTime int64     `json:"it"`
	Ts          int64     `json:"ts,omitempty"`
	BlockType   string    `json:"bt,omitempty"`
	Hash        string    `json:"h"`
	URL         []URL     `json:"url,omitempty"`
	IP4         []IP4     `json:"ip4,omitempty"`
	IP6         []IP6     `json:"ip6,omitempty"`
	Subnet4     []Subnet4 `json:"sb4,omitempty"`
	Subnet6     []Subnet6 `json:"sb6,omitempty"`
	Domain      []Domain  `json:"dm,omitempty"`
	HTTPSBlock  int       `json:"hb"`
	U2Hash      uint64    `json:"u2h"`
}

// Subnet6 - store for <ipv6Subnet>.
type Subnet6 struct {
	Subnet6 string `json:"sb6"`
	Ts      int64  `json:"ts,omitempty"`
}

// Subnet4 - store for <ipSubnet>.
type Subnet4 struct {
	Subnet4 string `json:"sb4"`
	Ts      int64  `json:"ts,omitempty"`
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

// IP4 - store for <ip>.
type IP4 struct {
	IP4 uint32 `json:"ip4"`
	Ts  int64  `json:"ts,omitempty"`
}

// IP6 - store for <ip6>
type IP6 struct {
	IP6 []byte `json:"ip6"`
	Ts  int64  `json:"ts,omitempty"`
}

// Decision - <decision> and store for <decision>
type Decision struct {
	Date   string `xml:"date,attr" json:"dd"`
	Number string `xml:"number,attr" json:"dn"`
	Org    string `xml:"org,attr" json:"do"`
}
