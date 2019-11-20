package main

type TMinContent struct {
	Id      int32      `json:"id"`
	Url     []TUrl     `json:"url,omitempty"`
	Ip4     []TIp4     `json:"ip4,omitempty"`
	Ip6     []TIp6     `json:"ip6,omitempty"`
	Subnet4 []TSubnet4 `json:"sb4,omitempty"`
	Subnet6 []TSubnet6 `json:"sb6,omitempty"`
	Domain  []TDomain  `json:"dm,omitempty"`
	U2Hash  uint32     `json:"u2h"`
}

type TContent struct {
	Id          int32      `json:"id"`
	EntryType   int32      `json:"et"`
	UrgencyType int32      `json:"ut,omitempty"`
	Decision    TDecision  `json:"d"`
	IncludeTime int64      `json:"it"`
	Ts          int64      `json:"ts,omitempty"`
	BlockType   string     `json:"bt,omitempty"`
	Hash        string     `json:"h"`
	Url         []TUrl     `json:"url,omitempty"`
	Ip4         []TIp4     `json:"ip4,omitempty"`
	Ip6         []TIp6     `json:"ip6,omitempty"`
	Subnet4     []TSubnet4 `json:"sb4,omitempty"`
	Subnet6     []TSubnet6 `json:"sb6,omitempty"`
	Domain      []TDomain  `json:"dm,omitempty"`
	HttpsBlock  int        `json:"hb"`
	U2Hash      uint32     `json:"u2h"`
}

type TSubnet6 struct {
	Subnet6 string `json:"sb6"`
	Ts      int64  `json:"ts,omitempty"`
}

type TSubnet4 struct {
	Subnet4 string `json:"sb4"`
	Ts      int64  `json:"ts,omitempty"`
}

type TDomain struct {
	Domain string `json:"dm"`
	Ts     int64  `json:"ts,omitempty"`
}

type TUrl struct {
	Url string `json:"u"`
	Ts  int64  `json:"ts,omitempty"`
}

type TIp4 struct {
	Ip4 uint32 `json:"ip4"`
	Ts  int64  `json:"ts,omitempty"`
}

type TIp6 struct {
	Ip6 string `json:"ip6"`
	Ts  int64  `json:"ts,omitempty"`
}

type TDecision struct {
	Date   string `xml:"date,attr" json:"dd"`
	Number string `xml:"number,attr" json:"dn"`
	Org    string `xml:"org,attr" json:"do"`
}
