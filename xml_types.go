package main

type TContent struct {
	Id          int32      `xml:"id,attr" json:"id"`
	EntryType   int32      `xml:"entryType,attr" json:"entryType"`
	UrgencyType int32      `xml:"urgencyType,attr,omitempty" json:"urgencyType,omitempty"`
	Decision    TDecision  `xml:"decision" json:"decision"`
	IncludeTime string     `xml:"includeTime,attr" json:"includeTime"`
	BlockType   string     `xml:"blockType,attr,omitempty" json:"blockType,omitempty"`
	Hash        string     `xml:"hash,attr" json:"hash"`
	Ts          string     `xml:"ts,attr,omitempty" json:"ts,omitempty"`
	Url         []TUrl     `xml:"url,omitempty" json:"url,omitempty"`
	Ip          []TIp      `xml:"ip,omitempty" json:"ip,omitempty"`
	Ip6         []TIp6     `xml:"ipv6,omitempty" json:"ip6,omitempty"`
	Subnet      []TSubnet  `xml:"ipSubnet,omitempty" json:"subnet,omitempty"`
	Subnet6     []TSubnet6 `xml:"ipv6Subnet,omitempty" json:"subnet6,omitempty"`
	Domain      []TDomain  `xml:"domain,omitempty" json:"domain,omitempty"`
}

type TSubnet6 struct {
	Subnet6 string `xml:",chardata"`
	Ts      string `xml:"ts,attr,omitempty"`
}

type TSubnet struct {
	Subnet string `xml:",chardata"`
	Ts     string `xml:"ts,attr,omitempty"`
}

type TDomain struct {
	Domain string `xml:",cdata"`
	Ts     string `xml:"ts,attr,omitempty"`
}

type TUrl struct {
	Url string `xml:",cdata"`
	Ts  string `xml:"ts,attr,omitempty"`
}

type TIp struct {
	Ip string `xml:",chardata"`
	Ts string `xml:"ts,attr,omitempty"`
}

type TIp6 struct {
	Ip6 string `xml:",chardata"`
	Ts  string `xml:"ts,attr,omitempty"`
}

type TDecision struct {
	Date   string `xml:"date,attr"`
	Number string `xml:"number,attr"`
	Org    string `xml:"org,attr"`
}
