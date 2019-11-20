package main

type TXMLSubnet6 struct {
	Subnet6 string `xml:",chardata"`
	Ts      string `xml:"ts,attr,omitempty"`
}

type TXMLSubnet struct {
	Subnet string `xml:",chardata"`
	Ts     string `xml:"ts,attr,omitempty"`
}

type TXMLDomain struct {
	Domain string `xml:",cdata"`
	Ts     string `xml:"ts,attr,omitempty"`
}

type TXMLUrl struct {
	Url string `xml:",cdata"`
	Ts  string `xml:"ts,attr,omitempty"`
}

type TXMLIp struct {
	Ip string `xml:",chardata"`
	Ts string `xml:"ts,attr,omitempty"`
}

type TXMLIp6 struct {
	Ip6 string `xml:",chardata"`
	Ts  string `xml:"ts,attr,omitempty"`
}

/*
// use universal TDecision
type TXMLDecision struct {
	Date   string `xml:"date,attr"`
	Number string `xml:"number,attr"`
	Org    string `xml:"org,attr"`
} */
