package main

// XMLSubnet - <ipSubnet>.
type XMLSubnet struct {
	Subnet string `xml:",chardata"`
	Ts     string `xml:"ts,attr,omitempty"`
}

// XMLSubnet6 - <ipv6Subnet>.
type XMLSubnet6 struct {
	Subnet6 string `xml:",chardata"`
	Ts      string `xml:"ts,attr,omitempty"`
}

// XMLDomain - <domain>.
type XMLDomain struct {
	Domain string `xml:",cdata"`
	Ts     string `xml:"ts,attr,omitempty"`
}

// XMLURL - <url>.
type XMLURL struct {
	URL string `xml:",cdata"`
	Ts  string `xml:"ts,attr,omitempty"`
}

// XMLIP - <ip>.
type XMLIP struct {
	IP string `xml:",chardata"`
	Ts string `xml:"ts,attr,omitempty"`
}

// XMLIP6 - <ipv6>.
type XMLIP6 struct {
	IP6 string `xml:",chardata"`
	Ts  string `xml:"ts,attr,omitempty"`
}

/*
// use universal TDecision
type XMLDecision struct {
	Date   string `xml:"date,attr"`
	Number string `xml:"number,attr"`
	Org    string `xml:"org,attr"`
} */
