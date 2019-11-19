package main

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

const (
	xml01 string = `<?xml version="1.0" encoding="windows-1251"?>
<reg:register xmlns:reg="http://rsoc.ru" xmlns:tns="http://rsoc.ru" updateTime="2018-04-16T11:20:00+03:00" updateTimeUrgently="2018-04-16T11:10:00+03:00" formatVersion="2.4">

<content id="111" includeTime="2009-10-11T23:00:00" entryType="1" blockType="default" hash="XXXX">
        <decision date="2001-02-17" number="1/1/11-1111" org="FSKN"/>
        <url><![CDATA[https://www.example01.com/sex]]></url>
        <url><![CDATA[http://www.example01.com/cheese]]></url>
        <domain><![CDATA[www.example01.com]]></domain>
        <ip>192.168.1.11</ip>
        <ip>192.168.12.100</ip>
        <ip>10.0.1.2</ip>
        <ipv6>fd11:beaf:7ea::1</ipv6>
        <ipv6>fd11:c01d:7ea::1</ipv6>
        <ipv6>fd12:c01d:7ea::100</ipv6>
</content>
<content id="222" includeTime="2009-10-11T12:00:00" entryType="1" blockType="domain" hash="YYYY">
        <decision date="2001-03-18" number="2/2/22-2222" org="RKN"/>
        <domain><![CDATA[www.example02.com]]></domain>
        <ip>192.168.2.11</ip>
        <ip>192.168.12.100</ip>
        <ip>10.0.2.2</ip>
        <ipv6>fd12:beaf:7ea::1</ipv6>
        <ipv6>fd12:c01d:7ea::1</ipv6>
        <ipv6>fd12:c01d:7ea::100</ipv6>
</content>
<content id="333" includeTime="2009-12-11T06:00:00" entryType="1" blockType="ip" hash="ZZZZ">
        <decision date="2011-04-11" number="3/3/33-3333" org="MVD"/>
        <ip>192.168.3.11</ip>
        <ip>192.168.12.100</ip>
        <ip>10.0.3.2</ip>
        <ipv6>fd13:beaf:7ea::1</ipv6>
        <ipv6>fd13:c01d:7ea::1</ipv6>
        <ipv6>fd12:c01d:7ea::100</ipv6>
</content>
<content id="444" includeTime="2013-12-14T16:00:00" entryType="1" blockType="ip" hash="QQQQ">
        <decision date="2012-05-21" number="4/4/44-4444" org="MVD"/>
        <ip>192.168.4.11</ip>
        <ip>192.168.4.100</ip>
        <ip>10.0.4.2</ip>
        <ipSubnet>10.4.0.0/16</ipSubnet>
        <ipv6>fd14:beaf:7ea::1</ipv6>
        <ipv6>fd14:c01d:7ea::1</ipv6>
        <ipv6>fd12:c01d:7ea::100</ipv6>
</content>
<content id="555" includeTime="2008-10-11T12:00:00" entryType="1" blockType="domain" hash="PPPP">
        <decision date="2001-03-18" number="2/2/22-2222" org="FSB"/>
        <domain><![CDATA[www.example02.com]]></domain>
        <ip>192.168.2.11</ip>
        <ip>192.168.12.111</ip>
        <ip>10.0.2.2</ip>
        <ipv6>fd12:beaf:7ea::2</ipv6>
        <ipv6>fd12:c01d:7ea::1</ipv6>
        <ipv6>fd12:c01d:7ea::100</ipv6>
</content>
</reg:register>`

	xml02 string = `<?xml version="1.0" encoding="windows-1251"?>
<reg:register xmlns:reg="http://rsoc.ru" xmlns:tns="http://rsoc.ru" updateTime="2018-04-17T12:20:00+03:00" updateTimeUrgently="2018-04-16T12:10:00+03:00" formatVersion="2.4">

<content id="111" includeTime="2009-10-11T23:00:00" entryType="1" blockType="default" hash="XXXX">
        <decision date="2001-02-17" number="1/1/11-1111" org="FSKN"/>
        <url><![CDATA[https://www.example01.com/sex]]></url>
        <url><![CDATA[http://www.example01.com/cheese]]></url>
        <domain><![CDATA[www.example01.com]]></domain>
        <ip>192.168.1.14</ip>
        <ip>192.168.12.100</ip>
        <ip>10.0.1.2</ip>
        <ipv6>fd11:beaf:7ea::1</ipv6>
        <ipv6>fd11:c01d:7ea::1</ipv6>
        <ipv6>fd12:c01d:7ea::100</ipv6>
</content>
<content id="222" includeTime="2009-10-11T12:00:00" entryType="1" blockType="domain" hash="YYYY">
        <decision date="2001-03-18" number="2/2/22-2222" org="RKN"/>
        <domain><![CDATA[www.example02.com]]></domain>
        <ip>192.168.2.11</ip>
        <ip>10.0.2.2</ip>
        <ipv6>fd12:beaf:7ea::1</ipv6>
        <ipv6>fd12:c01d:7ea::1</ipv6>
        <ipv6>fd12:c01d:7ea::100</ipv6>
</content>
<content id="333" includeTime="2009-12-11T06:00:00" entryType="1" blockType="ip" hash="ZZZZ">
        <decision date="2011-04-11" number="3/3/33-3333" org="MVD"/>
        <ip>192.168.3.11</ip>
        <ip>192.168.12.100</ip>
        <ip>10.0.3.2</ip>
        <ipv6>fd13:beaf:7ea::1</ipv6>
        <ipv6>fd13:c01d:7ea::1</ipv6>
        <ipv6>fd12:c01d:7ea::100</ipv6>
</content>
<content id="444" includeTime="2013-12-14T16:00:00" entryType="1" blockType="ip" hash="QQQQ">
        <decision date="2012-05-21" number="4/4/44-4444" org="MVD"/>
        <ip>192.168.4.11</ip>
        <ip>192.168.4.100</ip>
        <ip>10.0.4.2</ip>
        <ipSubnet>10.4.0.0/16</ipSubnet>
        <ipv6>fd14:beaf:7ea::1</ipv6>
        <ipv6>fd14:c01d:7ea::1</ipv6>
</content>
<content id="555" includeTime="2008-10-11T12:00:00" entryType="1" blockType="domain" hash="PPPP">
        <decision date="2002-03-18" number="2/2/22-2222" org="FSB"/>
        <domain><![CDATA[www.example02.com]]></domain>
        <ip>192.168.2.11</ip>
        <ip>192.168.12.111</ip>
        <ip>10.0.2.2</ip>
        <ipv6>fd12:beaf:7ea::2</ipv6>
        <ipv6>fd12:c01d:7ea::1</ipv6>
        <ipv6>fd12:c01d:7ea::100</ipv6>
</content>
</reg:register>`
)

func Test_Parse(t *testing.T) {
	logInit(os.Stderr, os.Stdout, os.Stderr, os.Stderr)
	dumpFile := strings.NewReader(xml01)
	err := Parse(dumpFile)
	if err != nil {
		t.Errorf(err.Error())
	}
	fmt.Printf("IP4:\n%v\n", DumpSnap.ip)
	//fmt.Printf("IP6:\n%v\n", DumpSnap.ip6)
	//fmt.Printf("Subnet:\n%v\n", DumpSnap.subnet)
	//fmt.Printf("Subnet6:\n%v\n", DumpSnap.subnet6)
	//fmt.Printf("URL:\n%v\n", DumpSnap.url)
	//fmt.Printf("Domain:\n%v\n", DumpSnap.domain)
	//fmt.Printf("Contents: ")
	for k, _ := range DumpSnap.Content.C {
		fmt.Printf("%d ", k)
	}
	fmt.Println()
	dumpFile = strings.NewReader(xml02)
	err = Parse(dumpFile)
	if err != nil {
		t.Errorf(err.Error())
	}
	fmt.Printf("IP4:\n%v\n", DumpSnap.ip)
	//fmt.Printf("IP6:\n%v\n", DumpSnap.ip6)
	//fmt.Printf("Subnet:\n%v\n", DumpSnap.subnet)
	//fmt.Printf("Subnet6:\n%v\n", DumpSnap.subnet6)
	//fmt.Printf("Url:\n%v\n", DumpSnap.url)
	//fmt.Printf("Domain:\n%v\n", DumpSnap.domain)
	//fmt.Printf("Contents: ")
	for k, _ := range DumpSnap.Content.C {
		fmt.Printf("%d ", k)
	}
	fmt.Println()
}
