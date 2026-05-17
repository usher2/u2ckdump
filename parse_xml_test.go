package main

import (
	"fmt"
	"net"
	"os"
	"strings"
	"testing"

	"github.com/usher2/u2ckdump/internal/logger"
)

const (
	xml01 string = `<?xml version="1.0" encoding="windows-1251"?>
<reg:register xmlns:reg="http://rsoc.ru" xmlns:tns="http://rsoc.ru" updateTime="2011-01-01T01:01:01+03:00" updateTimeUrgently="2010-02-02T02:02:01+03:00" formatVersion="2.4">

<content id="111" includeTime="2001-01-01T01:01:01" entryType="1" blockType="default" hash="XXXX">
        <decision date="2000-01-01" number="1/1/11-1111" org="ONE"/>
        <url><![CDATA[https://www.e01.tld/sex]]></url>
        <url><![CDATA[http://www.e01.tld/cheese]]></url>
        <url><![CDATA[http://www.e01.tld/slip]]></url>
        <domain><![CDATA[www.e01.tld]]></domain>
        <ip>192.168.1.11</ip>
        <ip>192.168.0.100</ip>
        <ip>10.1.1.1</ip>
        <ipv6>fd11:1::1</ipv6>
        <ipv6>fd11:11::1</ipv6>
        <ipv6>fdaa:f::100</ipv6>
</content>
<content id="222" includeTime="2001-01-01T02:02:02" entryType="1" blockType="domain" hash="YYYY">
        <decision date="2000-01-02" number="2/2/22-2222" org="TWO"/>
        <domain><![CDATA[www.e02.tld]]></domain>
        <ip>192.168.2.22</ip>
        <ip>192.168.0.100</ip>
        <ip>10.2.2.2</ip>
        <ipv6>fd22:2::2</ipv6>
        <ipv6>fd22:22::2</ipv6>
        <ipv6>fdaa:f::100</ipv6>
</content>
<content id="333" includeTime="2001-01-01T03:03:03" entryType="1" blockType="ip" hash="ZZZZ">
        <decision date="2001-01-03" number="3/3/33-3333" org="THREE"/>
        <ip>192.168.3.33</ip>
        <ip>192.168.0.100</ip>
        <ip>10.3.3.3</ip>
        <ipv6>fd33:3::3</ipv6>
        <ipv6>fd33:33::3</ipv6>
        <ipv6>fdaa:f::100</ipv6>
</content>
<content id="444" includeTime="2001-01-01T04:04:04" entryType="1" blockType="ip" hash="QQQQ">
        <decision date="2001-01-04" number="4/4/44-4444" org="FOUR"/>
        <ip>192.168.4.44</ip>
        <ip>192.168.4.100</ip>
        <ip>10.4.4.4</ip>
        <ipSubnet>10.4.0.0/16</ipSubnet>
        <ipv6>fd44:4::1</ipv6>
        <ipv6>fd44:44::1</ipv6>
        <ipv6>fdaa:f::100</ipv6>
</content>
<content id="555" includeTime="2001-01-01T05:05:05" entryType="1" blockType="domain" hash="PPPP">
        <decision date="2001-01-05" number="5/5/55-5555" org="FIVE"/>
        <domain><![CDATA[www.e02.tld]]></domain>
        <ip>192.168.5.55</ip>
        <ip>192.168.0.111</ip>
        <ip>10.5.5.5</ip>
        <ipv6>fd55:5::5</ipv6>
        <ipv6>fd55:55::5</ipv6>
        <ipv6>fdaa:f::100</ipv6>
</content>
</reg:register>`

	xml02 string = `<?xml version="1.0" encoding="windows-1251"?>
<reg:register xmlns:reg="http://rsoc.ru" xmlns:tns="http://rsoc.ru" updateTime="2013-03-03T03:03:03+03:00" updateTimeUrgently="2012-04-04T04:04:04+03:00" formatVersion="2.4">

<content id="111" includeTime="2009-10-11T23:00:00" entryType="1" blockType="default" hash="XXXX">
        <decision date="2001-02-17" number="1/1/11-1111" org="FSKN"/>
        <url><![CDATA[https://www.example01.com/sex]]></url>
        <url><![CDATA[http://www.example01.com/cheese]]></url>
        <domain><![CDATA[www.example01.com]]></domain>
        <ip>192.168.1.14</ip>
        <ip>192.168.12.100</ip>
        <ip>10.1.1.2</ip>
        <ipv6>fd11:beaf:7ea::1</ipv6>
        <ipv6>fd11:c01d:7ea::1</ipv6>
        <ipv6>fd12:c01d:7ea::100</ipv6>
</content>
<content id="222" includeTime="2009-10-11T12:00:00" entryType="1" blockType="domain" hash="YYYY">
        <decision date="2001-03-18" number="2/2/22-2222" org="RKN"/>
        <domain><![CDATA[www.example02.com]]></domain>
        <ip>192.168.2.11</ip>
        <ip>10.2.2.2</ip>
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
	logger.LogInit(os.Stderr, os.Stdout, os.Stderr, os.Stderr)
	dumpFile := strings.NewReader(xml01)
	stats, err := Parse(dumpFile)
	if err != nil {
		t.Errorf(err.Error())
	}

	if stats.MaxItemReferences != 5 ||
		stats.Count != 5 ||
		stats.AddCount != 5 ||
		stats.UpdateCount != 0 ||
		stats.RemoveCount != 0 {
		t.Errorf("Stat error: %v\n", Summary)
	}

	if len(CurrentDump.IPv4Index) != 13 ||
		len(CurrentDump.IPv6Index) != 11 ||
		len(CurrentDump.subnetIPv4Index) != 1 ||
		len(CurrentDump.subnetIPv6Index) != 0 ||
		len(CurrentDump.URLIndex) != 3 ||
		len(CurrentDump.domainIndex) != 2 {
		t.Errorf("Count error")
	}

	if len(CurrentDump.ContentIndex) != 5 ||
		len(CurrentDump.ContentIndex) != stats.Count {
		t.Errorf("DumpSnap integrity error: %d\n", len(CurrentDump.ContentIndex))
	}

	fmt.Println()
	dumpFile = strings.NewReader(xml02)
	_, err = Parse(dumpFile)
	if err != nil {
		t.Errorf(err.Error())
	}
	fmt.Printf("IP4:\n%v\n", CurrentDump.IPv4Index)
	for k := range CurrentDump.ContentIndex {
		fmt.Printf("%d ", k)
	}
	fmt.Println()
}

func TestUpdateRebindsLargeFieldSlicesByIndexKey(t *testing.T) {
	logger.LogInit(os.Stderr, os.Stdout, os.Stderr, os.Stderr)

	dump := NewDump()
	pack := newPackedContent(42, 0, 0, nil)
	oldRecord := &Content{
		IPv4: []IPv4{
			{IPv4: IPv4StrToInt("192.0.2.1")},
			{IPv4: IPv4StrToInt("192.0.2.2")},
			{IPv4: IPv4StrToInt("192.0.2.3")},
		},
		IPv6: []IPv6{
			{IPv6: net.ParseIP("2001:db8::1")},
			{IPv6: net.ParseIP("2001:db8::2")},
			{IPv6: net.ParseIP("2001:db8::3")},
		},
		SubnetIPv4: []SubnetIPv4{
			{SubnetIPv4: "198.51.100.0/24"},
			{SubnetIPv4: "203.0.113.0/24"},
			{SubnetIPv4: "192.0.2.0/24"},
		},
		SubnetIPv6: []SubnetIPv6{
			{SubnetIPv6: "2001:db8:1::/48"},
			{SubnetIPv6: "2001:db8:2::/48"},
			{SubnetIPv6: "2001:db8:3::/48"},
		},
		Domain: []Domain{
			{Domain: "old-one.example"},
			{Domain: "kept.example"},
			{Domain: "old-two.example"},
		},
		URL: []URL{
			{URL: "http://old-one.example/a"},
			{URL: "https://kept.example/b"},
			{URL: "http://old-two.example/c"},
		},
	}

	dump.ExtractAndApplyIPv4(oldRecord, pack)
	dump.ExtractAndApplyIPv6(oldRecord, pack)
	dump.ExtractAndApplySubnetIPv4(oldRecord, pack)
	dump.ExtractAndApplySubnetIPv6(oldRecord, pack)
	dump.ExtractAndApplyDomain(oldRecord, pack)
	dump.ExtractAndApplyURL(oldRecord, pack)

	newRecord := &Content{
		IPv4: []IPv4{
			{IPv4: IPv4StrToInt("192.0.2.2")},
			{IPv4: IPv4StrToInt("192.0.2.4")},
		},
		IPv6: []IPv6{
			{IPv6: net.ParseIP("2001:db8::2")},
			{IPv6: net.ParseIP("2001:db8::4")},
		},
		SubnetIPv4: []SubnetIPv4{
			{SubnetIPv4: "203.0.113.0/24"},
			{SubnetIPv4: "198.18.0.0/15"},
		},
		SubnetIPv6: []SubnetIPv6{
			{SubnetIPv6: "2001:db8:2::/48"},
			{SubnetIPv6: "2001:db8:4::/48"},
		},
		Domain: []Domain{
			{Domain: "kept.example"},
			{Domain: "new.example"},
		},
		URL: []URL{
			{URL: "https://kept.example/b"},
			{URL: "http://new.example/d"},
		},
	}

	dump.EctractAndApplyUpdateIPv4(newRecord, pack)
	dump.EctractAndApplyUpdateIPv6(newRecord, pack)
	dump.EctractAndApplyUpdateSubnetIPv4(newRecord, pack)
	dump.EctractAndApplyUpdateSubnetIPv6(newRecord, pack)
	dump.EctractAndApplyUpdateDomain(newRecord, pack)
	dump.EctractAndApplyUpdateURL(newRecord, pack)

	assertUint32ID(t, dump.IPv4Index, IPv4StrToInt("192.0.2.1"), pack.ID, false)
	assertUint32ID(t, dump.IPv4Index, IPv4StrToInt("192.0.2.2"), pack.ID, true)
	assertUint32ID(t, dump.IPv4Index, IPv4StrToInt("192.0.2.3"), pack.ID, false)
	assertUint32ID(t, dump.IPv4Index, IPv4StrToInt("192.0.2.4"), pack.ID, true)

	assertStringID(t, dump.IPv6Index, string(net.ParseIP("2001:db8::1")), pack.ID, false)
	assertStringID(t, dump.IPv6Index, string(net.ParseIP("2001:db8::2")), pack.ID, true)
	assertStringID(t, dump.IPv6Index, string(net.ParseIP("2001:db8::3")), pack.ID, false)
	assertStringID(t, dump.IPv6Index, string(net.ParseIP("2001:db8::4")), pack.ID, true)

	assertStringID(t, dump.subnetIPv4Index, "198.51.100.0/24", pack.ID, false)
	assertStringID(t, dump.subnetIPv4Index, "203.0.113.0/24", pack.ID, true)
	assertStringID(t, dump.subnetIPv4Index, "192.0.2.0/24", pack.ID, false)
	assertStringID(t, dump.subnetIPv4Index, "198.18.0.0/15", pack.ID, true)

	assertStringID(t, dump.subnetIPv6Index, "2001:db8:1::/48", pack.ID, false)
	assertStringID(t, dump.subnetIPv6Index, "2001:db8:2::/48", pack.ID, true)
	assertStringID(t, dump.subnetIPv6Index, "2001:db8:3::/48", pack.ID, false)
	assertStringID(t, dump.subnetIPv6Index, "2001:db8:4::/48", pack.ID, true)

	assertStringID(t, dump.domainIndex, NormalizeDomain("old-one.example"), pack.ID, false)
	assertStringID(t, dump.domainIndex, NormalizeDomain("kept.example"), pack.ID, true)
	assertStringID(t, dump.domainIndex, NormalizeDomain("old-two.example"), pack.ID, false)
	assertStringID(t, dump.domainIndex, NormalizeDomain("new.example"), pack.ID, true)

	assertStringID(t, dump.URLIndex, NormalizeURL("http://old-one.example/a"), pack.ID, false)
	assertStringID(t, dump.URLIndex, NormalizeURL("https://kept.example/b"), pack.ID, true)
	assertStringID(t, dump.URLIndex, NormalizeURL("http://old-two.example/c"), pack.ID, false)
	assertStringID(t, dump.URLIndex, NormalizeURL("http://new.example/d"), pack.ID, true)

	if len(pack.IPv4) != len(newRecord.IPv4) ||
		len(pack.IPv6) != len(newRecord.IPv6) ||
		len(pack.SubnetIPv4) != len(newRecord.SubnetIPv4) ||
		len(pack.SubnetIPv6) != len(newRecord.SubnetIPv6) ||
		len(pack.Domain) != len(newRecord.Domain) ||
		len(pack.URL) != len(newRecord.URL) {
		t.Fatalf("packed content slices were not rebound to the new record")
	}
}

func assertStringID(t *testing.T, index StringSearchIndex, key string, id int32, want bool) {
	t.Helper()

	got := false
	for _, v := range index[key] {
		if v == id {
			got = true
			break
		}
	}

	if got != want {
		t.Fatalf("index[%q] id %d: got %t, want %t", key, id, got, want)
	}
}

func assertUint32ID(t *testing.T, index Uint32SearchIndex, key uint32, id int32, want bool) {
	t.Helper()

	got := false
	for _, v := range index[key] {
		if v == id {
			got = true
			break
		}
	}

	if got != want {
		t.Fatalf("index[%d] id %d: got %t, want %t", key, id, got, want)
	}
}
