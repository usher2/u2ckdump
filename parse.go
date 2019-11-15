package main

import (
	"hash/crc32"
	"sync"
)

type (
	Nothing struct{}
	IntSet  map[int]Nothing
)

var NothingV = Nothing{}

type Stats struct {
	Cnt       int
	CntAdd    int
	CntUpdate int
	CntRemove int
}

type TContentMap struct {
	sync.RWMutex
	C map[int]*TXContent
}

type TDump struct {
	Ip      Ip4Set
	Ip6     StringSet
	Subnet  StringSet
	Subnet6 StringSet
	Url     StringSet
	Domain  StringSet
	Content TContentMap
}

var DumpSnap = TDump{
	Ip:      make(Ip4Set),
	Ip6:     make(StringSet),
	Subnet:  make(StringSet),
	Subnet6: make(StringSet),
	Url:     make(StringSet),
	Domain:  make(StringSet),
	Content: TContentMap{C: make(map[int]*TXContent)},
}

type TReg struct {
	UpdateTime         int64
	UpdateTimeUrgently string
	FormatVersion      string
}

type TXDomain struct {
	Domain string `json:"domain"`
	Ts     int64  `json:"ts,omitempty"`
}

type TXUrl struct {
	Url string `json:"url"`
	Ts  int64  `json:"ts,omitempty"`
}

type TXIp struct {
	Ip uint32 `json:"ip"`
	Ts int64  `json:"ts,omitempty"`
}

type TXIp6 struct {
	Ip6 string `json:"ip6"`
	Ts  int64  `json:"ts,omitempty"`
}

type TXSubnet struct {
	Subnet string `json:"subnet"`
	Ts     int64  `json:"ts,omitempty"`
}

type TXSubnet6 struct {
	Subnet6 string `json:"subnet6"`
	Ts      int64  `json:"ts,omitempty"`
}

type TXDecision struct {
	Date   string `json:"date"`
	Number string `json:"number"`
	Org    string `json:"org"`
}

type TXContent struct {
	Id                 int         `json:"id"`
	EntryType          int         `json:"entryType"`
	UrgencyType        int         `json:"urgencyType,omitempty"`
	HTTPSBlock         int         `json:"https,omitempty"`
	RegistryUpdateTime int64       `json:"registry"`
	Decision           TXDecision  `json:"decision"`
	IncludeTime        int64       `json:"includeTime"`
	BlockType          string      `json:"blockType,omitempty"`
	Hash               string      `json:"hash"`
	Ts                 int64       `json:"ts,omitempty"`
	U2Hash             uint32      `xml:"-" json:"-"`
	Url                []TXUrl     `json:"url,omitempty"`
	Ip                 []TXIp      `json:"ip,omitempty"`
	Ip6                []TXIp6     `json:"ip6,omitempty"`
	Subnet             []TXSubnet  `json:"subnet,omitempty"`
	Subnet6            []TXSubnet6 `json:"subnet6,omitempty"`
	Domain             []TXDomain  `json:"domain,omitempty"`
}

var crc32Table = crc32.MakeTable(crc32.Castagnoli)

func Parse2(UpdateTime int64) {
	DumpSnap.Content.Lock()
	for _, v := range DumpSnap.Content.C {
		v.RegistryUpdateTime = UpdateTime
	}
	DumpSnap.Content.Unlock()
}
