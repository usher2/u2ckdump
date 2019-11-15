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
	ip      Ip4Set
	ip6     StringSet
	subnet  StringSet
	subnet6 StringSet
	url     StringSet
	domain  StringSet
	Content TContentMap
}

func NewTDump() *TDump {
	return &TDump{
		ip:      make(Ip4Set),
		ip6:     make(StringSet),
		subnet:  make(StringSet),
		subnet6: make(StringSet),
		url:     make(StringSet),
		domain:  make(StringSet),
		Content: TContentMap{C: make(map[int]*TXContent)},
	}
}

func (t *TDump) AddIp(ip uint32, id int) {
	t.ip.Add(ip, id)
}

func (t *TDump) DeleteIp(ip uint32, id int) {
	t.ip.Delete(ip, id)
}

func (t *TDump) AddIp6(i string, id int) {
	t.ip6.Add(i, id)
}
func (t *TDump) DeleteIp6(i string, id int) {
	t.ip6.Delete(i, id)
}

func (t *TDump) AddSubnet(i string, id int) {
	t.subnet.Add(i, id)
}
func (t *TDump) DeleteSubnet(i string, id int) {
	t.subnet.Delete(i, id)
}

func (t *TDump) AddSubnet6(i string, id int) {
	t.subnet6.Add(i, id)
}
func (t *TDump) DeleteSubnet6(i string, id int) {
	t.subnet6.Delete(i, id)
}

func (t *TDump) AddUrl(i string, id int) {
	t.url.Add(i, id)
}
func (t *TDump) DeleteUrl(i string, id int) {
	t.url.Delete(i, id)
}

func (t *TDump) AddDomain(i string, id int) {
	t.domain.Add(i, id)
}
func (t *TDump) DeleteDomain(i string, id int) {
	t.domain.Delete(i, id)
}

var DumpSnap = NewTDump()

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
