package main

import (
	"net"
	"sync"

	pb "github.com/usher-2/u2ckdump/msg"
	"github.com/yl2chen/cidranger"
)

type (
	Nothing        struct{}
	IntSet         map[int32]Nothing
	TMinContentMap map[int32]*TMinContent
	TPbContentMap  map[int32]*pb.Content
)

var NothingV = Nothing{}

type Stat struct {
	Cnt            int
	CntAdd         int
	CntUpdate      int
	CntRemove      int
	MaxArrayIntSet int
	MaxContentSize int
}

var Stats Stat

type TDump struct {
	sync.RWMutex
	utime    int64
	ip       Ip4Set
	ip6      StringIntSet
	subnet   StringIntSet
	subnet6  StringIntSet
	net      cidranger.Ranger
	url      StringIntSet
	domain   StringIntSet
	Content  TMinContentMap
	Protobuf TPbContentMap
}

func NewTDump() *TDump {
	return &TDump{
		utime:    0,
		ip:       make(Ip4Set),
		ip6:      make(StringIntSet),
		subnet:   make(StringIntSet),
		subnet6:  make(StringIntSet),
		url:      make(StringIntSet),
		domain:   make(StringIntSet),
		Content:  make(TMinContentMap),
		Protobuf: make(TPbContentMap),
		net:      cidranger.NewPCTrieRanger(),
	}
}

func (t *TDump) AddIp(ip uint32, id int32) {
	t.ip.Add(ip, id)
}

func (t *TDump) DeleteIp(ip uint32, id int32) {
	t.ip.Delete(ip, id)
}

func (t *TDump) AddIp6(i string, id int32) {
	t.ip6.Add(i, id)
}
func (t *TDump) DeleteIp6(i string, id int32) {
	t.ip6.Delete(i, id)
}

func (t *TDump) AddSubnet(i string, id int32) {
	if t.subnet.Add(i, id) {
		_, network, err := net.ParseCIDR(i)
		if err != nil {
			Debug.Printf("Can't parse CIDR: %s: %s\n", i, err.Error())
		}
		err = t.net.Insert(cidranger.NewBasicRangerEntry(*network))
		if err != nil {
			Debug.Printf("Can't insert CIDR: %s: %s\n", i, err.Error())
		}
	}
}
func (t *TDump) DeleteSubnet(i string, id int32) {
	if t.subnet.Delete(i, id) {
		_, network, err := net.ParseCIDR(i)
		if err != nil {
			Debug.Printf("Can't parse CIDR: %s: %s\n", i, err.Error())
		}
		_, err = t.net.Remove(*network)
		if err != nil {
			Debug.Printf("Can't remove CIDR: %s: %s\n", i, err.Error())
		}
	}
}

func (t *TDump) AddSubnet6(i string, id int32) {
	if t.subnet6.Add(i, id) {
		_, network, err := net.ParseCIDR(i)
		if err != nil {
			Debug.Printf("Can't parse CIDR: %s: %s\n", i, err.Error())
		}
		err = t.net.Insert(cidranger.NewBasicRangerEntry(*network))
		if err != nil {
			Debug.Printf("Can't insert CIDR: %s: %s\n", i, err.Error())
		}
	}
}
func (t *TDump) DeleteSubnet6(i string, id int32) {
	if t.subnet6.Delete(i, id) {
		_, network, err := net.ParseCIDR(i)
		if err != nil {
			Debug.Printf("Can't parse CIDR: %s: %s\n", i, err.Error())
		}
		_, err = t.net.Remove(*network)
		if err != nil {
			Debug.Printf("Can't remove CIDR: %s: %s\n", i, err.Error())
		}
	}
}

func (t *TDump) AddUrl(i string, id int32) {
	t.url.Add(i, id)
}
func (t *TDump) DeleteUrl(i string, id int32) {
	t.url.Delete(i, id)
}

func (t *TDump) AddDomain(i string, id int32) {
	t.domain.Add(i, id)
}
func (t *TDump) DeleteDomain(i string, id int32) {
	t.domain.Delete(i, id)
}

var DumpSnap = NewTDump()

type TReg struct {
	UpdateTime         int64
	UpdateTimeUrgently string
	FormatVersion      string
}

func Parse2(UpdateTime int64) {
	DumpSnap.Lock()
	for _, v := range DumpSnap.Protobuf {
		v.RegistryUpdateTime = UpdateTime
	}
	DumpSnap.Unlock()
}
