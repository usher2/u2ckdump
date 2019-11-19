package main

import (
	"hash/crc32"
	"net"
	"sync"

	pb "github.com/usher-2/u2ckdump/msg"
	"github.com/yl2chen/cidranger"
)

type (
	Nothing     struct{}
	IntSet      map[int32]Nothing
	ArrayIntSet []int32
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
	C map[int32]*pb.Content
}

type TDump struct {
	utime   int64
	ip      Ip4Set
	ip6     StringIntSet
	subnet  StringIntSet
	subnet6 StringIntSet
	net     cidranger.Ranger
	url     StringIntSet
	domain  StringIntSet
	Content TContentMap
}

func NewTDump() *TDump {
	return &TDump{
		utime:   0,
		ip:      make(Ip4Set),
		ip6:     make(StringIntSet),
		subnet:  make(StringIntSet),
		subnet6: make(StringIntSet),
		url:     make(StringIntSet),
		domain:  make(StringIntSet),
		Content: TContentMap{C: make(map[int32]*pb.Content)},
		net:     cidranger.NewPCTrieRanger(),
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

var crc32Table = crc32.MakeTable(crc32.Castagnoli)

func Parse2(UpdateTime int64) {
	DumpSnap.Content.Lock()
	for _, v := range DumpSnap.Content.C {
		v.RegistryUpdateTime = UpdateTime
	}
	DumpSnap.Content.Unlock()
}

func (a ArrayIntSet) Blank() bool { return len(a) == 0 }

func (a ArrayIntSet) Add(v int32) ArrayIntSet {
	for i := range a {
		if a[i] == v {
			return a
		}
	}
	return append(a, v)
}

func (a ArrayIntSet) Del(v int32) ArrayIntSet {
	idx := -1
	for i := range a {
		if a[i] == v {
			idx = i
			break
		}
	}
	if idx == -1 {
		return a
	}
	return append(a[:idx], a[idx+1:]...)
}
