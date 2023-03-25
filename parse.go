package main

import (
	"net"
	"sync"

	"github.com/yl2chen/cidranger"

	"github.com/usher2/u2ckdump/internal/logger"
)

type (
	Nothing       struct{}
	Int32Map      map[int32]Nothing
	MinContentMap map[int32]*PackedContent
)

type Stat struct {
	Cnt            int
	CntAdd         int
	CntUpdate      int
	CntRemove      int
	MaxArrayIntSet int
	MaxContentSize int
}

var Stats Stat

type Dump struct {
	sync.RWMutex
	utime    int64
	ip4      IP4Set
	ip6      StringIntSet
	subnet4  StringIntSet
	subnet6  StringIntSet
	net      cidranger.Ranger
	url      StringIntSet
	domain   StringIntSet
	decision DecisionSet
	Content  MinContentMap
}

func NewDump() *Dump {
	return &Dump{
		utime:    0,
		ip4:      make(IP4Set),
		ip6:      make(StringIntSet),
		subnet4:  make(StringIntSet),
		subnet6:  make(StringIntSet),
		url:      make(StringIntSet),
		domain:   make(StringIntSet),
		decision: make(DecisionSet),
		Content:  make(MinContentMap),
		net:      cidranger.NewPCTrieRanger(),
	}
}

func (d *Dump) AddIp(ip4 uint32, id int32) {
	d.ip4.Add(ip4, id)
}

func (d *Dump) DeleteIp(ip4 uint32, id int32) {
	d.ip4.Delete(ip4, id)
}

func (d *Dump) AddIp6(ip6 string, id int32) {
	d.ip6.Add(ip6, id)
}

func (d *Dump) DeleteIp6(ip6 string, id int32) {
	d.ip6.Delete(ip6, id)
}

func (d *Dump) AddSubnet(subnet4 string, id int32) {
	if d.subnet4.Add(subnet4, id) {
		_, network, err := net.ParseCIDR(subnet4)
		if err != nil {
			logger.Debug.Printf("Can't parse CIDR: %s: %s\n", subnet4, err.Error())
		}
		err = d.net.Insert(cidranger.NewBasicRangerEntry(*network))
		if err != nil {
			logger.Debug.Printf("Can't insert CIDR: %s: %s\n", subnet4, err.Error())
		}
	}
}

func (d *Dump) DeleteSubnet(subnet4 string, id int32) {
	if d.subnet4.Delete(subnet4, id) {
		_, network, err := net.ParseCIDR(subnet4)
		if err != nil {
			logger.Debug.Printf("Can't parse CIDR: %s: %s\n", subnet4, err.Error())
		}
		_, err = d.net.Remove(*network)
		if err != nil {
			logger.Debug.Printf("Can't remove CIDR: %s: %s\n", subnet4, err.Error())
		}
	}
}

func (d *Dump) AddSubnet6(subnet6 string, id int32) {
	if d.subnet6.Add(subnet6, id) {
		_, network, err := net.ParseCIDR(subnet6)
		if err != nil {
			logger.Debug.Printf("Can't parse CIDR: %s: %s\n", subnet6, err.Error())
		}
		err = d.net.Insert(cidranger.NewBasicRangerEntry(*network))
		if err != nil {
			logger.Debug.Printf("Can't insert CIDR: %s: %s\n", subnet6, err.Error())
		}
	}
}

func (d *Dump) DeleteSubnet6(subnet6 string, id int32) {
	if d.subnet6.Delete(subnet6, id) {
		_, network, err := net.ParseCIDR(subnet6)
		if err != nil {
			logger.Debug.Printf("Can't parse CIDR: %s: %s\n", subnet6, err.Error())
		}
		_, err = d.net.Remove(*network)
		if err != nil {
			logger.Debug.Printf("Can't remove CIDR: %s: %s\n", subnet6, err.Error())
		}
	}
}

func (d *Dump) AddUrl(url string, id int32) {
	d.url.Add(url, id)
}

func (d *Dump) DeleteUrl(url string, id int32) {
	d.url.Delete(url, id)
}

func (d *Dump) AddDomain(domain string, id int32) {
	d.domain.Add(domain, id)
}

func (d *Dump) DeleteDomain(domain string, id int32) {
	d.domain.Delete(domain, id)
}

func (d *Dump) AddDecision(decision uint64, id int32) {
	d.decision.Add(decision, id)
}

func (d *Dump) DeleteDecision(decision uint64, id int32) {
	d.decision.Delete(decision, id)
}

var CurrentDump = NewDump()

type Reg struct {
	UpdateTime         int64
	UpdateTimeUrgently string
	FormatVersion      string
}

func UpdateDumpTime(UpdateTime int64) {
	CurrentDump.Lock()
	for _, v := range CurrentDump.Content {
		v.RegistryUpdateTime = UpdateTime
	}
	CurrentDump.utime = UpdateTime
	CurrentDump.Unlock()
}
