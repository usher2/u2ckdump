package main

import (
	"net"
	"sync"
	"time"

	"github.com/yl2chen/cidranger"

	"github.com/usher2/u2ckdump/internal/logger"
)

type (
	Nothing       struct{}
	Int32Map      map[int32]Nothing
	MinContentMap map[int32]*PackedContent
)

type ParseStatistics struct {
	Count          int
	AddCount       int
	UpdateCount    int
	RemoveCount    int
	MaxIDSetLen    int
	MaxContentSize int
	Updated        time.Time
}

var Stats ParseStatistics

func (s *ParseStatistics) Update() {
	s.Updated = time.Now()
}

type Dump struct {
	sync.RWMutex
	utime       int64
	ip4Idx      IP4Set
	ip6Idx      StringIntSet
	subnet4Idx  StringIntSet
	subnet6Idx  StringIntSet
	netTree     cidranger.Ranger
	urlIdx      StringIntSet
	domainIdx   StringIntSet
	decisionIdx DecisionSet
	ContentIdx  MinContentMap
}

func NewDump() *Dump {
	return &Dump{
		utime:       0,
		ip4Idx:      make(IP4Set),
		ip6Idx:      make(StringIntSet),
		subnet4Idx:  make(StringIntSet),
		subnet6Idx:  make(StringIntSet),
		urlIdx:      make(StringIntSet),
		domainIdx:   make(StringIntSet),
		decisionIdx: make(DecisionSet),
		ContentIdx:  make(MinContentMap),
		netTree:     cidranger.NewPCTrieRanger(),
	}
}

func (d *Dump) InsertToIndexIP4(ip4 uint32, id int32) {
	d.ip4Idx.Insert(ip4, id)
}

func (d *Dump) RemoveFromIndexIP4(ip4 uint32, id int32) {
	d.ip4Idx.Remove(ip4, id)
}

func (d *Dump) InsertToIndexIP6(ip6 string, id int32) {
	d.ip6Idx.Insert(ip6, id)
}

func (d *Dump) RemoveFromIndexIP6(ip6 string, id int32) {
	d.ip6Idx.Remove(ip6, id)
}

func (d *Dump) InsertToIndexSubnet4(subnet4 string, id int32) {
	if d.subnet4Idx.Insert(subnet4, id) {
		_, network, err := net.ParseCIDR(subnet4)
		if err != nil {
			logger.Debug.Printf("Can't parse CIDR: %s: %s\n", subnet4, err.Error())
		}
		err = d.netTree.Insert(cidranger.NewBasicRangerEntry(*network))
		if err != nil {
			logger.Debug.Printf("Can't insert CIDR: %s: %s\n", subnet4, err.Error())
		}
	}
}

func (d *Dump) RemoveFromSubnet4(subnet4 string, id int32) {
	if d.subnet4Idx.Remove(subnet4, id) {
		_, network, err := net.ParseCIDR(subnet4)
		if err != nil {
			logger.Debug.Printf("Can't parse CIDR: %s: %s\n", subnet4, err.Error())
		}
		_, err = d.netTree.Remove(*network)
		if err != nil {
			logger.Debug.Printf("Can't remove CIDR: %s: %s\n", subnet4, err.Error())
		}
	}
}

func (d *Dump) InsertToIndexSubnet6(subnet6 string, id int32) {
	if d.subnet6Idx.Insert(subnet6, id) {
		_, network, err := net.ParseCIDR(subnet6)
		if err != nil {
			logger.Debug.Printf("Can't parse CIDR: %s: %s\n", subnet6, err.Error())
		}
		err = d.netTree.Insert(cidranger.NewBasicRangerEntry(*network))
		if err != nil {
			logger.Debug.Printf("Can't insert CIDR: %s: %s\n", subnet6, err.Error())
		}
	}
}

func (d *Dump) RemoveFromIndexSubnet6(subnet6 string, id int32) {
	if d.subnet6Idx.Remove(subnet6, id) {
		_, network, err := net.ParseCIDR(subnet6)
		if err != nil {
			logger.Debug.Printf("Can't parse CIDR: %s: %s\n", subnet6, err.Error())
		}
		_, err = d.netTree.Remove(*network)
		if err != nil {
			logger.Debug.Printf("Can't remove CIDR: %s: %s\n", subnet6, err.Error())
		}
	}
}

func (d *Dump) InsertToIndexURL(url string, id int32) {
	d.urlIdx.Insert(url, id)
}

func (d *Dump) RemoveFromIndexURL(url string, id int32) {
	d.urlIdx.Remove(url, id)
}

func (d *Dump) InsertToIndexDomain(domain string, id int32) {
	d.domainIdx.Insert(domain, id)
}

func (d *Dump) RemoveFromIndexDomain(domain string, id int32) {
	d.domainIdx.Remove(domain, id)
}

func (d *Dump) InsertToIndexDecision(decision uint64, id int32) {
	d.decisionIdx.Insert(decision, id)
}

func (d *Dump) RemoveFromIndexDecision(decision uint64, id int32) {
	d.decisionIdx.Remove(decision, id)
}

var CurrentDump = NewDump()

type Reg struct {
	UpdateTime         int64
	UpdateTimeUrgently string
	FormatVersion      string
}

func UpdateDumpTime(UpdateTime int64) {
	CurrentDump.Lock()
	for _, v := range CurrentDump.ContentIdx {
		v.RegistryUpdateTime = UpdateTime
	}
	CurrentDump.utime = UpdateTime
	CurrentDump.Unlock()
}
