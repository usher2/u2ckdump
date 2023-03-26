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

func (d *Dump) InsertPairIP4xID(ip4 uint32, id int32) {
	d.ip4.Insert(ip4, id)
}

func (d *Dump) DropPairIP4xID(ip4 uint32, id int32) {
	d.ip4.Drop(ip4, id)
}

func (d *Dump) InsertPairIP6xID(ip6 string, id int32) {
	d.ip6.Insert(ip6, id)
}

func (d *Dump) DropPairIP6xID(ip6 string, id int32) {
	d.ip6.Drop(ip6, id)
}

func (d *Dump) InsertPairSubnet4xID(subnet4 string, id int32) {
	if d.subnet4.Insert(subnet4, id) {
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

func (d *Dump) DropPairSubnet4xID(subnet4 string, id int32) {
	if d.subnet4.Drop(subnet4, id) {
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

func (d *Dump) InsertPairSubnet6xID(subnet6 string, id int32) {
	if d.subnet6.Insert(subnet6, id) {
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

func (d *Dump) DropPairSubnet6xID(subnet6 string, id int32) {
	if d.subnet6.Drop(subnet6, id) {
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

func (d *Dump) InsertPairURLxID(url string, id int32) {
	d.url.Insert(url, id)
}

func (d *Dump) DropPairURLxID(url string, id int32) {
	d.url.Drop(url, id)
}

func (d *Dump) InsertPairDomainID(domain string, id int32) {
	d.domain.Insert(domain, id)
}

func (d *Dump) DropPairDomainID(domain string, id int32) {
	d.domain.Drop(domain, id)
}

func (d *Dump) InsertPairDecisionID(decision uint64, id int32) {
	d.decision.Insert(decision, id)
}

func (d *Dump) DropPairDecisionID(decision uint64, id int32) {
	d.decision.Drop(decision, id)
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
