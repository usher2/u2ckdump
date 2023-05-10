package main

import (
	"net"
	"sync"
	"time"

	"github.com/yl2chen/cidranger"
	"golang.org/x/net/publicsuffix"

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
	utime             int64
	IPv4Index         Uint32SearchIndex
	IPv6Index         StringSearchIndex
	subnetIPv4Index   StringSearchIndex
	subnetIPv6Index   StringSearchIndex
	URLIndex          StringSearchIndex
	domainIndex       StringSearchIndex
	decisionIndex     Uint64SearchIndex
	ContentIndex      MinContentMap
	netTree           cidranger.Ranger
	publicSuffixIndex StringSearchIndex
	entryTypeIndex    Uint32SearchIndex
}

func NewDump() *Dump {
	return &Dump{
		utime:             0,
		IPv4Index:         make(Uint32SearchIndex),
		IPv6Index:         make(StringSearchIndex),
		subnetIPv4Index:   make(StringSearchIndex),
		subnetIPv6Index:   make(StringSearchIndex),
		URLIndex:          make(StringSearchIndex),
		domainIndex:       make(StringSearchIndex),
		decisionIndex:     make(Uint64SearchIndex),
		ContentIndex:      make(MinContentMap),
		netTree:           cidranger.NewPCTrieRanger(),
		publicSuffixIndex: make(StringSearchIndex),
		entryTypeIndex:    make(Uint32SearchIndex),
	}
}

func (d *Dump) InsertToIPv4Index(ip4 uint32, id int32) {
	d.IPv4Index.Insert(ip4, id)
}

func (d *Dump) RemoveFromIPv4Index(ip4 uint32, id int32) {
	d.IPv4Index.Remove(ip4, id)
}

func (d *Dump) InsertToIPv6Index(ip6 string, id int32) {
	d.IPv6Index.Insert(ip6, id)
}

func (d *Dump) RemoveFromIPv6Index(ip6 string, id int32) {
	d.IPv6Index.Remove(ip6, id)
}

func (d *Dump) InsertToSubnetIPv4Index(subnet4 string, id int32) {
	if d.subnetIPv4Index.Insert(subnet4, id) {
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

func (d *Dump) RemoveFromSubnetIPv4Index(subnet4 string, id int32) {
	if d.subnetIPv4Index.Remove(subnet4, id) {
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

func (d *Dump) InsertToSubnetIPv6Index(subnet6 string, id int32) {
	if d.subnetIPv6Index.Insert(subnet6, id) {
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

func (d *Dump) RemoveFromSubnetIPv6Index(subnet6 string, id int32) {
	if d.subnetIPv6Index.Remove(subnet6, id) {
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

func (d *Dump) InsertToURLIndex(url string, id int32) {
	d.URLIndex.Insert(url, id)
}

func (d *Dump) RemoveFromURLIndex(url string, id int32) {
	d.URLIndex.Remove(url, id)
}

func (d *Dump) InsertToDomainIndex(domain string, id int32) {
	d.domainIndex.Insert(domain, id)
	if suffix, _ := publicsuffix.PublicSuffix(domain); suffix != "" {
		d.publicSuffixIndex.Insert(suffix, id)
	}
}

func (d *Dump) RemoveFromDomainIndex(domain string, id int32) {
	d.domainIndex.Remove(domain, id)
	if suffix, _ := publicsuffix.PublicSuffix(domain); suffix != "" {
		d.publicSuffixIndex.Remove(suffix, id)
	}
}

func (d *Dump) InsertToDecisionIndex(decision uint64, id int32) {
	d.decisionIndex.Insert(decision, id)
}

func (d *Dump) RemoveFromDecisionIndex(decision uint64, id int32) {
	d.decisionIndex.Remove(decision, id)
}

func (d *Dump) InsertToEntryTypeIndex(entryType int32, id int32) {
	d.entryTypeIndex.Insert(uint32(entryType), id)
}

func (d *Dump) RemoveFromEntryTypeIndex(entryType int32, id int32) {
	d.entryTypeIndex.Remove(uint32(entryType), id)
}

var CurrentDump = NewDump()

type Reg struct {
	UpdateTime         int64
	UpdateTimeUrgently string
	FormatVersion      string
}

func UpdateDumpTime(UpdateTime int64) {
	CurrentDump.Lock()
	for _, v := range CurrentDump.ContentIndex {
		v.RegistryUpdateTime = UpdateTime
	}
	CurrentDump.utime = UpdateTime
	CurrentDump.Unlock()
}
