package main

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"hash"
	"hash/fnv"
	"io"
	"net"
	"strconv"
	"strings"

	"golang.org/x/net/html/charset"

	"github.com/usher2/u2ckdump/internal/logger"
	pb "github.com/usher2/u2ckdump/msg"
)

const (
	elementContent   = "content"
	elementDecision  = "decision"
	elementURL       = "url"
	elementDomain    = "domain"
	elementIP4       = "ip"
	elementIP6       = "ipv6"
	elementIP4Subnet = "ipSubnet"
	elementIP6Subnet = "ipv6Subnet"
)

var hasher64 hash.Hash64

// UnmarshalContent - unmarshal <content> element.
func UnmarshalContent(contBuf []byte, content *Content) error {
	buf := bytes.NewReader(contBuf)
	decoder := xml.NewDecoder(buf)

	for {
		token, err := decoder.Token()
		if token == nil {
			if err != io.EOF {
				return fmt.Errorf("token: %w", err)
			}

			break
		}

		switch element := token.(type) {
		case xml.StartElement:
			// TODO: one func for one case, handle time parsing
			switch element.Name.Local {
			case elementContent:
				if err := parseContentElement(element, content); err != nil {
					return fmt.Errorf("parse content elm: %w", err)
				}
			case elementDecision:
				if err := decoder.DecodeElement(&content.Decision, &element); err != nil {
					return fmt.Errorf("parse decision elm: %w", err)
				}
			case elementURL:
				u := XMLURL{}
				if err := decoder.DecodeElement(&u, &element); err != nil {
					return fmt.Errorf("parse url elm: %w", err)
				}

				content.URL = append(content.URL, URL{URL: u.URL, Ts: parseRFC3339Time(u.Ts)})
			case elementDomain:
				domain := XMLDomain{}
				if err := decoder.DecodeElement(&domain, &element); err != nil {
					return fmt.Errorf("parse domain elm: %w", err)
				}

				content.Domain = append(content.Domain, Domain{Domain: domain.Domain, Ts: parseRFC3339Time(domain.Ts)})
			case elementIP4:
				ip4 := XMLIP{}
				if err := decoder.DecodeElement(&ip4, &element); err != nil {
					return fmt.Errorf("parse ip elm: %w", err)
				}

				content.IPv4 = append(content.IPv4, IPv4{IP4: IPv4StrToInt(ip4.IP), Ts: parseRFC3339Time(ip4.Ts)})
			case elementIP6:
				ip6 := XMLIP6{}
				if err := decoder.DecodeElement(&ip6, &element); err != nil {
					return fmt.Errorf("parse ipv6 elm: %w", err)
				}

				content.IPv6 = append(content.IPv6, IPv6{IP6: net.ParseIP(ip6.IP6), Ts: parseRFC3339Time(ip6.Ts)})
			case elementIP4Subnet:
				subnet4 := XMLSubnet{}
				if err := decoder.DecodeElement(&subnet4, &element); err != nil {
					return fmt.Errorf("parse subnet elm: %w", err)
				}

				content.SubnetIPv4 = append(content.SubnetIPv4, SubnetIPv4{Subnet4: subnet4.Subnet, Ts: parseRFC3339Time(subnet4.Ts)})
			case elementIP6Subnet:
				subnet6 := XMLSubnet6{}
				if err := decoder.DecodeElement(&subnet6, &element); err != nil {
					return fmt.Errorf("parse ipv6 subnet elm: %w", err)
				}

				content.SubnetIPv6 = append(content.SubnetIPv6, SubnetIPv6{Subnet6: subnet6.Subnet6, Ts: parseRFC3339Time(subnet6.Ts)})
			}
		}
	}

	return nil
}

// pasre <content> element itself.
func parseContentElement(element xml.StartElement, content *Content) error {
	for _, attr := range element.Attr {
		switch attr.Name.Local {
		case "id":
			id, err := strconv.Atoi(attr.Value)
			if err != nil {
				return fmt.Errorf("id atoi: %w: %s", err, attr.Value)
			}

			content.ID = int32(id)
		case "entryType":
			entryType, err := strconv.Atoi(attr.Value)
			if err != nil {
				return fmt.Errorf("entryType atoi: %w: %s", err, attr.Value)
			}

			content.EntryType = int32(entryType)
		case "urgencyType":
			urgencyType, err := strconv.Atoi(attr.Value)
			if err != nil {
				return fmt.Errorf("urgencyType atoi: %w: %s", err, attr.Value)
			}

			content.UrgencyType = int32(urgencyType)
		case "includeTime":
			content.IncludeTime = parseMoscowTime(attr.Value)
		case "blockType":
			content.BlockType = attr.Value
		case "hash":
			content.Hash = attr.Value
		case "ts":
			content.Ts = parseRFC3339Time(attr.Value)
		}
	}

	return nil
}

// Parse - parse dump.
func Parse(dumpFile io.Reader) error {
	var (
		reg                            Reg
		buffer                         bytes.Buffer
		bufferOffset, offsetCorrection int64

		stats ParseStatistics
	)

	hasher64 = fnv.New64a()
	decoder := xml.NewDecoder(dumpFile)

	// we need this closure, we don't want constructor
	decoder.CharsetReader = func(label string, input io.Reader) (io.Reader, error) {
		r, err := charset.NewReaderLabel(label, input)
		if err != nil {
			return nil, err
		}

		offsetCorrection = decoder.InputOffset()

		return io.TeeReader(r, &buffer), nil
	}

	// TODO: What is it?
	ContJournal := make(Int32Map, len(CurrentDump.ContentIndex))

	for {
		tokenStartOffset := decoder.InputOffset() - offsetCorrection

		token, err := decoder.Token()
		if token == nil {
			if err != io.EOF {
				return err
			}

			break
		}

		switch element := token.(type) {
		case xml.StartElement:
			switch element.Name.Local {
			case "register":
				parseRegister(element, &reg)
			case "content":
				id := getContentId(element)

				// parse <content>...</content> only if need
				decoder.Skip()

				// read buffer to mark anyway
				diff := tokenStartOffset - bufferOffset
				buffer.Next(int(diff))
				bufferOffset += diff

				// calc end of element
				tokenStartOffset = decoder.InputOffset() - offsetCorrection

				// create hash of <content>...</content> for comp
				contBuf := buffer.Next(int(tokenStartOffset - bufferOffset))
				if stats.MaxContentSize < len(contBuf) {
					stats.MaxContentSize = len(contBuf)
				}

				bufferOffset = tokenStartOffset

				hasher64.Reset()
				hasher64.Write(contBuf)

				newRecordHash := hasher64.Sum64()

				// create or update
				CurrentDump.Lock()

				prevCont, exists := CurrentDump.ContentIndex[id]
				ContJournal[id] = Nothing{} // add to journal.

				switch {
				case !exists:
					newCont, err := NewContent(newRecordHash, contBuf)
					if err != nil {
						logger.Error.Printf("Decode Error: %s\n", err)

						break
					}

					CurrentDump.NewPackedContent(newCont, reg.UpdateTime)
					stats.AddCount++
				case prevCont.RecordHash != newRecordHash:
					newCont, err := NewContent(newRecordHash, contBuf)
					if err != nil {
						logger.Error.Printf("Decode Error: %s\n", err)

						break
					}

					CurrentDump.MergePackedContent(newCont, prevCont, reg.UpdateTime)
					stats.UpdateCount++
				default:
					CurrentDump.SetContentUpdateTime(id, reg.UpdateTime)
				}

				CurrentDump.Unlock()
				stats.Count++
			}
		}

		// read buffer anyway
		diff := tokenStartOffset - bufferOffset
		buffer.Next(int(diff))
		bufferOffset += diff
	}

	// Cleanup.
	CurrentDump.Cleanup(ContJournal, &stats, reg.UpdateTime)

	stats.Update()
	Stats = stats

	// Print stats.

	logger.Info.Printf("Records: %d Added: %d Updated: %d Removed: %d\n", stats.Count, stats.AddCount, stats.UpdateCount, stats.RemoveCount)
	logger.Info.Printf("  IP: %d IPv6: %d Subnets: %d Subnets6: %d Domains: %d URSs: %d\n",
		len(CurrentDump.IPv4Index), len(CurrentDump.IPv6Index), len(CurrentDump.subnetIPv4Index), len(CurrentDump.subnetIPv6Index),
		len(CurrentDump.domainIndex), len(CurrentDump.URLIndex))
	logger.Info.Printf("Biggest array: %d\n", stats.MaxIDSetLen)
	logger.Info.Printf("Biggest content: %d\n", stats.MaxContentSize)

	return nil
}

func NewContent(recordHash uint64, buf []byte) (*Content, error) {
	content := &Content{
		RecordHash: recordHash,
	}

	err := UnmarshalContent(buf, content)
	if err != nil {
		return nil, err
	}

	return content, nil
}

func (dump *Dump) Cleanup(existed Int32Map, stats *ParseStatistics, utime int64) {
	dump.Lock()
	defer dump.Unlock()

	dump.purge(existed, stats)   // remove deleted records from index.
	dump.calcMaxEntityLen(stats) // calc max entity len.
	dump.utime = utime           // set global update time.
}

func (dump *Dump) calcMaxEntityLen(stats *ParseStatistics) {
	stats.MaxIDSetLen = 0

	for _, a := range dump.IPv4Index {
		if stats.MaxIDSetLen < len(a) {
			stats.MaxIDSetLen = len(a)
		}
	}
	for _, a := range dump.IPv6Index {
		if stats.MaxIDSetLen < len(a) {
			stats.MaxIDSetLen = len(a)
		}
	}
	for _, a := range dump.subnetIPv4Index {
		if stats.MaxIDSetLen < len(a) {
			stats.MaxIDSetLen = len(a)
		}
	}
	for _, a := range dump.subnetIPv6Index {
		if stats.MaxIDSetLen < len(a) {
			stats.MaxIDSetLen = len(a)
		}
	}
	for _, a := range dump.URLIndex {
		if stats.MaxIDSetLen < len(a) {
			stats.MaxIDSetLen = len(a)
		}
	}
	for _, a := range dump.domainIndex {
		if stats.MaxIDSetLen < len(a) {
			stats.MaxIDSetLen = len(a)
		}
	}
}

// purge - remove deleted records from index.
func (dump *Dump) purge(existed Int32Map, stats *ParseStatistics) {
	for id, cont := range dump.ContentIndex {
		if _, ok := existed[id]; !ok {
			for _, ip4 := range cont.IPv4 {
				dump.RemoveFromIPv4Index(ip4.IP4, cont.ID)
			}

			for _, ip6 := range cont.IPv6 {
				ip6 := string(ip6.IP6)
				dump.RemoveFromIPv6Index(ip6, cont.ID)
			}

			for _, subnet6 := range cont.SubnetIPv6 {
				dump.RemoveFromSubnetIPv6Index(subnet6.Subnet6, cont.ID)
			}

			for _, subnet4 := range cont.SubnetIPv4 {
				dump.RemoveFromSubnetIPv4Index(subnet4.Subnet4, cont.ID)
			}

			for _, u := range cont.URL {
				dump.RemoveFromURLIndex(NormalizeURL(u.URL), cont.ID)
			}

			for _, domain := range cont.Domain {
				dump.RemoveFromDomainIndex(NormalizeDomain(domain.Domain), cont.ID)
			}

			dump.RemoveFromDecisionIndex(cont.Decision, cont.ID)
			dump.RemoveFromEntryTypeIndex(cont.EntryType, cont.ID)

			delete(dump.ContentIndex, id)

			stats.RemoveCount++
		}
	}
}

// Marshal - encodes content to JSON.
func (record *Content) Marshal() []byte {
	b, err := json.Marshal(record)
	if err != nil {
		logger.Error.Printf("Error encoding: %s\n", err.Error())
	}
	return b
}

// constructBlockType - returns block type for content.
func (record *Content) constructBlockType() int32 {
	switch record.BlockType {
	case "ip":
		return BlockTypeIP
	case "domain":
		return BlockTypeDomain
	case "domain-mask":
		return BlockTypeMask
	default:
		if record.BlockType != "default" && record.BlockType != "" {
			logger.Error.Printf("Unknown block type: %s\n", record.BlockType)
		}
		if record.HTTPSBlock == 0 {
			return BlockTypeURL
		} else {
			return BlockTypeHTTPS
		}
	}
}

func (dump *Dump) SetContentUpdateTime(id int32, updateTime int64) {
	dump.ContentIndex[id].RegistryUpdateTime = dump.utime
}

// MergePackedContent - merges new content with previous one.
// It is used to update existing content.
func (dump *Dump) MergePackedContent(record *Content, prev *PackedContent, updateTime int64) {
	prev.refreshPackedContent(record.RecordHash, updateTime, record.Marshal())

	dump.EctractAndApplyUpdateIPv4(record, prev)
	dump.EctractAndApplyUpdateIPv6(record, prev)
	dump.EctractAndApplyUpdateSubnetIPv4(record, prev)
	dump.EctractAndApplyUpdateSubnetIPv6(record, prev)
	dump.EctractAndApplyUpdateDomain(record, prev)
	dump.EctractAndApplyUpdateURL(record, prev)
	dump.EctractAndApplyUpdateDecision(record, prev)  // reason for ALARM!!!
	dump.EctractAndApplyUpdateEntryType(record, prev) // reason for ALARM!!!
}

// NewPackedContent - creates new content.
// It is used to add new content.
func (dump *Dump) NewPackedContent(record *Content, updateTime int64) {
	fresh := newPackedContent(record.ID, record.RecordHash, updateTime, record.Marshal())
	dump.ContentIndex[record.ID] = fresh

	dump.ExtractAndApplyIPv4(record, fresh)
	dump.ExtractAndApplyIPv6(record, fresh)
	dump.ExtractAndApplySubnetIPv4(record, fresh)
	dump.ExtractAndApplySubnetIPv6(record, fresh)
	dump.ExtractAndApplyDomain(record, fresh)
	dump.ExtractAndApplyURL(record, fresh)
	dump.ExtractAndApplyDecision(record, fresh)
	dump.ExtractAndApplyEntryType(record, fresh)
}

func (dump *Dump) ExtractAndApplyEntryType(record *Content, pack *PackedContent) {
	pack.EntryType = record.EntryType
	dump.InsertToEntryTypeIndex(pack.EntryType, pack.ID)
}

// IT IS REASON FOR ALARM!!!!
func (dump *Dump) EctractAndApplyUpdateEntryType(record *Content, pack *PackedContent) {
	dump.RemoveFromEntryTypeIndex(pack.EntryType, pack.ID)

	pack.EntryType = record.EntryType

	dump.InsertToEntryTypeIndex(pack.EntryType, pack.ID)
}

func (dump *Dump) ExtractAndApplyDecision(record *Content, pack *PackedContent) {
	pack.Decision = hashDecision(&record.Decision)
	dump.InsertToDecisionIndex(pack.Decision, pack.ID)
}

// IT IS REASON FOR ALARM!!!!
func (dump *Dump) EctractAndApplyUpdateDecision(record *Content, pack *PackedContent) {
	dump.RemoveFromDecisionIndex(pack.Decision, pack.ID)

	pack.Decision = hashDecision(&record.Decision)

	dump.InsertToDecisionIndex(pack.Decision, pack.ID)
}

func hashDecision(decision *Decision) uint64 {
	// hash.Write([]byte(v0.Decision.Org + " " + v0.Decision.Number + " " + v0.Decision.Date))
	hasher64.Reset()
	hasher64.Write([]byte(decision.Org))
	hasher64.Write([]byte(" "))
	hasher64.Write([]byte(decision.Number))
	hasher64.Write([]byte(" "))
	hasher64.Write([]byte(decision.Date))
	return hasher64.Sum64()
}

func (dump *Dump) ExtractAndApplyIPv4(record *Content, pack *PackedContent) {
	if len(record.IPv4) > 0 {
		pack.IPv4 = record.IPv4
		for _, ip4 := range pack.IPv4 {
			dump.InsertToIPv4Index(ip4.IP4, pack.ID)
		}
	}
}

func (dump *Dump) EctractAndApplyUpdateIPv4(record *Content, pack *PackedContent) {
	ipExisted := make(map[uint32]Nothing, len(pack.IPv4))
	if len(record.IPv4) > 0 {
		for _, ip4 := range record.IPv4 {
			pack.InsertIPv4(ip4)
			dump.InsertToIPv4Index(ip4.IP4, pack.ID)
			ipExisted[ip4.IP4] = Nothing{}
		}
	}

	for _, ip4 := range pack.IPv4 {
		if _, ok := ipExisted[ip4.IP4]; !ok {
			pack.RemoveIPv4(ip4)
			dump.RemoveFromIPv4Index(ip4.IP4, pack.ID)
		}
	}
}

func (pack *PackedContent) InsertIPv4(ip4 IPv4) {
	for _, existedIP4 := range pack.IPv4 {
		if ip4 == existedIP4 {
			return
		}
	}

	pack.IPv4 = append(pack.IPv4, ip4)
}

func (pack *PackedContent) RemoveIPv4(ip4 IPv4) {
	for i, existedIP4 := range pack.IPv4 {
		if ip4 == existedIP4 {
			pack.IPv4 = append(pack.IPv4[:i], pack.IPv4[i+1:]...)

			return
		}
	}
}

func (dump *Dump) ExtractAndApplyIPv6(record *Content, pack *PackedContent) {
	if len(record.IPv6) > 0 {
		pack.IPv6 = record.IPv6
		for _, ip4 := range pack.IPv6 {
			dump.InsertToIPv6Index(string(ip4.IP6), pack.ID)
		}
	}
}

func (dump *Dump) EctractAndApplyUpdateIPv6(record *Content, pack *PackedContent) {
	ipExisted := make(map[string]Nothing, len(pack.IPv6))
	if len(record.IPv6) > 0 {
		for _, ip6 := range record.IPv6 {
			pack.InsertIPv6(ip6)

			addr := string(ip6.IP6)
			dump.InsertToIPv6Index(addr, pack.ID)
			ipExisted[addr] = Nothing{}
		}
	}

	for _, ip6 := range pack.IPv6 {
		if _, ok := ipExisted[string(ip6.IP6)]; !ok {
			pack.RemoveIPv6(ip6)
			dump.RemoveFromIPv6Index(string(ip6.IP6), pack.ID)
		}
	}
}

func (pack *PackedContent) InsertIPv6(ip6 IPv6) {
	for _, existedIP6 := range pack.IPv6 {
		if string(ip6.IP6) == string(existedIP6.IP6) && ip6.Ts == existedIP6.Ts {
			return
		}
	}

	pack.IPv6 = append(pack.IPv6, ip6)
}

func (pack *PackedContent) RemoveIPv6(ip6 IPv6) {
	for i, existedIP6 := range pack.IPv6 {
		if string(ip6.IP6) == string(existedIP6.IP6) && ip6.Ts == existedIP6.Ts {
			pack.IPv6 = append(pack.IPv6[:i], pack.IPv6[i+1:]...)

			return
		}
	}
}

func (dump *Dump) ExtractAndApplySubnetIPv4(record *Content, pack *PackedContent) {
	if len(record.SubnetIPv4) > 0 {
		pack.SubnetIPv4 = record.SubnetIPv4
		for _, subnet4 := range pack.SubnetIPv4 {
			dump.InsertToSubnetIPv4Index(subnet4.Subnet4, pack.ID)
		}
	}
}

func (dump *Dump) EctractAndApplyUpdateSubnetIPv4(record *Content, pack *PackedContent) {
	subnetExisted := NewStringSet(len(pack.SubnetIPv4))
	if len(record.SubnetIPv4) > 0 {
		for _, subnet4 := range record.SubnetIPv4 {
			pack.InsertSubnetIPv4(subnet4)
			dump.InsertToSubnetIPv4Index(subnet4.Subnet4, pack.ID)
			subnetExisted[subnet4.Subnet4] = Nothing{}
		}
	}

	for _, subnet4 := range pack.SubnetIPv4 {
		if _, ok := subnetExisted[subnet4.Subnet4]; !ok {
			pack.RemoveSubnetIPv4(subnet4)
			dump.RemoveFromSubnetIPv4Index(subnet4.Subnet4, pack.ID)
		}
	}
}

func (pack *PackedContent) InsertSubnetIPv4(subnet4 SubnetIPv4) {
	for _, existedSubnet4 := range pack.SubnetIPv4 {
		if subnet4 == existedSubnet4 {
			return
		}
	}

	pack.SubnetIPv4 = append(pack.SubnetIPv4, subnet4)
}

func (pack *PackedContent) RemoveSubnetIPv4(subnet4 SubnetIPv4) {
	for i, existedSubnet4 := range pack.SubnetIPv4 {
		if subnet4 == existedSubnet4 {
			pack.SubnetIPv4 = append(pack.SubnetIPv4[:i], pack.SubnetIPv4[i+1:]...)

			return
		}
	}
}

func (dump *Dump) ExtractAndApplySubnetIPv6(record *Content, pack *PackedContent) {
	if len(record.SubnetIPv6) > 0 {
		pack.SubnetIPv6 = record.SubnetIPv6
		for _, subnet6 := range pack.SubnetIPv6 {
			dump.InsertToSubnetIPv4Index(subnet6.Subnet6, pack.ID)
		}
	}
}

func (dump *Dump) EctractAndApplyUpdateSubnetIPv6(record *Content, pack *PackedContent) {
	subnetExisted := NewStringSet(len(pack.SubnetIPv6))
	if len(record.SubnetIPv6) > 0 {
		for _, subnet6 := range record.SubnetIPv6 {
			pack.InsertSubnetIPv6(subnet6)
			dump.InsertToSubnetIPv6Index(subnet6.Subnet6, pack.ID)
			subnetExisted[subnet6.Subnet6] = Nothing{}
		}
	}

	for _, subnet6 := range pack.SubnetIPv6 {
		if _, ok := subnetExisted[subnet6.Subnet6]; !ok {
			pack.RemoveSubnetIPv6(subnet6)
			dump.RemoveFromSubnetIPv4Index(subnet6.Subnet6, pack.ID)
		}
	}
}

func (pack *PackedContent) InsertSubnetIPv6(subnet6 SubnetIPv6) {
	for _, existedSubnet6 := range pack.SubnetIPv6 {
		if subnet6 == existedSubnet6 {
			return
		}
	}

	pack.SubnetIPv6 = append(pack.SubnetIPv6, subnet6)
}

func (pack *PackedContent) RemoveSubnetIPv6(subnet6 SubnetIPv6) {
	for i, existedSubnet6 := range pack.SubnetIPv6 {
		if subnet6 == existedSubnet6 {
			pack.SubnetIPv6 = append(pack.SubnetIPv6[:i], pack.SubnetIPv6[i+1:]...)

			return
		}
	}
}

func (dump *Dump) ExtractAndApplyDomain(record *Content, pack *PackedContent) {
	if len(record.Domain) > 0 {
		pack.Domain = record.Domain
		for _, domain := range pack.Domain {
			nDomain := NormalizeDomain(domain.Domain)

			dump.InsertToDomainIndex(nDomain, pack.ID)
		}
	}
}

func (dump *Dump) EctractAndApplyUpdateDomain(record *Content, pack *PackedContent) {
	domainExisted := NewStringSet(len(pack.Domain))
	if len(record.Domain) > 0 {
		for _, domain := range record.Domain {
			pack.InsertDomain(domain)

			nDomain := NormalizeDomain(domain.Domain)

			dump.InsertToDomainIndex(nDomain, pack.ID)

			domainExisted[domain.Domain] = Nothing{}
		}
	}

	for _, domain := range pack.Domain {
		if _, ok := domainExisted[domain.Domain]; !ok {
			pack.RemoveDomain(domain)

			nDomain := NormalizeDomain(domain.Domain)

			dump.RemoveFromDomainIndex(nDomain, pack.ID)
		}
	}
}

func (pack *PackedContent) InsertDomain(domain Domain) {
	for _, existedDomain := range pack.Domain {
		if domain == existedDomain {
			return
		}
	}

	pack.Domain = append(pack.Domain, domain)
}

func (pack *PackedContent) RemoveDomain(domain Domain) {
	for i, existedDomain := range pack.Domain {
		if domain == existedDomain {
			pack.Domain = append(pack.Domain[:i], pack.Domain[i+1:]...)

			return
		}
	}
}

func (dump *Dump) ExtractAndApplyURL(record *Content, pack *PackedContent) {
	if len(record.URL) > 0 {
		pack.URL = record.URL
		for _, u := range pack.URL {
			nURL := NormalizeURL(u.URL)
			if strings.HasPrefix(nURL, "https://") {
				record.HTTPSBlock++
			}

			dump.InsertToURLIndex(nURL, pack.ID)
		}
	}

	pack.BlockType = record.constructBlockType()
}

func (dump *Dump) EctractAndApplyUpdateURL(record *Content, pack *PackedContent) {
	urlExisted := NewStringSet(len(pack.URL))
	HTTPSBlock := 0

	if len(record.URL) > 0 {
		for _, u := range record.URL {
			pack.InsertURL(u)

			nURL := NormalizeURL(u.URL)
			if strings.HasPrefix(nURL, "https://") {
				HTTPSBlock++
			}

			dump.InsertToURLIndex(nURL, pack.ID)

			urlExisted[u.URL] = Nothing{}
		}
	}

	record.HTTPSBlock = HTTPSBlock
	pack.BlockType = record.constructBlockType()

	for _, u := range pack.URL {
		if _, ok := urlExisted[u.URL]; !ok {
			pack.RemoveURL(u)

			nURL := NormalizeURL(u.URL)

			dump.RemoveFromURLIndex(nURL, pack.ID)
		}
	}
}

func (pack *PackedContent) InsertURL(u URL) {
	for _, existedURL := range pack.URL {
		if u == existedURL {
			return
		}
	}

	pack.URL = append(pack.URL, u)
}

func (pack *PackedContent) RemoveURL(u URL) {
	for i, existedURL := range pack.URL {
		if u == existedURL {
			pack.URL = append(pack.URL[:i], pack.URL[i+1:]...)

			return
		}
	}
}

func (pack *PackedContent) refreshPackedContent(hash uint64, utime int64, payload []byte) {
	pack.RecordHash, pack.RegistryUpdateTime, pack.Payload = hash, utime, payload
}

func newPackedContent(id int32, hash uint64, utime int64, payload []byte) *PackedContent {
	return &PackedContent{
		ID:                 id,
		RecordHash:         hash,
		RegistryUpdateTime: utime,
		Payload:            payload,
	}
}

func (v *PackedContent) newPbContent(ip4 uint32, ip6 []byte, domain, url, aggr string) *pb.Content {
	v0 := pb.Content{}
	v0.BlockType = v.BlockType
	v0.RegistryUpdateTime = v.RegistryUpdateTime
	v0.Id = v.ID
	v0.Ip4 = ip4
	v0.Ip6 = ip6
	v0.Domain = domain
	v0.Url = url
	v0.Aggr = aggr
	v0.Pack = v.Payload
	return &v0
}

func getContentId(_e xml.StartElement) int32 {
	var (
		id  int
		err error
	)
	for _, _a := range _e.Attr {
		if _a.Name.Local == "id" {
			id, err = strconv.Atoi(_a.Value)
			if err != nil {
				logger.Debug.Printf("Can't fetch id: %s: %s\n", _a.Value, err.Error())
			}
		}
	}
	return int32(id)
}

func parseRegister(element xml.StartElement, r *Reg) {
	for _, attr := range element.Attr {
		switch attr.Name.Local {
		case "formatVersion":
			r.FormatVersion = attr.Value
		case "updateTime":
			r.UpdateTime = parseRFC3339Time(attr.Value)
		case "updateTimeUrgently":
			r.UpdateTimeUrgently = attr.Value
		}
	}
}
