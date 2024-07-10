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

				content.IPv4 = append(content.IPv4, IPv4{IPv4: IPv4StrToInt(ip4.IP), Ts: parseRFC3339Time(ip4.Ts)})
			case elementIP6:
				ip6 := XMLIP6{}
				if err := decoder.DecodeElement(&ip6, &element); err != nil {
					return fmt.Errorf("parse ipv6 elm: %w", err)
				}

				content.IPv6 = append(content.IPv6, IPv6{IPv6: net.ParseIP(ip6.IP6), Ts: parseRFC3339Time(ip6.Ts)})
			case elementIP4Subnet:
				subnet4 := XMLSubnet{}
				if err := decoder.DecodeElement(&subnet4, &element); err != nil {
					return fmt.Errorf("parse subnet elm: %w", err)
				}

				content.SubnetIPv4 = append(content.SubnetIPv4, SubnetIPv4{SubnetIPv4: subnet4.Subnet, Ts: parseRFC3339Time(subnet4.Ts)})
			case elementIP6Subnet:
				subnet6 := XMLSubnet6{}
				if err := decoder.DecodeElement(&subnet6, &element); err != nil {
					return fmt.Errorf("parse ipv6 subnet elm: %w", err)
				}

				content.SubnetIPv6 = append(content.SubnetIPv6, SubnetIPv6{SubnetIPv6: subnet6.Subnet6, Ts: parseRFC3339Time(subnet6.Ts)})
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
				if stats.LargestSizeOfContent < len(contBuf) {
					stats.LargestSizeOfContent = len(contBuf)
					stats.LargestSizeOfContentCintentID = id
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
	statistics := CurrentDump.Cleanup(ContJournal, &stats, reg.UpdateTime)

	stats.Update()
	Summary.Store(statistics)

	logger.Debug.Printf("Statistics: %#v\n", statistics)

	// Print stats.

	logger.Info.Printf("Records: %d Added: %d Updated: %d Removed: %d\n", stats.Count, stats.AddCount, stats.UpdateCount, stats.RemoveCount)
	logger.Info.Printf("  IP: %d IPv6: %d Subnets: %d Subnets6: %d Domains: %d URSs: %d\n",
		len(CurrentDump.IPv4Index), len(CurrentDump.IPv6Index), len(CurrentDump.subnetIPv4Index), len(CurrentDump.subnetIPv6Index),
		len(CurrentDump.domainIndex), len(CurrentDump.URLIndex))
	logger.Info.Printf("Biggest array: %d\n", stats.MaxItemReferences)
	logger.Info.Printf("Biggest content: %d (/n_%d)\n", stats.LargestSizeOfContent, stats.LargestSizeOfContentCintentID)

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

func (dump *Dump) Cleanup(existed Int32Map, stats *ParseStatistics, utime int64) *SummaryValues {
	dump.Lock()
	defer dump.Unlock()

	dump.purge(existed, stats)   // remove deleted records from index.
	dump.calcMaxEntityLen(stats) // calc max entity len.
	dump.utime = utime           // set global update time.

	statisctics := &SummaryValues{
		UpdateTime:        dump.utime,
		ContentEntries:    len(dump.ContentIndex),
		IPv4Entries:       len(dump.IPv4Index),
		IPv6Entries:       len(dump.IPv6Index),
		SubnetIPv4Entries: len(dump.subnetIPv4Index),
		SubnetIPv6Entries: len(dump.subnetIPv6Index),
		DomainEntries:     len(dump.domainIndex),
		URLEntries:        len(dump.URLIndex),
		EntryTypes:        make(map[string]int),
		DecisionOrgs:      make(map[string]int),
	}

	for _, c := range dump.ContentIndex {
		switch c.BlockType {
		case BlockTypeURL:
			statisctics.BlockTypeURL++
		case BlockTypeDomain:
			statisctics.BlockTypeDomain++
		case BlockTypeHTTPS:
			statisctics.BlockTypeHTTPS++
		case BlockTypeIP:
			statisctics.BlockTypeIP++
		case BlockTypeMask:
			statisctics.BlockTypeMask++
		}

		// statisctics.EntryTypes[entryTypeKey(c.EntryType, c.DecisionOrg)]++
		// statisctics.DecisionOrgs[c.DecisionOrg]++
	}

	for entryTypeKey, list := range dump.entryTypeIndex {
		statisctics.EntryTypes[entryTypeKey] = len(list)
	}

	for org := range dump.packedOrgIndex {
		delete(dump.packedOrgIndex, org)
	}

	for org, list := range dump.orgIndex {
		statisctics.DecisionOrgs[org] = len(list)
		dump.packedOrgIndex[String2fnv2uint64(org)] = org
	}

	statisctics.LargestSizeOfContent = stats.LargestSizeOfContent
	statisctics.LargestSizeOfContentCintentID = stats.LargestSizeOfContentCintentID
	statisctics.MaxItemReferences = stats.MaxItemReferences
	statisctics.MaxItemReferencesString = stats.MaxItemReferencesString
	statisctics.EntriesWithoutDecisionNo = len(dump.withoutDecisionNo)

	return statisctics
}

func entryTypeKey(entryType int32, org, number string) (res string) {
	basis := "15.1" //"[ст. 15.1](http://www.consultant.ru/document/cons_doc_LAW_61798/38c8ea666d27d9dc12b078c556e316e90248f551/), общая"
	switch {
	case entryType == 1 && org == "Роскомнадзор" && strings.HasSuffix(number, "-СОБ"):
		basis = "15.1.1m" //"[ст. 15.1 пункт 1 попдункт м](http://www.consultant.ru/document/cons_doc_LAW_61798/38c8ea666d27d9dc12b078c556e316e90248f551/), общая"
	case entryType == 1 && (org == "Генпрокуратура" || org == ""):
		basis = "15.1-1" // "[ст. 15.1-1](http://www.consultant.ru/document/cons_doc_LAW_61798/079aac275ffc6cea954b19c5b177a547b94f3c48/), неуважение"
	case entryType == 2:
		basis = "15.2" // "[ст. 15.2](http://www.consultant.ru/document/cons_doc_LAW_61798/1f316dc4a18023edcd030bc6591c4dd8b4f841dc/), правообладание"
	case entryType == 3:
		basis = "15.3" // "[ст. 15.3](http://www.consultant.ru/document/cons_doc_LAW_61798/34547c9b6ddb60cebd0a67593943fd9ef64ebdd0/), мятеж и фейки"
	case entryType == 4:
		basis = "15.4" // "[ст. 15.4](http://www.consultant.ru/document/cons_doc_LAW_61798/96723dcd9be73473a978013263f16f42cd8cd53d/), ОРИ не молчи"
	case entryType == 5 && org == "Мосгорсуд":
		basis = "15.6" // "[ст. 15.6](http://www.consultant.ru/document/cons_doc_LAW_61798/c7c4ad36689c46c7e8a3ab49c9db8ccbc7c82920/), вечная"
	case entryType == 5 && (org == "Минцифра" || org == "Минкомсвязь"):
		basis = "15.6-1" // "[ст. 15.6-1](http://www.consultant.ru/document/cons_doc_LAW_61798/c7c4ad36689c46c7e8a3ab49c9db8ccbc7c82920/), вечная зеркал"
	case entryType == 6:
		basis = "15.5" //"[ст. 15.5](http://www.consultant.ru/document/cons_doc_LAW_61798/98228cbe6565abbe55d0842a7e8593012c3449ea/), персональные данные"
	case entryType == 7:
		basis = "15.8" // "[ст. 15.8](http://www.consultant.ru/document/cons_doc_LAW_61798/1a807328c80a540bd0bb724927d6e774595431dc/), VPN"
	case entryType == 8:
		basis = "15.9" // "[ст. 15.9](http://www.consultant.ru/document/cons_doc_LAW_61798/31eb19e991d54b484ac546107c4db838b3631e9f/), сайт иноагента"
	}

	return strings.ReplaceAll(strings.ReplaceAll(basis, ".", "_"), "-", "_")
}

func (dump *Dump) calcMaxEntityLen(stats *ParseStatistics) {
	stats.MaxItemReferences = 0
	stats.MaxItemReferencesString = ""

	for key, a := range dump.IPv4Index {
		if stats.MaxItemReferences < len(a) {
			stats.MaxItemReferences = len(a)
			stats.MaxItemReferencesString = int2Ip4(key)
		}

		if stats.MaxIPv4IDReferences < len(a) {
			stats.MaxIPv4IDReferences = len(a)
		}
	}
	for key, a := range dump.IPv6Index {
		if stats.MaxItemReferences < len(a) {
			stats.MaxItemReferences = len(a)
			stats.MaxItemReferencesString = key
		}

		if stats.MaxIPv6IDReferences < len(a) {
			stats.MaxIPv6IDReferences = len(a)
		}
	}
	for key, a := range dump.subnetIPv4Index {
		if stats.MaxItemReferences < len(a) {
			stats.MaxItemReferences = len(a)
			stats.MaxItemReferencesString = key
		}

		if stats.MaxSubnetIPv4IDReferences < len(a) {
			stats.MaxSubnetIPv4IDReferences = len(a)
		}
	}
	for key, a := range dump.subnetIPv6Index {
		if stats.MaxItemReferences < len(a) {
			stats.MaxItemReferences = len(a)
			stats.MaxItemReferencesString = key
		}

		if stats.MaxSubnetIPv6IDReferences < len(a) {
			stats.MaxSubnetIPv6IDReferences = len(a)
		}
	}
	for key, a := range dump.URLIndex {
		if stats.MaxItemReferences < len(a) {
			stats.MaxItemReferences = len(a)
			stats.MaxItemReferencesString = key
		}

		if stats.MaxURLIDReferences < len(a) {
			stats.MaxURLIDReferences = len(a)
		}
	}
	for key, a := range dump.domainIndex {
		if stats.MaxItemReferences < len(a) {
			stats.MaxItemReferences = len(a)
			stats.MaxItemReferencesString = key
		}

		if stats.MaxDomainIDReferences < len(a) {
			stats.MaxDomainIDReferences = len(a)
		}
	}
}

// purge - remove deleted records from index.
func (dump *Dump) purge(existed Int32Map, stats *ParseStatistics) {
	for id, cont := range dump.ContentIndex {
		if _, ok := existed[id]; !ok {
			for _, ip4 := range cont.IPv4 {
				dump.RemoveFromIPv4Index(ip4.IPv4, cont.ID)
			}

			for _, ip6 := range cont.IPv6 {
				ip6 := string(ip6.IPv6)
				dump.RemoveFromIPv6Index(ip6, cont.ID)
			}

			for _, subnet6 := range cont.SubnetIPv6 {
				dump.RemoveFromSubnetIPv6Index(subnet6.SubnetIPv6, cont.ID)
			}

			for _, subnet4 := range cont.SubnetIPv4 {
				dump.RemoveFromSubnetIPv4Index(subnet4.SubnetIPv4, cont.ID)
			}

			for _, u := range cont.URL {
				dump.RemoveFromURLIndex(NormalizeURL(u.URL), cont.ID)
			}

			for _, domain := range cont.Domain {
				dump.RemoveFromDomainIndex(NormalizeDomain(domain.Domain), cont.ID)
			}

			dump.RemoveFromDecisionIndex(cont.Decision, cont.ID)
			dump.RemoveFromDecisionOrgIndex(cont.DecisionOrg, cont.ID)
			dump.RemoveFromDecisionWithoutNoIndex(cont.ID)
			dump.RemoveFromEntryTypeIndex(entryTypeKey(cont.EntryType, cont.DecisionOrg, cont.DecisionNumber), cont.ID)

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
	pack.EntryTypeString = entryTypeKey(record.EntryType, record.Decision.Org, record.Decision.Number)

	dump.InsertToEntryTypeIndex(pack.EntryTypeString, pack.ID)
}

// IT IS REASON FOR ALARM!!!!
func (dump *Dump) EctractAndApplyUpdateEntryType(record *Content, pack *PackedContent) {
	dump.RemoveFromEntryTypeIndex(pack.EntryTypeString, pack.ID)

	pack.EntryType = record.EntryType
	pack.EntryTypeString = entryTypeKey(record.EntryType, record.Decision.Org, record.Decision.Number)

	dump.InsertToEntryTypeIndex(pack.EntryTypeString, pack.ID)
}

func makeRightDecisionOrg(org string) string {
	switch {
	case org == "":
		return "Генпрокуратура"
	case !strings.Contains(org, "Мосгорсуд") && (strings.Contains(org, "суд") || strings.Contains(org, "Суд")):
		return "Суд"
	case strings.Contains(org, "ФССП"):
		return "ФССП"
	default:
		return org
	}
}

func (dump *Dump) ExtractAndApplyDecision(record *Content, pack *PackedContent) {
	pack.Decision = hashDecision(&record.Decision)
	pack.DecisionOrg = makeRightDecisionOrg(record.Decision.Org)
	pack.DecisionNumber = record.Decision.Number

	dump.InsertToDecisionIndex(pack.Decision, pack.ID)
	dump.InsertToDecisionOrgIndex(pack.DecisionOrg, pack.ID)
	dump.InsertToDecisionWithoutNoIndex(record.Decision.Number, pack.ID)
}

// IT IS REASON FOR ALARM!!!!
func (dump *Dump) EctractAndApplyUpdateDecision(record *Content, pack *PackedContent) {
	dump.RemoveFromDecisionIndex(pack.Decision, pack.ID)
	dump.RemoveFromDecisionOrgIndex(pack.DecisionOrg, pack.ID)
	dump.RemoveFromDecisionWithoutNoIndex(pack.ID)

	pack.Decision = hashDecision(&record.Decision)
	pack.DecisionOrg = makeRightDecisionOrg(record.Decision.Org)
	pack.DecisionNumber = record.Decision.Number

	dump.InsertToDecisionIndex(pack.Decision, pack.ID)
	dump.InsertToDecisionOrgIndex(pack.DecisionOrg, pack.ID)
	dump.InsertToDecisionWithoutNoIndex(record.Decision.Number, pack.ID)
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
			dump.InsertToIPv4Index(ip4.IPv4, pack.ID)
		}
	}
}

func (dump *Dump) EctractAndApplyUpdateIPv4(record *Content, pack *PackedContent) {
	ipExisted := make(map[uint32]Nothing, len(pack.IPv4))
	if len(record.IPv4) > 0 {
		for _, ip4 := range record.IPv4 {
			pack.InsertIPv4(ip4)
			dump.InsertToIPv4Index(ip4.IPv4, pack.ID)
			ipExisted[ip4.IPv4] = Nothing{}
		}
	}

	for _, ip4 := range pack.IPv4 {
		if _, ok := ipExisted[ip4.IPv4]; !ok {
			pack.RemoveIPv4(ip4)
			dump.RemoveFromIPv4Index(ip4.IPv4, pack.ID)
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
			dump.InsertToIPv6Index(string(ip4.IPv6), pack.ID)
		}
	}
}

func (dump *Dump) EctractAndApplyUpdateIPv6(record *Content, pack *PackedContent) {
	ipExisted := make(map[string]Nothing, len(pack.IPv6))
	if len(record.IPv6) > 0 {
		for _, ip6 := range record.IPv6 {
			pack.InsertIPv6(ip6)

			addr := string(ip6.IPv6)
			dump.InsertToIPv6Index(addr, pack.ID)
			ipExisted[addr] = Nothing{}
		}
	}

	for _, ip6 := range pack.IPv6 {
		if _, ok := ipExisted[string(ip6.IPv6)]; !ok {
			pack.RemoveIPv6(ip6)
			dump.RemoveFromIPv6Index(string(ip6.IPv6), pack.ID)
		}
	}
}

func (pack *PackedContent) InsertIPv6(ip6 IPv6) {
	for _, existedIP6 := range pack.IPv6 {
		if string(ip6.IPv6) == string(existedIP6.IPv6) && ip6.Ts == existedIP6.Ts {
			return
		}
	}

	pack.IPv6 = append(pack.IPv6, ip6)
}

func (pack *PackedContent) RemoveIPv6(ip6 IPv6) {
	for i, existedIP6 := range pack.IPv6 {
		if string(ip6.IPv6) == string(existedIP6.IPv6) && ip6.Ts == existedIP6.Ts {
			pack.IPv6 = append(pack.IPv6[:i], pack.IPv6[i+1:]...)

			return
		}
	}
}

func (dump *Dump) ExtractAndApplySubnetIPv4(record *Content, pack *PackedContent) {
	if len(record.SubnetIPv4) > 0 {
		pack.SubnetIPv4 = record.SubnetIPv4
		for _, subnet4 := range pack.SubnetIPv4 {
			dump.InsertToSubnetIPv4Index(subnet4.SubnetIPv4, pack.ID)
		}
	}
}

func (dump *Dump) EctractAndApplyUpdateSubnetIPv4(record *Content, pack *PackedContent) {
	existedSubnetIPv4 := NewStringSet(len(pack.SubnetIPv4))
	if len(record.SubnetIPv4) > 0 {
		for _, subnetIPv4 := range record.SubnetIPv4 {
			pack.InsertSubnetIPv4(subnetIPv4)
			dump.InsertToSubnetIPv4Index(subnetIPv4.SubnetIPv4, pack.ID)
			existedSubnetIPv4[subnetIPv4.SubnetIPv4] = Nothing{}
		}
	}

	for _, subnetIPv4 := range pack.SubnetIPv4 {
		if _, ok := existedSubnetIPv4[subnetIPv4.SubnetIPv4]; !ok {
			pack.RemoveSubnetIPv4(subnetIPv4)
			dump.RemoveFromSubnetIPv4Index(subnetIPv4.SubnetIPv4, pack.ID)
		}
	}
}

func (pack *PackedContent) InsertSubnetIPv4(subnetIPv4 SubnetIPv4) {
	for _, existedSubnetIPv4 := range pack.SubnetIPv4 {
		if subnetIPv4 == existedSubnetIPv4 {
			return
		}
	}

	pack.SubnetIPv4 = append(pack.SubnetIPv4, subnetIPv4)
}

func (pack *PackedContent) RemoveSubnetIPv4(subnetIPv4 SubnetIPv4) {
	for i, existedSubnetIPv4 := range pack.SubnetIPv4 {
		if subnetIPv4 == existedSubnetIPv4 {
			pack.SubnetIPv4 = append(pack.SubnetIPv4[:i], pack.SubnetIPv4[i+1:]...)

			return
		}
	}
}

func (dump *Dump) ExtractAndApplySubnetIPv6(record *Content, pack *PackedContent) {
	if len(record.SubnetIPv6) > 0 {
		pack.SubnetIPv6 = record.SubnetIPv6
		for _, subnet6 := range pack.SubnetIPv6 {
			dump.InsertToSubnetIPv4Index(subnet6.SubnetIPv6, pack.ID)
		}
	}
}

func (dump *Dump) EctractAndApplyUpdateSubnetIPv6(record *Content, pack *PackedContent) {
	existedSubnetIPv6 := NewStringSet(len(pack.SubnetIPv6))
	if len(record.SubnetIPv6) > 0 {
		for _, subnetIPv6 := range record.SubnetIPv6 {
			pack.InsertSubnetIPv6(subnetIPv6)
			dump.InsertToSubnetIPv6Index(subnetIPv6.SubnetIPv6, pack.ID)
			existedSubnetIPv6[subnetIPv6.SubnetIPv6] = Nothing{}
		}
	}

	for _, subnetIPv6 := range pack.SubnetIPv6 {
		if _, ok := existedSubnetIPv6[subnetIPv6.SubnetIPv6]; !ok {
			pack.RemoveSubnetIPv6(subnetIPv6)
			dump.RemoveFromSubnetIPv4Index(subnetIPv6.SubnetIPv6, pack.ID)
		}
	}
}

func (pack *PackedContent) InsertSubnetIPv6(subnetIPv6 SubnetIPv6) {
	for _, existedSubnetIPv6 := range pack.SubnetIPv6 {
		if subnetIPv6 == existedSubnetIPv6 {
			return
		}
	}

	pack.SubnetIPv6 = append(pack.SubnetIPv6, subnetIPv6)
}

func (pack *PackedContent) RemoveSubnetIPv6(subnetIPv6 SubnetIPv6) {
	for i, existedSubnetIPv6 := range pack.SubnetIPv6 {
		if subnetIPv6 == existedSubnetIPv6 {
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
