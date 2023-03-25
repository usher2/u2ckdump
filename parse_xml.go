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
func UnmarshalContent(b []byte, cont *Content) error {
	buf := bytes.NewReader(b)
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
				if err := parseContentElement(element, cont); err != nil {
					return fmt.Errorf("parse content elm: %w", err)
				}
			case elementDecision:
				if err := decoder.DecodeElement(&cont.Decision, &element); err != nil {
					return fmt.Errorf("parse decision elm: %w", err)
				}
			case elementURL:
				u := XMLURL{}
				if err := decoder.DecodeElement(&u, &element); err != nil {
					return fmt.Errorf("parse url elm: %w", err)
				}

				cont.URL = append(cont.URL, URL{URL: u.URL, Ts: parseRFC3339Time(u.Ts)})
			case elementDomain:
				d := XMLDomain{}
				if err := decoder.DecodeElement(&d, &element); err != nil {
					return fmt.Errorf("parse domain elm: %w", err)
				}

				cont.Domain = append(cont.Domain, Domain{Domain: d.Domain, Ts: parseRFC3339Time(d.Ts)})
			case elementIP4:
				ip := XMLIP{}
				if err := decoder.DecodeElement(&ip, &element); err != nil {
					return fmt.Errorf("parse ip elm: %w", err)
				}

				cont.IP4 = append(cont.IP4, IP4{IP4: IPv4StrToInt(ip.IP), Ts: parseRFC3339Time(ip.Ts)})
			case elementIP6:
				ip := XMLIP6{}
				if err := decoder.DecodeElement(&ip, &element); err != nil {
					return fmt.Errorf("parse ipv6 elm: %w", err)
				}

				cont.IP6 = append(cont.IP6, IP6{IP6: net.ParseIP(ip.IP6), Ts: parseRFC3339Time(ip.Ts)})
			case elementIP4Subnet:
				s := XMLSubnet{}
				if err := decoder.DecodeElement(&s, &element); err != nil {
					return fmt.Errorf("parse subnet elm: %w", err)
				}

				cont.Subnet4 = append(cont.Subnet4, Subnet4{Subnet4: s.Subnet, Ts: parseRFC3339Time(s.Ts)})
			case elementIP6Subnet:
				s := XMLSubnet6{}
				if err := decoder.DecodeElement(&s, &element); err != nil {
					return fmt.Errorf("parse ipv6 subnet elm: %w", err)
				}

				cont.Subnet6 = append(cont.Subnet6, Subnet6{Subnet6: s.Subnet6, Ts: parseRFC3339Time(s.Ts)})
			}
		}
	}

	return nil
}

// pasre <content> element itself.
func parseContentElement(element xml.StartElement, v *Content) error {
	for _, attr := range element.Attr {
		switch attr.Name.Local {
		case "id":
			x, err := strconv.Atoi(attr.Value)
			if err != nil {
				return fmt.Errorf("id atoi: %w: %s", err, attr.Value)
			}

			v.ID = int32(x)
		case "entryType":
			x, err := strconv.Atoi(attr.Value)
			if err != nil {
				return fmt.Errorf("entryType atoi: %w: %s", err, attr.Value)
			}

			v.EntryType = int32(x)
		case "urgencyType":
			x, err := strconv.Atoi(attr.Value)
			if err != nil {
				return fmt.Errorf("urgencyType atoi: %w: %s", err, attr.Value)
			}

			v.UrgencyType = int32(x)
		case "includeTime":
			v.IncludeTime = parseMoscowTime(attr.Value)
		case "blockType":
			v.BlockType = attr.Value
		case "hash":
			v.Hash = attr.Value
		case "ts":
			v.Ts = parseRFC3339Time(attr.Value)
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

		stats Stat
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
	ContJournal := make(Int32Map, len(CurrentDump.Content))

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
				handleRegister(element, &reg)
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

				// TODO: move to special func
				newCont := &Content{
					RecordHash: hasher64.Sum64(),
				}

				ContJournal[id] = Nothing{} // add to journal.

				// create or update
				CurrentDump.Lock()

				prevCont, exists := CurrentDump.Content[id]

				switch {
				case !exists:
					err := UnmarshalContent(contBuf, newCont)
					if err != nil {
						logger.Error.Printf("Decode Error: %s\n", err)

						break
					}

					CurrentDump.NewPackedContent(newCont, reg.UpdateTime)
					stats.CntAdd++
				case prevCont.RecordHash != newCont.RecordHash:
					err := UnmarshalContent(contBuf, newCont)
					if err != nil {
						logger.Error.Printf("Decode Error: %s\n", err)

						break
					}

					CurrentDump.MergePackedContent(newCont, prevCont, reg.UpdateTime)
					stats.CntUpdate++
				default:
					CurrentDump.SetContentUpdateTime(id, reg.UpdateTime)
				}

				CurrentDump.Unlock()
				stats.Cnt++
			}
		}

		// read buffer anyway
		diff := tokenStartOffset - bufferOffset
		buffer.Next(int(diff))
		bufferOffset += diff
	}

	// TODO: move to dedicated function or few

	// remove operations
	CurrentDump.Lock()

	CurrentDump.Purge(ContJournal, &stats)

	CurrentDump.utime = reg.UpdateTime

	CurrentDump.CalcMaxEntityLen(&stats)

	CurrentDump.Unlock()

	logger.Info.Printf("Records: %d Added: %d Updated: %d Removed: %d\n", stats.Cnt, stats.CntAdd, stats.CntUpdate, stats.CntRemove)
	logger.Info.Printf("  IP: %d IPv6: %d Subnets: %d Subnets6: %d Domains: %d URSs: %d\n",
		len(CurrentDump.ip4), len(CurrentDump.ip6), len(CurrentDump.subnet4), len(CurrentDump.subnet6),
		len(CurrentDump.domain), len(CurrentDump.url))
	logger.Info.Printf("Biggest array: %d\n", stats.MaxArrayIntSet)
	logger.Info.Printf("Biggest content: %d\n", stats.MaxContentSize)

	return nil
}

func (dump *Dump) CalcMaxEntityLen(stats *Stat) {
	stats.MaxArrayIntSet = 0

	for _, a := range dump.ip4 {
		if stats.MaxArrayIntSet < len(a) {
			stats.MaxArrayIntSet = len(a)
		}
	}
	for _, a := range dump.ip6 {
		if stats.MaxArrayIntSet < len(a) {
			stats.MaxArrayIntSet = len(a)
		}
	}
	for _, a := range dump.subnet4 {
		if stats.MaxArrayIntSet < len(a) {
			stats.MaxArrayIntSet = len(a)
		}
	}
	for _, a := range dump.subnet6 {
		if stats.MaxArrayIntSet < len(a) {
			stats.MaxArrayIntSet = len(a)
		}
	}
	for _, a := range dump.url {
		if stats.MaxArrayIntSet < len(a) {
			stats.MaxArrayIntSet = len(a)
		}
	}
	for _, a := range dump.domain {
		if stats.MaxArrayIntSet < len(a) {
			stats.MaxArrayIntSet = len(a)
		}
	}
}

func (dump *Dump) Purge(existed Int32Map, stats *Stat) {
	for id, cont := range dump.Content {
		if _, ok := existed[id]; !ok {
			for _, ip4 := range cont.IP4 {
				dump.DeleteIp(ip4.IP4, cont.ID)
			}

			for _, ip6 := range cont.IP6 {
				ip6 := string(ip6.IP6)
				dump.DeleteIp6(ip6, cont.ID)
			}

			for _, subnet6 := range cont.Subnet6 {
				dump.DeleteSubnet6(subnet6.Subnet6, cont.ID)
			}

			for _, subnet4 := range cont.Subnet4 {
				dump.DeleteSubnet(subnet4.Subnet4, cont.ID)
			}

			for _, u := range cont.URL {
				dump.DeleteUrl(NormalizeURL(u.URL), cont.ID)
			}

			for _, domain := range cont.Domain {
				dump.DeleteDomain(NormalizeDomain(domain.Domain), cont.ID)
			}

			dump.DeleteDecision(cont.Decision, cont.ID)

			delete(dump.Content, id)

			stats.CntRemove++
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
	dump.Content[id].RegistryUpdateTime = dump.utime
}

// MergePackedContent - merges new content with previous one.
// It is used to update existing content.
func (dump *Dump) MergePackedContent(record *Content, prev *PackedContent, updateTime int64) {
	prev.refreshPackedContent(record.RecordHash, updateTime, record.Marshal())

	dump.EctractAndApplyUpdateIP4(record, prev)
	dump.EctractAndApplyUpdateIP6(record, prev)
	dump.EctractAndApplyUpdateSubnet4(record, prev)
	dump.EctractAndApplyUpdateSubnet6(record, prev)
	dump.EctractAndApplyUpdateDomain(record, prev)
	dump.EctractAndApplyUpdateURL(record, prev)
	dump.EctractAndApplyUpdateDecision(record, prev) // reason for ALARM!!!
}

// NewPackedContent - creates new content.
// It is used to add new content.
func (dump *Dump) NewPackedContent(record *Content, updateTime int64) {
	fresh := newPackedContent(record.ID, record.RecordHash, updateTime, record.Marshal())
	dump.Content[record.ID] = fresh

	dump.ExtractAndApplyIP4(record, fresh)
	dump.ExtractAndApplyIP6(record, fresh)
	dump.ExtractAndApplySubnet4(record, fresh)
	dump.ExtractAndApplySubnet6(record, fresh)
	dump.ExtractAndApplyDomain(record, fresh)
	dump.ExtractAndApplyURL(record, fresh)
	dump.ExtractAndApplyDecision(record, fresh)
}

func (dump *Dump) ExtractAndApplyDecision(record *Content, pack *PackedContent) {
	pack.Decision = hashDecision(&record.Decision)
	dump.AddDecision(pack.Decision, pack.ID)
}

// IT IS REASON FOR ALARM!!!!
func (dump *Dump) EctractAndApplyUpdateDecision(record *Content, pack *PackedContent) {
	dump.DeleteDecision(pack.Decision, pack.ID)

	pack.Decision = hashDecision(&record.Decision)

	dump.AddDecision(pack.Decision, pack.ID)
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

func (dump *Dump) ExtractAndApplyIP4(record *Content, pack *PackedContent) {
	if len(record.IP4) > 0 {
		pack.IP4 = record.IP4
		for _, ip4 := range pack.IP4 {
			dump.AddIp(ip4.IP4, pack.ID)
		}
	}
}

func (dump *Dump) EctractAndApplyUpdateIP4(record *Content, pack *PackedContent) {
	ipExisted := make(map[uint32]Nothing, len(pack.IP4))
	if len(record.IP4) > 0 {
		for _, ip4 := range record.IP4 {
			pack.AppendIP4(ip4)
			dump.AddIp(ip4.IP4, pack.ID)
			ipExisted[ip4.IP4] = Nothing{}
		}
	}

	for _, ip4 := range pack.IP4 {
		if _, ok := ipExisted[ip4.IP4]; !ok {
			pack.RemoveIP4(ip4)
			dump.DeleteIp(ip4.IP4, pack.ID)
		}
	}
}

func (pack *PackedContent) AppendIP4(ip4 IP4) {
	for _, existedIP4 := range pack.IP4 {
		if ip4 == existedIP4 {
			return
		}
	}

	pack.IP4 = append(pack.IP4, ip4)
}

func (pack *PackedContent) RemoveIP4(ip4 IP4) {
	for i, existedIP4 := range pack.IP4 {
		if ip4 == existedIP4 {
			pack.IP4 = append(pack.IP4[:i], pack.IP4[i+1:]...)

			return
		}
	}
}

func (dump *Dump) ExtractAndApplyIP6(record *Content, pack *PackedContent) {
	if len(record.IP6) > 0 {
		pack.IP6 = record.IP6
		for _, ip4 := range pack.IP6 {
			dump.AddIp6(string(ip4.IP6), pack.ID)
		}
	}
}

func (dump *Dump) EctractAndApplyUpdateIP6(record *Content, pack *PackedContent) {
	ipExisted := make(map[string]Nothing, len(pack.IP6))
	if len(record.IP6) > 0 {
		for _, ip6 := range record.IP6 {
			pack.AppendIP6(ip6)

			addr := string(ip6.IP6)
			dump.AddIp6(addr, pack.ID)
			ipExisted[addr] = Nothing{}
		}
	}

	for _, ip6 := range pack.IP6 {
		if _, ok := ipExisted[string(ip6.IP6)]; !ok {
			pack.RemoveIP6(ip6)
			dump.DeleteIp6(string(ip6.IP6), pack.ID)
		}
	}
}

func (pack *PackedContent) AppendIP6(ip6 IP6) {
	for _, existedIP6 := range pack.IP6 {
		if string(ip6.IP6) == string(existedIP6.IP6) && ip6.Ts == existedIP6.Ts {
			return
		}
	}

	pack.IP6 = append(pack.IP6, ip6)
}

func (pack *PackedContent) RemoveIP6(ip6 IP6) {
	for i, existedIP6 := range pack.IP6 {
		if string(ip6.IP6) == string(existedIP6.IP6) && ip6.Ts == existedIP6.Ts {
			pack.IP6 = append(pack.IP6[:i], pack.IP6[i+1:]...)

			return
		}
	}
}

func (dump *Dump) ExtractAndApplySubnet4(record *Content, pack *PackedContent) {
	if len(record.Subnet4) > 0 {
		pack.Subnet4 = record.Subnet4
		for _, subnet4 := range pack.Subnet4 {
			dump.AddSubnet(subnet4.Subnet4, pack.ID)
		}
	}
}

func (dump *Dump) EctractAndApplyUpdateSubnet4(record *Content, pack *PackedContent) {
	subnetExisted := NewStringSet(len(pack.Subnet4))
	if len(record.Subnet4) > 0 {
		for _, subnet4 := range record.Subnet4 {
			pack.AppendSubnet4(subnet4)
			dump.AddSubnet(subnet4.Subnet4, pack.ID)
			subnetExisted[subnet4.Subnet4] = Nothing{}
		}
	}

	for _, subnet4 := range pack.Subnet4 {
		if _, ok := subnetExisted[subnet4.Subnet4]; !ok {
			pack.RemoveSubnet4(subnet4)
			dump.DeleteSubnet(subnet4.Subnet4, pack.ID)
		}
	}
}

func (pack *PackedContent) AppendSubnet4(subnet4 Subnet4) {
	for _, existedSubnet4 := range pack.Subnet4 {
		if subnet4 == existedSubnet4 {
			return
		}
	}

	pack.Subnet4 = append(pack.Subnet4, subnet4)
}

func (pack *PackedContent) RemoveSubnet4(subnet4 Subnet4) {
	for i, existedSubnet4 := range pack.Subnet4 {
		if subnet4 == existedSubnet4 {
			pack.Subnet4 = append(pack.Subnet4[:i], pack.Subnet4[i+1:]...)

			return
		}
	}
}

func (dump *Dump) ExtractAndApplySubnet6(record *Content, pack *PackedContent) {
	if len(record.Subnet6) > 0 {
		pack.Subnet6 = record.Subnet6
		for _, subnet6 := range pack.Subnet6 {
			dump.AddSubnet(subnet6.Subnet6, pack.ID)
		}
	}
}

func (dump *Dump) EctractAndApplyUpdateSubnet6(record *Content, pack *PackedContent) {
	subnetExisted := NewStringSet(len(pack.Subnet6))
	if len(record.Subnet6) > 0 {
		for _, subnet6 := range record.Subnet6 {
			pack.AppendSubnet6(subnet6)
			dump.AddSubnet6(subnet6.Subnet6, pack.ID)
			subnetExisted[subnet6.Subnet6] = Nothing{}
		}
	}

	for _, subnet6 := range pack.Subnet6 {
		if _, ok := subnetExisted[subnet6.Subnet6]; !ok {
			pack.RemoveSubnet6(subnet6)
			dump.DeleteSubnet(subnet6.Subnet6, pack.ID)
		}
	}
}

func (pack *PackedContent) AppendSubnet6(subnet6 Subnet6) {
	for _, existedSubnet6 := range pack.Subnet6 {
		if subnet6 == existedSubnet6 {
			return
		}
	}

	pack.Subnet6 = append(pack.Subnet6, subnet6)
}

func (pack *PackedContent) RemoveSubnet6(subnet6 Subnet6) {
	for i, existedSubnet6 := range pack.Subnet6 {
		if subnet6 == existedSubnet6 {
			pack.Subnet6 = append(pack.Subnet6[:i], pack.Subnet6[i+1:]...)

			return
		}
	}
}

func (dump *Dump) ExtractAndApplyDomain(record *Content, pack *PackedContent) {
	if len(record.Domain) > 0 {
		pack.Domain = record.Domain
		for _, domain := range pack.Domain {
			nDomain := NormalizeDomain(domain.Domain)

			dump.AddDomain(nDomain, pack.ID)
		}
	}
}

func (dump *Dump) EctractAndApplyUpdateDomain(record *Content, pack *PackedContent) {
	domainExisted := NewStringSet(len(pack.Domain))
	if len(record.Domain) > 0 {
		for _, domain := range record.Domain {
			pack.AppendDomain(domain)

			nDomain := NormalizeDomain(domain.Domain)

			dump.AddDomain(nDomain, pack.ID)

			domainExisted[domain.Domain] = Nothing{}
		}
	}

	for _, domain := range pack.Domain {
		if _, ok := domainExisted[domain.Domain]; !ok {
			pack.RemoveDomain(domain)

			nDomain := NormalizeDomain(domain.Domain)

			dump.DeleteDomain(nDomain, pack.ID)
		}
	}
}

func (pack *PackedContent) AppendDomain(domain Domain) {
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

			dump.AddUrl(nURL, pack.ID)
		}
	}

	pack.BlockType = record.constructBlockType()
}

func (dump *Dump) EctractAndApplyUpdateURL(record *Content, pack *PackedContent) {
	urlExisted := NewStringSet(len(pack.URL))
	HTTPSBlock := 0

	if len(record.URL) > 0 {
		for _, u := range record.URL {
			pack.AppendURL(u)

			nURL := NormalizeURL(u.URL)
			if strings.HasPrefix(nURL, "https://") {
				HTTPSBlock++
			}

			dump.AddUrl(nURL, pack.ID)

			urlExisted[u.URL] = Nothing{}
		}
	}

	record.HTTPSBlock = HTTPSBlock
	pack.BlockType = record.constructBlockType()

	for _, u := range pack.URL {
		if _, ok := urlExisted[u.URL]; !ok {
			pack.RemoveURL(u)

			nURL := NormalizeURL(u.URL)

			dump.DeleteUrl(nURL, pack.ID)
		}
	}
}

func (pack *PackedContent) AppendURL(u URL) {
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

func handleRegister(element xml.StartElement, r *Reg) {
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
