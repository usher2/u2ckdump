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

				hasher64.Reset()
				hasher64.Write(contBuf)

				newContHash := hasher64.Sum64()
				bufferOffset = tokenStartOffset

				// TODO: move to special func
				newCont := Content{}

				ContJournal[id] = NothingV // add to journal.

				// create or update
				CurrentDump.Lock()

				prevCont, exists := CurrentDump.Content[id]

				switch {
				case !exists:
					err := UnmarshalContent(contBuf, &newCont)
					if err != nil {
						logger.Error.Printf("Decode Error: %s\n", err)

						break
					}

					newCont.Add(newContHash, reg.UpdateTime)
					stats.CntAdd++
				case prevCont.U2Hash != newContHash:
					err := UnmarshalContent(contBuf, &newCont)
					if err != nil {
						logger.Error.Printf("Decode Error: %s\n", err)

						break
					}

					newCont.Update(newContHash, prevCont, reg.UpdateTime)
					stats.CntUpdate++
				default:
					CurrentDump.Content[id].RegistryUpdateTime = reg.UpdateTime
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

	for id, cont := range CurrentDump.Content {
		if _, ok := ContJournal[id]; !ok {
			for _, ip4 := range cont.IP4 {
				CurrentDump.DeleteIp(ip4.IP4, cont.ID)
			}

			for _, ip6 := range cont.IP6 {
				ip6 := string(ip6.IP6)
				CurrentDump.DeleteIp6(ip6, cont.ID)
			}

			for _, subnet6 := range cont.Subnet6 {
				CurrentDump.DeleteSubnet6(subnet6.Subnet6, cont.ID)
			}

			for _, subnet4 := range cont.Subnet4 {
				CurrentDump.DeleteSubnet(subnet4.Subnet4, cont.ID)
			}

			for _, u := range cont.URL {
				CurrentDump.DeleteUrl(NormalizeURL(u.URL), cont.ID)
			}

			for _, domain := range cont.Domain {
				CurrentDump.DeleteDomain(NormalizeDomain(domain.Domain), cont.ID)
			}

			CurrentDump.DeleteDecision(cont.Decision, cont.ID)
			delete(CurrentDump.Content, id)
			stats.CntRemove++
		}
	}

	CurrentDump.utime = reg.UpdateTime
	stats.MaxArrayIntSet = 0

	for _, a := range CurrentDump.ip4 {
		if stats.MaxArrayIntSet < len(a) {
			stats.MaxArrayIntSet = len(a)
		}
	}
	for _, a := range CurrentDump.ip6 {
		if stats.MaxArrayIntSet < len(a) {
			stats.MaxArrayIntSet = len(a)
		}
	}
	for _, a := range CurrentDump.subnet4 {
		if stats.MaxArrayIntSet < len(a) {
			stats.MaxArrayIntSet = len(a)
		}
	}
	for _, a := range CurrentDump.subnet6 {
		if stats.MaxArrayIntSet < len(a) {
			stats.MaxArrayIntSet = len(a)
		}
	}
	for _, a := range CurrentDump.url {
		if stats.MaxArrayIntSet < len(a) {
			stats.MaxArrayIntSet = len(a)
		}
	}
	for _, a := range CurrentDump.domain {
		if stats.MaxArrayIntSet < len(a) {
			stats.MaxArrayIntSet = len(a)
		}
	}

	CurrentDump.Unlock()

	logger.Info.Printf("Records: %d Added: %d Updated: %d Removed: %d\n", stats.Cnt, stats.CntAdd, stats.CntUpdate, stats.CntRemove)
	logger.Info.Printf("  IP: %d IPv6: %d Subnets: %d Subnets6: %d Domains: %d URSs: %d\n",
		len(CurrentDump.ip4), len(CurrentDump.ip6), len(CurrentDump.subnet4), len(CurrentDump.subnet6),
		len(CurrentDump.domain), len(CurrentDump.url))
	logger.Info.Printf("Biggest array: %d\n", stats.MaxArrayIntSet)
	logger.Info.Printf("Biggest content: %d\n", stats.MaxContentSize)

	return nil
}

func (v *Content) Marshal() []byte {
	b, err := json.Marshal(v)
	if err != nil {
		logger.Error.Printf("Error encoding: %s\n", err.Error())
	}
	return b
}

func (v *Content) constructBlockType() int32 {
	switch v.BlockType {
	case "ip":
		return BlockTypeIP
	case "domain":
		return BlockTypeDomain
	case "domain-mask":
		return BlockTypeMask
	default:
		if v.BlockType != "default" && v.BlockType != "" {
			logger.Error.Printf("Unknown block type: %s\n", v.BlockType)
		}
		if v.HTTPSBlock == 0 {
			return BlockTypeURL
		} else {
			return BlockTypeHTTPS
		}
	}
}

func (v *Content) Update(u2Hash uint64, o *MinContent, updateTime int64) {
	pack := v.Marshal()
	v1 := newMinContent(v.ID, u2Hash, updateTime, pack)
	CurrentDump.Content[v.ID] = v1
	v1.handleUpdateIp(v, o)
	v1.handleUpdateIp6(v, o)
	v1.handleUpdateSubnet(v, o)
	v1.handleUpdateSubnet6(v, o)
	v1.handleUpdateUrl(v, o)
	v1.handleUpdateDomain(v, o)
	v1.handleUpdateDecision(v, o) // reason for ALARM!!!
	v1.BlockType = v.constructBlockType()
}

func (v *Content) Add(u2Hash uint64, updateTime int64) {
	pack := v.Marshal()
	v1 := newMinContent(v.ID, u2Hash, updateTime, pack)
	CurrentDump.Content[v.ID] = v1
	v1.handleAddIp(v)
	v1.handleAddIp6(v)
	v1.handleAddSubnet6(v)
	v1.handleAddSubnet(v)
	v1.handleAddUrl(v)
	v1.handleAddDomain(v)
	v1.handleAddDecision(v)
	v1.BlockType = v.constructBlockType()
}

func (v *MinContent) handleAddDecision(v0 *Content) {
	c := []byte(" ")
	// hash.Write([]byte(v0.Decision.Org + " " + v0.Decision.Number + " " + v0.Decision.Date))
	hasher64.Reset()
	hasher64.Write([]byte(v0.Decision.Org))
	hasher64.Write(c)
	hasher64.Write([]byte(v0.Decision.Number))
	hasher64.Write(c)
	hasher64.Write([]byte(v0.Decision.Date))
	v.Decision = hasher64.Sum64()
	CurrentDump.AddDecision(v.Decision, v.ID)
}

// IT IS REASON FOR ALARM!!!!
func (v *MinContent) handleUpdateDecision(v0 *Content, o *MinContent) {
	c := []byte(" ")
	// hash.Write([]byte(v0.Decision.Org + " " + v0.Decision.Number + " " + v0.Decision.Date))
	hasher64.Reset()
	hasher64.Write([]byte(v0.Decision.Org))
	hasher64.Write(c)
	hasher64.Write([]byte(v0.Decision.Number))
	hasher64.Write(c)
	hasher64.Write([]byte(v0.Decision.Date))
	v.Decision = hasher64.Sum64()
	CurrentDump.DeleteDecision(o.Decision, o.ID)
	CurrentDump.AddDecision(v.Decision, v.ID)
}

func (v *MinContent) handleAddIp(v0 *Content) {
	if len(v0.IP4) > 0 {
		v.IP4 = v0.IP4
		for i := range v.IP4 {
			CurrentDump.AddIp(v.IP4[i].IP4, v.ID)
		}
	}
}

func (v *MinContent) handleUpdateIp(v0 *Content, o *MinContent) {
	ipSet := make(map[uint32]Nothing, len(v.IP4))
	if len(v0.IP4) > 0 {
		v.IP4 = v0.IP4
		for i := range v.IP4 {
			CurrentDump.AddIp(v.IP4[i].IP4, v.ID)
			ipSet[v.IP4[i].IP4] = NothingV
		}
	}
	for i := range o.IP4 {
		ip := o.IP4[i].IP4
		if _, ok := ipSet[ip]; !ok {
			CurrentDump.DeleteIp(ip, o.ID)
		}
	}
}

func (v *MinContent) handleAddDomain(v0 *Content) {
	if len(v0.Domain) > 0 {
		v.Domain = v0.Domain
		for _, value := range v.Domain {
			domain := NormalizeDomain(value.Domain)
			CurrentDump.AddDomain(domain, v.ID)
		}
	}
}

func (v *MinContent) handleUpdateDomain(v0 *Content, o *MinContent) {
	domainSet := NewStringSet(len(v.Domain))
	if len(v0.Domain) > 0 {
		v.Domain = v0.Domain
		for _, value := range v.Domain {
			domain := NormalizeDomain(value.Domain)
			CurrentDump.AddDomain(domain, v.ID)
			domainSet[domain] = NothingV
		}
	}
	for _, value := range o.Domain {
		domain := NormalizeDomain(value.Domain)
		if _, ok := domainSet[domain]; !ok {
			CurrentDump.DeleteDomain(domain, o.ID)
		}
	}
}

func (v *MinContent) handleAddUrl(v0 *Content) {
	if len(v0.URL) > 0 {
		v.URL = v0.URL
		for _, value := range v.URL {
			url := NormalizeURL(value.URL)
			CurrentDump.AddUrl(url, v.ID)
			if url[:8] == "https://" {
				v0.HTTPSBlock += 1
			}
		}
	}
}

func (v *MinContent) handleUpdateUrl(v0 *Content, o *MinContent) {
	urlSet := NewStringSet(len(v.URL))
	if len(v0.URL) > 0 {
		v.URL = v0.URL
		for _, value := range v.URL {
			url := NormalizeURL(value.URL)
			CurrentDump.AddUrl(url, v.ID)
			if url[:8] == "https://" {
				v0.HTTPSBlock += 1
			}
			urlSet[url] = NothingV
		}
	}
	for _, value := range o.URL {
		url := NormalizeURL(value.URL)
		if _, ok := urlSet[url]; !ok {
			CurrentDump.DeleteUrl(url, o.ID)
		}
	}
}

func (v *MinContent) handleAddSubnet(v0 *Content) {
	if len(v0.Subnet4) > 0 {
		v.Subnet4 = v0.Subnet4
		for _, value := range v.Subnet4 {
			CurrentDump.AddSubnet(value.Subnet4, v.ID)
		}
	}
}

func (v *MinContent) handleUpdateSubnet(v0 *Content, o *MinContent) {
	subnetSet := NewStringSet(len(v.Subnet4))
	if len(v0.Subnet4) > 0 {
		v.Subnet4 = v0.Subnet4
		for _, value := range v.Subnet4 {
			CurrentDump.AddSubnet(value.Subnet4, v.ID)
			subnetSet[value.Subnet4] = NothingV
		}
	}
	for _, value := range o.Subnet4 {
		if _, ok := subnetSet[value.Subnet4]; !ok {
			CurrentDump.DeleteSubnet(value.Subnet4, o.ID)
		}
	}
}

func (v *MinContent) handleAddSubnet6(v0 *Content) {
	if len(v0.Subnet6) > 0 {
		v.Subnet6 = v0.Subnet6
		for _, value := range v.Subnet6 {
			CurrentDump.AddSubnet6(value.Subnet6, v.ID)
		}
	}
}

func (v *MinContent) handleUpdateSubnet6(v0 *Content, o *MinContent) {
	subnet6Set := NewStringSet(len(v.Subnet6))
	if len(v0.Subnet6) > 0 {
		v.Subnet6 = v0.Subnet6
		for _, value := range v.Subnet6 {
			CurrentDump.AddSubnet(value.Subnet6, v.ID)
			subnet6Set[value.Subnet6] = NothingV
		}
	}
	for _, value := range o.Subnet6 {
		if _, ok := subnet6Set[value.Subnet6]; !ok {
			CurrentDump.DeleteSubnet6(value.Subnet6, o.ID)
		}
	}
}

func (v *MinContent) handleAddIp6(v0 *Content) {
	if len(v0.IP6) > 0 {
		v.IP6 = v0.IP6
		for _, value := range v.IP6 {
			ip6 := string(value.IP6)
			CurrentDump.AddIp6(ip6, v.ID)
		}
	}
}

func (v *MinContent) handleUpdateIp6(v0 *Content, o *MinContent) {
	ip6Set := NewStringSet(len(v.IP6))
	if len(v0.IP6) > 0 {
		v.IP6 = v0.IP6
		for _, value := range v.IP6 {
			ip6 := string(value.IP6)
			CurrentDump.AddIp6(ip6, v.ID)
			ip6Set[ip6] = NothingV
		}
	}
	for _, value := range o.IP6 {
		ip6 := string(value.IP6)
		if _, ok := ip6Set[ip6]; !ok {
			CurrentDump.DeleteIp6(ip6, o.ID)
		}
	}
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

func newMinContent(id int32, hash uint64, utime int64, pack []byte) *MinContent {
	v := MinContent{ID: id, U2Hash: hash, RegistryUpdateTime: utime, Pack: pack}
	return &v
}

func (v *MinContent) newPbContent(ip4 uint32, ip6 []byte, domain, url, aggr string) *pb.Content {
	v0 := pb.Content{}
	v0.BlockType = v.BlockType
	v0.RegistryUpdateTime = v.RegistryUpdateTime
	v0.Id = v.ID
	v0.Ip4 = ip4
	v0.Ip6 = ip6
	v0.Domain = domain
	v0.Url = url
	v0.Aggr = aggr
	v0.Pack = v.Pack
	return &v0
}
