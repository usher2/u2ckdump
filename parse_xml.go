package main

import (
	"bytes"
	"encoding/xml"
	"hash/crc32"
	"io"
	"net"

	"golang.org/x/net/html/charset"

	pb "github.com/usher-2/u2ckdump/msg"
)

func Parse(dumpFile io.Reader) error {
	var (
		err          error
		stats        Stats
		r            TReg
		buffer       bytes.Buffer
		bufferOffset int64
	)

	decoder := xml.NewDecoder(dumpFile)
	offsetCorrection := newCharsetDecoder(decoder, 0, &buffer)

	SPass := make(IntSet, len(DumpSnap.Content.C)+1000)
	for {
		tokenStartOffset := decoder.InputOffset() - offsetCorrection
		t, err := decoder.Token()
		if t == nil {
			if err != io.EOF {
				return err
			}
			break
		}
		switch _e := t.(type) {
		case xml.StartElement:
			switch _e.Name.Local {
			case "register":
				for _, _a := range _e.Attr {
					handleRegister(_a, &r)
				}
			case "content":
				v := &TContent{}
				// parse <content>...</content>
				if err := decoder.DecodeElement(v, &_e); err != nil {
					Error.Printf("Decode Error: %s\n", err.Error())
					continue
				}
				dif := tokenStartOffset - bufferOffset
				buffer.Next(int(dif))
				bufferOffset += dif
				tokenStartOffset = decoder.InputOffset() - offsetCorrection
				// create hash of <content>...</content> for comp
				u2Hash := crc32.Checksum(buffer.Next(int(tokenStartOffset-bufferOffset)), crc32Table)
				bufferOffset = tokenStartOffset
				// create or update
				DumpSnap.Content.Lock()
				o, exists := DumpSnap.Content.C[v.Id]
				if !exists {
					v.handleAdd(u2Hash, r.UpdateTime)
					stats.CntAdd++

					SPass[v.Id] = NothingV
				} else if o.U2Hash != u2Hash {
					v.handleUpdate(u2Hash, o, r.UpdateTime)
					stats.CntUpdate++

					SPass[v.Id] = NothingV

				} else {
					o.RegistryUpdateTime = r.UpdateTime

					SPass[o.Id] = NothingV
					//v = nil
				}
				DumpSnap.Content.Unlock()
				stats.Cnt++
			}
		default:
			//fmt.printf("%v\n", _e)
		}
		dif := tokenStartOffset - bufferOffset
		buffer.Next(int(dif))
		bufferOffset += dif
	}
	// remove operations
	DumpSnap.Content.Lock()
	for id, o2 := range DumpSnap.Content.C {
		if _, ok := SPass[id]; !ok {
			for _, v := range o2.Ip4 {
				DumpSnap.DeleteIp(v.Ip4, o2.Id)
			}
			for _, v := range o2.Ip6 {
				DumpSnap.DeleteIp6(string(v.Ip6), o2.Id)
			}
			for _, v := range o2.Subnet6 {
				DumpSnap.DeleteSubnet6(v.Subnet6, o2.Id)
			}
			for _, v := range o2.Subnet {
				DumpSnap.DeleteSubnet(v.Subnet, o2.Id)
			}
			for _, v := range o2.Url {
				DumpSnap.DeleteUrl(NormalizeUrl(v.Url), o2.Id)
			}
			for _, v := range o2.Domain {
				DumpSnap.DeleteDomain(NormalizeDomain(v.Domain), o2.Id)
			}
			delete(DumpSnap.Content.C, id)
			stats.CntRemove++
		}
	}
	DumpSnap.utime = r.UpdateTime
	CntArrayIntSet := 0
	for _, a := range DumpSnap.ip {
		if CntArrayIntSet < len(a) {
			CntArrayIntSet = len(a)
		}
	}
	for _, a := range DumpSnap.ip6 {
		if CntArrayIntSet < len(a) {
			CntArrayIntSet = len(a)
		}
	}
	for _, a := range DumpSnap.subnet {
		if CntArrayIntSet < len(a) {
			CntArrayIntSet = len(a)
		}
	}
	for _, a := range DumpSnap.subnet6 {
		if CntArrayIntSet < len(a) {
			CntArrayIntSet = len(a)
		}
	}
	for _, a := range DumpSnap.url {
		if CntArrayIntSet < len(a) {
			CntArrayIntSet = len(a)
		}
	}
	for _, a := range DumpSnap.domain {
		if CntArrayIntSet < len(a) {
			CntArrayIntSet = len(a)
		}
	}
	DumpSnap.Content.Unlock()
	Info.Printf("Records: %d Added: %d Updated: %d Removed: %d\n", stats.Cnt, stats.CntAdd, stats.CntUpdate, stats.CntRemove)
	Info.Printf("  IP: %d IPv6: %d Subnets: %d Subnets6: %d Domains: %d URSs: %d\n",
		len(DumpSnap.ip), len(DumpSnap.ip6), len(DumpSnap.subnet), len(DumpSnap.subnet6),
		len(DumpSnap.domain), len(DumpSnap.url))
	Info.Printf("Biggest array: %d\n", CntArrayIntSet)
	return err
}

func (v *TContent) handleUpdate(u2Hash uint32, o *pb.Content, updateTime int64) {
	v0 := newPbContent(v, u2Hash, updateTime)
	DumpSnap.Content.C[v.Id] = v0
	v.handleUpdateIp(v0, o)
	v.handleUpdateIp6(v0, o)
	v.handleUpdateSubnet(v0, o)
	v.handleUpdateSubnet6(v0, o)
	v.handleUpdateUrl(v0, o)
	v.handleUpdateDomain(v0, o)
}

func (v *TContent) handleAdd(u2Hash uint32, updateTime int64) {
	v0 := newPbContent(v, u2Hash, updateTime)
	DumpSnap.Content.C[v.Id] = v0
	v.handleAddIp(v0)
	v.handleAddIp6(v0)
	v.handleAddSubnet6(v0)
	v.handleAddSubnet(v0)
	v.handleAddUrl(v0)
	v.handleAddDomain(v0)
}

func (v *TContent) handleAddIp(v0 *pb.Content) {
	if len(v.Ip) > 0 {
		v0.Ip4 = make([]*pb.IPv4Address, len(v.Ip))
		for i, _ := range v.Ip {
			ip := parseIp4(v.Ip[i].Ip)
			DumpSnap.AddIp(ip, v.Id)
			v0.Ip4[i] = &pb.IPv4Address{Ip4: ip, Ts: parseTime(v.Ip[i].Ts)}
		}
	}
}

func (v *TContent) handleUpdateIp(v0 *pb.Content, o *pb.Content) {
	ipSet := make(map[uint32]Nothing, len(v.Ip))
	if len(v.Ip) > 0 {
		v0.Ip4 = make([]*pb.IPv4Address, len(v.Ip))
		for i, _ := range v.Ip {
			ip := parseIp4(v.Ip[i].Ip)
			DumpSnap.AddIp(ip, v.Id)
			v0.Ip4[i] = &pb.IPv4Address{Ip4: ip, Ts: parseTime(v.Ip[i].Ts)}
			ipSet[ip] = NothingV
		}
	}
	for i, _ := range o.Ip4 {
		ip := o.Ip4[i].Ip4
		if _, ok := ipSet[ip]; !ok {
			DumpSnap.DeleteIp(ip, o.Id)
		}
	}
}

func (v *TContent) handleAddDomain(v0 *pb.Content) {
	if len(v.Domain) > 0 {
		v0.Domain = make([]*pb.Domain, len(v.Domain))
		for i, value := range v.Domain {
			domain := NormalizeDomain(value.Domain)
			DumpSnap.AddDomain(domain, v.Id)
			v0.Domain[i] = &pb.Domain{Domain: value.Domain, Ts: parseTime(value.Ts)}
		}
	}
}

func (v *TContent) handleUpdateDomain(v0 *pb.Content, o *pb.Content) {
	domainSet := NewStringSet(len(v.Domain))
	if len(v.Domain) > 0 {
		v0.Domain = make([]*pb.Domain, len(v.Domain))
		for i, value := range v.Domain {
			domain := NormalizeDomain(value.Domain)
			DumpSnap.AddDomain(domain, v.Id)
			v0.Domain[i] = &pb.Domain{Domain: value.Domain, Ts: parseTime(value.Ts)}
			domainSet[domain] = NothingV
		}
	}
	for _, value := range o.Domain {
		domain := NormalizeDomain(value.Domain)
		if _, ok := domainSet[domain]; !ok {
			DumpSnap.DeleteDomain(domain, o.Id)
		}
	}
}

func (v *TContent) handleAddUrl(v0 *pb.Content) {
	if len(v.Url) > 0 {
		v0.Url = make([]*pb.URL, len(v.Url))
		for i, value := range v.Url {
			v0.Url[i] = &pb.URL{Url: value.Url, Ts: parseTime(value.Ts)}
			url := NormalizeUrl(value.Url)
			DumpSnap.AddUrl(url, v.Id)
			if url[:8] == "https://" {
				v0.HttpsBlock += 1
			}
		}
	}
}

func (v *TContent) handleUpdateUrl(v0 *pb.Content, o *pb.Content) {
	urlSet := NewStringSet(len(v.Url))
	if len(v.Url) > 0 {
		v0.Url = make([]*pb.URL, len(v.Url))
		for i, value := range v.Url {
			url := NormalizeUrl(value.Url)
			DumpSnap.AddUrl(url, v.Id)
			v0.Url[i] = &pb.URL{Url: value.Url, Ts: parseTime(value.Ts)}
			if url[:8] == "https://" {
				v0.HttpsBlock += 1
			}
			urlSet[url] = NothingV
		}
	}
	for _, value := range o.Url {
		url := NormalizeUrl(value.Url)
		if _, ok := urlSet[url]; !ok {
			DumpSnap.DeleteUrl(url, o.Id)
		}
	}
}

func (v *TContent) handleAddSubnet(v0 *pb.Content) {
	if len(v.Subnet) > 0 {
		v0.Subnet = make([]*pb.Subnet, len(v.Subnet))
		for i, value := range v.Subnet {
			DumpSnap.AddSubnet(value.Subnet, v.Id)
			v0.Subnet[i] = &pb.Subnet{Subnet: v.Subnet[i].Subnet, Ts: parseTime(value.Ts)}
		}
	}
}

func (v *TContent) handleUpdateSubnet(v0 *pb.Content, o *pb.Content) {
	subnetSet := NewStringSet(len(v.Subnet))
	if len(v.Subnet) > 0 {
		v0.Subnet = make([]*pb.Subnet, len(v.Subnet))
		for i, value := range v.Subnet {
			DumpSnap.AddSubnet(value.Subnet, v.Id)
			v0.Subnet[i] = &pb.Subnet{Subnet: value.Subnet, Ts: parseTime(value.Ts)}
			subnetSet[value.Subnet] = NothingV
		}
	}
	for _, value := range o.Subnet {
		if _, ok := subnetSet[value.Subnet]; !ok {
			DumpSnap.DeleteSubnet(value.Subnet, o.Id)
		}
	}
}

func (v *TContent) handleAddSubnet6(v0 *pb.Content) {
	if len(v.Subnet6) > 0 {
		v0.Subnet6 = make([]*pb.Subnet6, len(v.Subnet6))
		for i, value := range v.Subnet6 {
			DumpSnap.AddSubnet6(value.Subnet6, v.Id)
			v0.Subnet6[i] = &pb.Subnet6{Subnet6: v.Subnet6[i].Subnet6, Ts: parseTime(value.Ts)}
		}
	}
}

func (v *TContent) handleUpdateSubnet6(v0 *pb.Content, o *pb.Content) {
	subnet6Set := NewStringSet(len(v.Subnet6))
	if len(v.Subnet6) > 0 {
		v0.Subnet6 = make([]*pb.Subnet6, len(v.Subnet6))
		for i, value := range v.Subnet6 {
			DumpSnap.AddSubnet(value.Subnet6, v.Id)
			v0.Subnet6[i] = &pb.Subnet6{Subnet6: value.Subnet6, Ts: parseTime(value.Ts)}
			subnet6Set[value.Subnet6] = NothingV
		}
	}
	for _, value := range o.Subnet6 {
		if _, ok := subnet6Set[value.Subnet6]; !ok {
			DumpSnap.DeleteSubnet6(value.Subnet6, o.Id)
		}
	}
}

func (v *TContent) handleAddIp6(v0 *pb.Content) {
	if len(v.Ip6) > 0 {
		v0.Ip6 = make([]*pb.IPv6Address, len(v.Ip6))
		for i, value := range v.Ip6 {
			ip6 := net.ParseIP(value.Ip6)
			DumpSnap.AddIp6(string(ip6), v.Id)
			v0.Ip6[i] = &pb.IPv6Address{Ip6: ip6, Ts: parseTime(value.Ts)}
		}
	}
}

func (v *TContent) handleUpdateIp6(v0 *pb.Content, o *pb.Content) {
	ip6Set := NewStringSet(len(v.Ip6))
	if len(v.Ip6) > 0 {
		v0.Ip6 = make([]*pb.IPv6Address, len(v.Ip6))
		for i, value := range v.Ip6 {
			ip6 := net.ParseIP(value.Ip6)
			sip6 := string(ip6)
			DumpSnap.AddIp6(sip6, v.Id)
			v0.Ip6[i] = &pb.IPv6Address{Ip6: ip6, Ts: parseTime(value.Ts)}
			ip6Set[sip6] = NothingV
		}
	}
	for _, value := range o.Ip6 {
		sip6 := string(value.Ip6)
		if _, ok := ip6Set[sip6]; !ok {
			DumpSnap.DeleteIp6(sip6, o.Id)
		}
	}
}

func handleRegister(_a xml.Attr, r *TReg) {
	if _a.Name.Local == "formatVersion" {
		r.FormatVersion = _a.Value
	} else if _a.Name.Local == "updateTime" {
		r.UpdateTime = parseTime(_a.Value)
	} else if _a.Name.Local == "updateTimeUrgently" {
		r.UpdateTimeUrgently = _a.Value
	}
}

func newCharsetDecoder(decoder *xml.Decoder, offsetCorrection int64, buffer *bytes.Buffer) int64 {
	decoder.CharsetReader = func(label string, input io.Reader) (io.Reader, error) {
		r, err := charset.NewReaderLabel(label, input)
		if err != nil {
			return nil, err
		}
		offsetCorrection = decoder.InputOffset()
		return io.TeeReader(r, buffer), nil
	}
	return offsetCorrection
}

func newPbContent(v *TContent, u2Hash uint32, utime int64) *pb.Content {
	decision := &pb.Decision{
		Date:   v.Decision.Date,
		Number: v.Decision.Number,
		Org:    v.Decision.Org,
	}

	v0 := &pb.Content{
		Id:          v.Id,
		EntryType:   v.EntryType,
		UrgencyType: v.UrgencyType,
		BlockType:   v.BlockType,
		Hash:        v.Hash,
		Decision:    decision,
		IncludeTime: parseTime2(v.IncludeTime),
		Ts:          parseTime(v.Ts),
	}
	v0.U2Hash = u2Hash
	v0.RegistryUpdateTime = utime
	return v0
}
