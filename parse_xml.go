package main

import (
	"bytes"
	"encoding/xml"
	"hash/crc32"
	"io"
	"net"
	"os"

	"golang.org/x/net/html/charset"
)

func Parse(dumpfile string) error {
	var (
		err      error
		dumpFile *os.File
		stats    Stats
		r        TReg
		buffer   bytes.Buffer
		buf      StringSet
		bufi     map[uint32]Nothing
	)

	// parse xml
	if dumpFile, err = os.Open(dumpfile); err != nil {
		return err
	}
	defer dumpFile.Close()

	bufferOffset := int64(0)
	offsetCorrection := int64(0)
	decoder := xml.NewDecoder(dumpFile)
	decoder.CharsetReader = func(label string, input io.Reader) (io.Reader, error) {
		r, err := charset.NewReaderLabel(label, input)
		if err != nil {
			return nil, err
		}
		offsetCorrection = decoder.InputOffset()
		return io.TeeReader(r, &buffer), nil
	}

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
					if _a.Name.Local == "formatVersion" {
						r.FormatVersion = _a.Value
					} else if _a.Name.Local == "updateTime" {
						r.UpdateTime = parseTime(_a.Value)
					} else if _a.Name.Local == "updateTimeUrgently" {
						r.UpdateTimeUrgently = _a.Value
					}
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
					v0 := &TXContent{
						Id:          v.Id,
						EntryType:   v.EntryType,
						UrgencyType: v.UrgencyType,
						BlockType:   v.BlockType,
						Hash:        v.Hash,
						Decision: TXDecision{
							Date:   v.Decision.Date,
							Number: v.Decision.Number,
							Org:    v.Decision.Org,
						},
						IncludeTime: parseTime2(v.IncludeTime),
						Ts:          parseTime(v.Ts),
					}
					v0.U2Hash = u2Hash
					v0.RegistryUpdateTime = r.UpdateTime
					DumpSnap.Content.C[v.Id] = v0

					if len(v.Ip) > 0 {
						v0.Ip = make([]TXIp, len(v.Ip))
						for i := range v.Ip {
							ip := parseIp4(v.Ip[i].Ip)
							DumpSnap.AddIp(ip, v.Id)
							v0.Ip[i] = TXIp{Ip: ip, Ts: parseTime(v.Ts)}
						}
					}

					if len(v.Ip6) > 0 {
						v0.Ip6 = make([]TXIp6, len(v.Ip6))
						for i, value := range v.Ip6 {
							ip6 := string(net.ParseIP(value.Ip6))
							DumpSnap.AddIp6(ip6, v.Id)
							v0.Ip6[i] = TXIp6{Ip6: ip6, Ts: parseTime(v.Ts)}
						}
					}

					if len(v.Subnet6) > 0 {
						v0.Subnet6 = make([]TXSubnet6, len(v.Subnet6))
						for i, value := range v.Subnet6 {
							DumpSnap.AddSubnet6(value.Subnet6, v.Id)
							v0.Subnet6[i] = TXSubnet6{Subnet6: v.Subnet6[i].Subnet6, Ts: parseTime(v.Ts)}
						}
					}

					if len(v.Subnet) > 0 {
						v0.Subnet = make([]TXSubnet, len(v.Subnet))
						for i, value := range v.Subnet {
							DumpSnap.AddSubnet(value.Subnet, v.Id)
							v0.Subnet[i] = TXSubnet{Subnet: v.Subnet[i].Subnet, Ts: parseTime(v.Ts)}
						}
					}

					if len(v.Url) > 0 {
						v0.Url = make([]TXUrl, len(v.Url))
						for i, value := range v.Url {
							v0.Url[i] = TXUrl{Url: value.Url, Ts: parseTime(v.Ts)}
							_url := NormalizeUrl(value.Url)
							DumpSnap.AddUrl(_url, v.Id)
							if _url[:8] == "https" {
								v0.HTTPSBlock += 1
							}
						}
					}

					if len(v.Domain) > 0 {
						v0.Domain = make([]TXDomain, len(v.Domain))
						for i, value := range v.Domain {
							DumpSnap.AddDomain(NormalizeDomain(value.Domain), v.Id)
							v0.Domain[i] = TXDomain{Domain: value.Domain, Ts: parseTime(v.Ts)}
						}
					}

					SPass[v.Id] = NothingV
					stats.CntAdd++
				} else if o.U2Hash != u2Hash {
					v0 := &TXContent{
						Id:          v.Id,
						EntryType:   v.EntryType,
						UrgencyType: v.UrgencyType,
						BlockType:   v.BlockType,
						Hash:        v.Hash,
						Decision: TXDecision{
							Date:   v.Decision.Date,
							Number: v.Decision.Number,
							Org:    v.Decision.Org,
						},
						IncludeTime: parseTime2(v.IncludeTime),
						Ts:          parseTime(v.Ts),
					}
					v0.U2Hash = u2Hash
					v0.RegistryUpdateTime = r.UpdateTime
					DumpSnap.Content.C[v.Id] = v0

					// make updates
					bufi = make(map[uint32]Nothing, len(v.Ip))
					if len(v.Ip) > 0 {
						v0.Ip = make([]TXIp, len(v.Ip))
						for i, value := range v.Ip {
							ip := parseIp4(value.Ip)
							DumpSnap.AddIp(ip, v.Id)
							bufi[ip] = NothingV
							v0.Ip[i] = TXIp{Ip: ip}
						}
					}
					for _, value := range o.Ip {
						ip := value.Ip
						if _, ok := bufi[ip]; !ok {
							DumpSnap.DeleteIp(ip, o.Id)
						}
					}
					bufi = nil

					buf = NewStringSet(len(v.Ip6))
					if len(v.Ip6) > 0 {
						v0.Ip6 = make([]TXIp6, len(v.Ip6))
						for i, value := range v.Ip6 {
							ip6 := string(net.ParseIP(value.Ip6))
							DumpSnap.AddIp6(ip6, v.Id)
							buf[ip6] = NothingV
							v0.Ip6[i] = TXIp6{Ip6: ip6, Ts: parseTime(v.Ts)}
						}
					}
					for _, value := range o.Ip6 {
						ip6 := string(net.ParseIP(value.Ip6))
						if _, ok := buf[ip6]; !ok {
							DumpSnap.DeleteIp6(ip6, o.Id)
						}
					}

					buf = NewStringSet(len(v.Subnet))
					if len(v.Subnet) > 0 {
						v0.Subnet = make([]TXSubnet, len(v.Subnet))
						for i, value := range v.Subnet {
							DumpSnap.AddSubnet(value.Subnet, v.Id)
							buf[value.Subnet] = NothingV
							v0.Subnet[i] = TXSubnet{Subnet: value.Subnet, Ts: parseTime(v.Ts)}
						}
					}
					for _, value := range o.Subnet {
						if _, ok := buf[value.Subnet]; !ok {
							DumpSnap.DeleteSubnet(value.Subnet, o.Id)
						}
					}

					buf = NewStringSet(len(v.Subnet6))
					if len(v.Subnet6) > 0 {
						v0.Subnet6 = make([]TXSubnet6, len(v.Subnet6))
						for i, value := range v.Subnet6 {
							DumpSnap.AddSubnet(value.Subnet6, v.Id)
							buf[value.Subnet6] = NothingV
							v0.Subnet6[i] = TXSubnet6{Subnet6: value.Subnet6, Ts: parseTime(v.Ts)}
						}
					}
					for _, value := range o.Subnet6 {
						if _, ok := buf[value.Subnet6]; !ok {
							DumpSnap.DeleteSubnet6(value.Subnet6, o.Id)
						}
					}

					buf = NewStringSet(len(v.Url))
					if len(v.Url) > 0 {
						v0.Url = make([]TXUrl, len(v.Url))
						for i, value := range v.Url {
							_url := NormalizeUrl(value.Url)
							DumpSnap.AddUrl(_url, v.Id)
							buf[_url] = NothingV
							v0.Url[i] = TXUrl{Url: value.Url, Ts: parseTime(v.Ts)}
							if _url[:8] == "https://" {
								v0.HTTPSBlock += 1
							}
						}
					}
					for _, value := range o.Url {
						_url := NormalizeUrl(value.Url)
						if _, ok := buf[_url]; !ok {
							DumpSnap.DeleteUrl(_url, o.Id)
						}
					}

					buf = NewStringSet(len(v.Domain))
					if len(v.Domain) > 0 {
						v0.Domain = make([]TXDomain, len(v.Domain))
						for i, value := range v.Domain {
							_domain := NormalizeDomain(value.Domain)
							DumpSnap.AddDomain(_domain, v.Id)
							buf[_domain] = NothingV
							v0.Domain[i] = TXDomain{Domain: value.Domain, Ts: parseTime(v.Ts)}
						}
					}
					for _, value := range o.Domain {
						_domain := NormalizeDomain(value.Domain)
						if _, ok := buf[_domain]; !ok {
							DumpSnap.DeleteDomain(_domain, o.Id)
						}
					}
					buf = nil
					SPass[v.Id] = NothingV
					stats.CntUpdate++
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
			for _, v := range o2.Ip {
				DumpSnap.DeleteIp(v.Ip, o2.Id)
			}
			for _, v := range o2.Ip6 {
				DumpSnap.DeleteIp6(v.Ip6, o2.Id)
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
	DumpSnap.Content.Unlock()
	Info.Printf("Records: %d Added: %d Updated: %d Removed: %d\n", stats.Cnt, stats.CntAdd, stats.CntUpdate, stats.CntRemove)
	Info.Printf("  IP: %d IPv6: %d Subnets: %d Subnets6: %d Domains: %d URSs: %d\n",
		len(DumpSnap.ip), len(DumpSnap.ip6), len(DumpSnap.subnet), len(DumpSnap.subnet6),
		len(DumpSnap.domain), len(DumpSnap.url))
	return err
}
