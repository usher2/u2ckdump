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
	var stats Stats
	var r TReg
	var buf map[string]Nothing
	var bufi map[uint32]Nothing
	SPass := make(IntSet, len(DumpSnap.Content.C)+1000)
	// parse xml
	fdump, err := os.Open(dumpfile)
	if err != nil {
		return err
	}
	defer fdump.Close()
	var buffer bytes.Buffer
	bufferOffset := int64(0)
	offsetCorrection := int64(0)
	decoder := xml.NewDecoder(fdump)
	decoder.CharsetReader = func(label string, input io.Reader) (io.Reader, error) {
		r, err := charset.NewReaderLabel(label, input)
		if err != nil {
			return nil, err
		}
		offsetCorrection = decoder.InputOffset()
		return io.TeeReader(r, &buffer), nil
	}

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
				err = decoder.DecodeElement(v, &_e)
				if err != nil {
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
						v0.Ip = make([]TXIp, 0, len(v.Ip))
						for i := range v.Ip {
							ip := ip2i(v.Ip[i].Ip)
							DumpSnap.Ip.AddIP4(ip, v.Id)
							v0.Ip = append(v0.Ip, TXIp{Ip: ip, Ts: parseTime(v.Ts)})
						}
					}
					if len(v.Ip6) > 0 {
						v0.Ip6 = make([]TXIp6, 0, len(v.Ip6))
						for i := range v.Ip6 {
							ip6 := string(net.ParseIP(v.Ip6[i].Ip6))
							DumpSnap.Ip6.AddRes(ip6, v.Id)
							v0.Ip6 = append(v0.Ip6, TXIp6{Ip6: ip6, Ts: parseTime(v.Ts)})
						}
					}
					if len(v.Subnet6) > 0 {
						v0.Subnet6 = make([]TXSubnet6, 0, len(v.Subnet6))
						for i := range v.Subnet6 {
							DumpSnap.Subnet6.AddRes(v.Subnet6[i].Subnet6, v.Id)
							v0.Subnet6 = append(v0.Subnet6, TXSubnet6{Subnet6: v.Subnet6[i].Subnet6, Ts: parseTime(v.Ts)})
						}
					}
					if len(v.Subnet) > 0 {
						v0.Subnet = make([]TXSubnet, 0, len(v.Subnet))
						for i := range v.Subnet {
							DumpSnap.Subnet.AddRes(v.Subnet[i].Subnet, v.Id)
							v0.Subnet = append(v0.Subnet, TXSubnet{Subnet: v.Subnet[i].Subnet, Ts: parseTime(v.Ts)})
						}
					}
					if len(v.Url) > 0 {
						v0.Url = make([]TXUrl, 0, len(v.Url))
						for i := range v.Url {
							v0.Url = append(v0.Url, TXUrl{Url: v.Url[i].Url, Ts: parseTime(v.Ts)})
							_url := NormalizeUrl(v.Url[i].Url)
							DumpSnap.Url.AddRes(_url, v.Id)
							if _url[:8] == "https" {
								v0.HTTPSBlock += 1
							}
						}
					}
					if len(v.Domain) > 0 {
						v0.Domain = make([]TXDomain, 0, len(v.Domain))
						for i := range v.Domain {
							DumpSnap.Domain.AddRes(NormalizeDomain(v.Domain[i].Domain), v.Id)
							v0.Domain = append(v0.Domain, TXDomain{Domain: v.Domain[i].Domain, Ts: parseTime(v.Ts)})
						}
					}
					SPass[v.Id] = Nothing{}
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
						v0.Ip = make([]TXIp, 0, len(v.Ip))
						for i := range v.Ip {
							ip := ip2i(v.Ip[i].Ip)
							DumpSnap.Ip.AddIP4(ip, v.Id)
							bufi[ip] = Nothing{}
							v0.Ip = append(v0.Ip, TXIp{Ip: ip})
						}
					}
					for i := range o.Ip {
						ip := o.Ip[i].Ip
						if _, ok := bufi[ip]; !ok {
							DumpSnap.Ip.DelIP(ip, o.Id)
						}
					}
					bufi = nil
					buf = make(map[string]Nothing, len(v.Ip6))
					if len(v.Ip6) > 0 {
						v0.Ip6 = make([]TXIp6, 0, len(v.Ip6))
						for i := range v.Ip6 {
							ip6 := string(net.ParseIP(v.Ip6[i].Ip6))
							DumpSnap.Ip6.AddRes(ip6, v.Id)
							buf[ip6] = Nothing{}
							v0.Ip6 = append(v0.Ip6, TXIp6{Ip6: ip6, Ts: parseTime(v.Ts)})
						}
					}
					for i := range o.Ip6 {
						ip6 := string(net.ParseIP(o.Ip6[i].Ip6))
						if _, ok := buf[ip6]; !ok {
							DumpSnap.Ip6.DelRes(ip6, o.Id)
						}
					}
					buf = make(map[string]Nothing, len(v.Subnet))
					if len(v.Subnet) > 0 {
						v0.Subnet = make([]TXSubnet, 0, len(v.Subnet))
						for i := range v.Subnet {
							DumpSnap.Subnet.AddRes(v.Subnet[i].Subnet, v.Id)
							buf[v.Subnet[i].Subnet] = Nothing{}
							v0.Subnet = append(v0.Subnet, TXSubnet{Subnet: v.Subnet[i].Subnet, Ts: parseTime(v.Ts)})
						}
					}
					for i := range o.Subnet {
						if _, ok := buf[o.Subnet[i].Subnet]; !ok {
							DumpSnap.Subnet.DelRes(o.Subnet[i].Subnet, o.Id)
						}
					}
					buf = make(map[string]Nothing, len(v.Subnet6))
					if len(v.Subnet6) > 0 {
						v0.Subnet6 = make([]TXSubnet6, 0, len(v.Subnet6))
						for i := range v.Subnet6 {
							DumpSnap.Subnet6.AddRes(v.Subnet6[i].Subnet6, v.Id)
							buf[v.Subnet6[i].Subnet6] = Nothing{}
							v0.Subnet6 = append(v0.Subnet6, TXSubnet6{Subnet6: v.Subnet6[i].Subnet6, Ts: parseTime(v.Ts)})
						}
					}
					for i := range o.Subnet6 {
						if _, ok := buf[o.Subnet6[i].Subnet6]; !ok {
							DumpSnap.Subnet6.DelRes(o.Subnet6[i].Subnet6, o.Id)
						}
					}
					buf = make(map[string]Nothing, len(v.Url))
					if len(v.Url) > 0 {
						v0.Url = make([]TXUrl, 0, len(v.Url))
						for i := range v.Url {
							_url := NormalizeUrl(v.Url[i].Url)
							DumpSnap.Url.AddRes(_url, v.Id)
							buf[_url] = Nothing{}
							v0.Url = append(v0.Url, TXUrl{Url: v.Url[i].Url, Ts: parseTime(v.Ts)})
							if _url[:8] == "https://" {
								v0.HTTPSBlock += 1
							}
						}
					}
					for i := range o.Url {
						_url := NormalizeUrl(o.Url[i].Url)
						if _, ok := buf[_url]; !ok {
							DumpSnap.Url.DelRes(_url, o.Id)
						}
					}
					buf = make(map[string]Nothing, len(v.Domain))
					if len(v.Domain) > 0 {
						v0.Domain = make([]TXDomain, 0, len(v.Domain))
						for i := range v.Domain {
							_domain := NormalizeDomain(v.Domain[i].Domain)
							DumpSnap.Domain.AddRes(_domain, v.Id)
							buf[_domain] = Nothing{}
							v0.Domain = append(v0.Domain, TXDomain{Domain: v.Domain[i].Domain, Ts: parseTime(v.Ts)})
						}
					}
					for i := range o.Domain {
						_domain := NormalizeDomain(o.Domain[i].Domain)
						if _, ok := buf[_domain]; !ok {
							DumpSnap.Domain.DelRes(_domain, o.Id)
						}
					}
					buf = nil
					SPass[v.Id] = Nothing{}
					stats.CntUpdate++
				} else {
					o.RegistryUpdateTime = r.UpdateTime
					SPass[o.Id] = Nothing{}
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
			for i := range o2.Ip {
				DumpSnap.Ip.DelIP(o2.Ip[i].Ip, o2.Id)
			}
			for i := range o2.Ip6 {
				DumpSnap.Ip6.DelRes(o2.Ip6[i].Ip6, o2.Id)
			}
			for i := range o2.Subnet6 {
				DumpSnap.Subnet6.DelRes(o2.Subnet6[i].Subnet6, o2.Id)
			}
			for i := range o2.Subnet {
				DumpSnap.Subnet.DelRes(o2.Subnet[i].Subnet, o2.Id)
			}
			for i := range o2.Url {
				DumpSnap.Url.DelRes(NormalizeUrl(o2.Url[i].Url), o2.Id)
			}
			for i := range o2.Domain {
				DumpSnap.Domain.DelRes(NormalizeDomain(o2.Domain[i].Domain), o2.Id)
			}
			delete(DumpSnap.Content.C, id)
			stats.CntRemove++
		}
	}
	DumpSnap.Content.Unlock()
	Info.Printf("Records: %d Add: %d Update: %d Remove: %d\n", stats.Cnt, stats.CntAdd, stats.CntUpdate, stats.CntRemove)
	Info.Printf("  IP: %d IPv6: %d Subnets: %d Subnets6: %d Domains: %d URSs: %d\n",
		len(DumpSnap.Ip), len(DumpSnap.Ip6), len(DumpSnap.Subnet), len(DumpSnap.Subnet6),
		len(DumpSnap.Domain), len(DumpSnap.Url))
	return err
}
