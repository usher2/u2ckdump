package main

import (
	"bytes"
	"encoding/xml"
	"golang.org/x/net/html/charset"
	"golang.org/x/net/idna"
	"hash/crc32"
	"io"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

type TContentMap struct {
	sync.RWMutex
	C map[int]*TXContent
}

type TDump struct {
	Ip                                map[uint32]map[int]struct{}
	Ip6, Subnet, Subnet6, Url, Domain map[string]map[int]struct{}
	Content                           TContentMap
}

var DumpSnap = TDump{
	Ip:      make(map[uint32]map[int]struct{}),
	Ip6:     make(map[string]map[int]struct{}),
	Subnet:  make(map[string]map[int]struct{}),
	Subnet6: make(map[string]map[int]struct{}),
	Url:     make(map[string]map[int]struct{}),
	Domain:  make(map[string]map[int]struct{}),
	Content: TContentMap{C: make(map[int]*TXContent)},
}

type TReg struct {
	UpdateTime         int64
	UpdateTimeUrgently string
	FormatVersion      string
}

type TDomain struct {
	Domain string `xml:",cdata"`
	Ts     string `xml:"ts,attr,omitempty"`
}

type TXDomain struct {
	Domain string `json:"domain"`
	Ts     int64  `json:"ts,omitempty"`
}

type TUrl struct {
	Url string `xml:",cdata"`
	Ts  string `xml:"ts,attr,omitempty"`
}

type TXUrl struct {
	Url string `json:"url"`
	Ts  int64  `json:"ts,omitempty"`
}

type TIp struct {
	Ip string `xml:",chardata"`
	Ts string `xml:"ts,attr,omitempty"`
}

type TXIp struct {
	Ip uint32 `json:"ip"`
	Ts int64  `json:"ts,omitempty"`
}

type TIp6 struct {
	Ip6 string `xml:",chardata"`
	Ts  string `xml:"ts,attr,omitempty"`
}

type TXIp6 struct {
	Ip6 string `json:"ip6"`
	Ts  int64  `json:"ts,omitempty"`
}

type TSubnet struct {
	Subnet string `xml:",chardata"`
	Ts     string `xml:"ts,attr,omitempty"`
}

type TXSubnet struct {
	Subnet string `json:"subnet"`
	Ts     int64  `json:"ts,omitempty"`
}

type TSubnet6 struct {
	Subnet6 string `xml:",chardata"`
	Ts      string `xml:"ts,attr,omitempty"`
}

type TXSubnet6 struct {
	Subnet6 string `json:"subnet6"`
	Ts      int64  `json:"ts,omitempty"`
}

type TXDecision struct {
	Date   string `json:"date"`
	Number string `json:"number"`
	Org    string `json:"org"`
}

type TContent struct {
	Id          int `xml:"id,attr" json:"id"`
	EntryType   int `xml:"entryType,attr" json:"entryType"`
	UrgencyType int `xml:"urgencyType,attr,omitempty" json:"urgencyType,omitempty"`
	Decision    struct {
		Date   string `xml:"date,attr"`
		Number string `xml:"number,attr"`
		Org    string `xml:"org,attr"`
	} `xml:"decision" json:"decision"`
	IncludeTime string     `xml:"includeTime,attr" json:"includeTime"`
	BlockType   string     `xml:"blockType,attr,omitempty" json:"blockType,omitempty"`
	Hash        string     `xml:"hash,attr" json:"hash"`
	Ts          string     `xml:"ts,attr,omitempty" json:"ts,omitempty"`
	Url         []TUrl     `xml:"url,omitempty" json:"url,omitempty"`
	Ip          []TIp      `xml:"ip,omitempty" json:"ip,omitempty"`
	Ip6         []TIp6     `xml:"ipv6,omitempty" json:"ip6,omitempty"`
	Subnet      []TSubnet  `xml:"ipSubnet,omitempty" json:"subnet,omitempty"`
	Subnet6     []TSubnet6 `xml:"ipv6Subnet,omitempty" json:"subnet6,omitempty"`
	Domain      []TDomain  `xml:"domain,omitempty" json:"domain,omitempty"`
}

type TXContent struct {
	Id                 int         `json:"id"`
	EntryType          int         `json:"entryType"`
	UrgencyType        int         `json:"urgencyType,omitempty"`
	HTTPSBlock         int         `json:"https,omitempty"`
	RegistryUpdateTime int64       `json:"registry"`
	Decision           TXDecision  `json:"decision"`
	IncludeTime        int64       `json:"includeTime"`
	BlockType          string      `json:"blockType,omitempty"`
	Hash               string      `json:"hash"`
	Ts                 int64       `json:"ts,omitempty"`
	U2Hash             uint32      `xml:"-" json:"-"`
	Url                []TXUrl     `json:"url,omitempty"`
	Ip                 []TXIp      `json:"ip,omitempty"`
	Ip6                []TXIp6     `json:"ip6,omitempty"`
	Subnet             []TXSubnet  `json:"subnet,omitempty"`
	Subnet6            []TXSubnet6 `json:"subnet6,omitempty"`
	Domain             []TXDomain  `json:"domain,omitempty"`
}

// my parser without slices
func ip2i(s string) uint32 {
	var ip, n uint32 = 0, 0
	var r uint = 24
	for i := 0; i < len(s); i++ {
		if '0' <= s[i] && s[i] <= '9' {
			n = n*10 + uint32(s[i]-'0')
			if n > 0xFF {
				//Debug.Printf("Bad IP (1) n=%d: %s\n", n, s)
				return 0xFFFFFFFF
			}
		} else if s[i] == '.' {
			if r != 0 {
				ip = ip + (n << r)
			} else {
				//Debug.Printf("Bad IP (2): %s\n", s)
				return 0xFFFFFFFF
			}
			r = r - 8
			n = 0
		} else {
			//Debug.Printf("Bad IP (3): %s\n", s)
			return 0xFFFFFFFF
		}
	}
	if r != 0 {
		//Debug.Printf("Bad IP (4): %s\n", s)
		return 0xFFFFFFFF
	}
	ip = ip + n
	return ip
}

func DelRes(a map[string]map[int]struct{}, i string, id int) {
	if v, ok := a[i]; ok {
		delete(v, id)
		if len(v) == 0 {
			delete(a, i)
		}
	}
}

func DelIP4(a map[uint32]map[int]struct{}, ip uint32, id int) {
	if v, ok := a[ip]; ok {
		delete(v, id)
		if len(v) == 0 {
			delete(a, ip)
		}
	}
}

func AddRes(a map[string]map[int]struct{}, i string, id int) {
	if v, ok := a[i]; !ok {
		v = make(map[int]struct{})
		v[id] = struct{}{}
		a[i] = v
	} else {
		v[id] = struct{}{}
	}
}

func AddIP4(a map[uint32]map[int]struct{}, ip uint32, id int) {
	if v, ok := a[ip]; !ok {
		v = make(map[int]struct{})
		v[id] = struct{}{}
		a[ip] = v
	} else {
		v[id] = struct{}{}
	}
}

func NormalizeDomain(domain string) string {
	domain = strings.Replace(domain, ",", ".", -1)
	domain = strings.Replace(domain, " ", "", -1)
	if _c := strings.IndexByte(domain, '/'); _c >= 0 {
		domain = domain[:_c]
	}
	if _c := strings.IndexByte(domain, '\\'); _c >= 0 {
		domain = domain[:_c]
	}
	domain = strings.TrimPrefix(domain, "*.")
	domain, _ = idna.ToASCII(domain)
	domain = strings.ToLower(domain)
	return domain
}

func NormalizeUrl(u string) string {
	u = strings.Replace(u, "\\", "/", -1)
	_url, err := url.Parse(u)
	if err != nil {
		Error.Printf("URL parse error: %s\n", err.Error())
		// add as is
		return u
	} else {
		port := ""
		domain := _url.Hostname()
		colon := strings.LastIndexByte(domain, ':')
		if colon != -1 && validOptionalPort(domain[colon:]) {
			domain, port = domain[:colon], domain[colon+1:]
		}
		domain = NormalizeDomain(domain)
		_url.Host = domain
		if port != "" {
			_url.Host = _url.Host + ":" + port
		}
		_url.Fragment = ""
		return _url.String()
	}
}

var crc32Table *crc32.Table = crc32.MakeTable(crc32.Castagnoli)

func parseTime(s string) int64 {
	if s == "" {
		return 0
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		Error.Printf("Can't parse time: %s (%s)\n", err.Error(), s)
		return 0
	}
	return t.Unix()
}

const parseIncludeTime = "2006-01-02T15:04:05"

func parseTime2(s string) int64 {
	if s == "" {
		return 0
	}
	t, err := time.Parse(parseIncludeTime, s)
	if err != nil {
		Error.Printf("Can't parse time: %s (%s)\n", err.Error(), s)
		return 0
	}
	return t.Unix() - 3600*3
}

func Parse(dumpfile string) error {
	var Cnt, CntAdd, CntUpdate, CntRemove int
	var r TReg
	var buf map[string]struct{}
	var bufi map[uint32]struct{}
	SPass := make(map[int]struct{}, len(DumpSnap.Content.C)+1000)
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
			_name := _e.Name.Local
			switch _name {
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
							AddIP4(DumpSnap.Ip, ip, v.Id)
							v0.Ip = append(v0.Ip, TXIp{Ip: ip, Ts: parseTime(v.Ts)})
						}
					}
					if len(v.Ip6) > 0 {
						v0.Ip6 = make([]TXIp6, 0, len(v.Ip6))
						for i := range v.Ip6 {
							ip6 := string(net.ParseIP(v.Ip6[i].Ip6))
							AddRes(DumpSnap.Ip6, ip6, v.Id)
							v0.Ip6 = append(v0.Ip6, TXIp6{Ip6: ip6, Ts: parseTime(v.Ts)})
						}
					}
					if len(v.Subnet6) > 0 {
						v0.Subnet6 = make([]TXSubnet6, 0, len(v.Subnet6))
						for i := range v.Subnet6 {
							AddRes(DumpSnap.Subnet6, v.Subnet6[i].Subnet6, v.Id)
							v0.Subnet6 = append(v0.Subnet6, TXSubnet6{Subnet6: v.Subnet6[i].Subnet6, Ts: parseTime(v.Ts)})
						}
					}
					if len(v.Subnet) > 0 {
						v0.Subnet = make([]TXSubnet, 0, len(v.Subnet))
						for i := range v.Subnet {
							AddRes(DumpSnap.Subnet, v.Subnet[i].Subnet, v.Id)
							v0.Subnet = append(v0.Subnet, TXSubnet{Subnet: v.Subnet[i].Subnet, Ts: parseTime(v.Ts)})
						}
					}
					if len(v.Url) > 0 {
						v0.Url = make([]TXUrl, 0, len(v.Url))
						for i := range v.Url {
							v0.Url = append(v0.Url, TXUrl{Url: v.Url[i].Url, Ts: parseTime(v.Ts)})
							_url := NormalizeUrl(v.Url[i].Url)
							AddRes(DumpSnap.Url, _url, v.Id)
							if _url[:8] == "https" {
								v0.HTTPSBlock += 1
							}
						}
					}
					if len(v.Domain) > 0 {
						v0.Domain = make([]TXDomain, 0, len(v.Domain))
						for i := range v.Domain {
							AddRes(DumpSnap.Domain, NormalizeDomain(v.Domain[i].Domain), v.Id)
							v0.Domain = append(v0.Domain, TXDomain{Domain: v.Domain[i].Domain, Ts: parseTime(v.Ts)})
						}
					}
					SPass[v.Id] = struct{}{}
					CntAdd++
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
					bufi = make(map[uint32]struct{}, len(v.Ip))
					if len(v.Ip) > 0 {
						v0.Ip = make([]TXIp, 0, len(v.Ip))
						for i := range v.Ip {
							ip := ip2i(v.Ip[i].Ip)
							AddIP4(DumpSnap.Ip, ip, v.Id)
							bufi[ip] = struct{}{}
							v0.Ip = append(v0.Ip, TXIp{Ip: ip})
						}
					}
					for i := range o.Ip {
						ip := o.Ip[i].Ip
						if _, ok := bufi[ip]; !ok {
							DelIP4(DumpSnap.Ip, ip, o.Id)
						}
					}
					bufi = nil
					buf = make(map[string]struct{}, len(v.Ip6))
					if len(v.Ip6) > 0 {
						v0.Ip6 = make([]TXIp6, 0, len(v.Ip6))
						for i := range v.Ip6 {
							ip6 := string(net.ParseIP(v.Ip6[i].Ip6))
							AddRes(DumpSnap.Ip6, ip6, v.Id)
							buf[ip6] = struct{}{}
							v0.Ip6 = append(v0.Ip6, TXIp6{Ip6: ip6, Ts: parseTime(v.Ts)})
						}
					}
					for i := range o.Ip6 {
						ip6 := string(net.ParseIP(o.Ip6[i].Ip6))
						if _, ok := buf[ip6]; !ok {
							DelRes(DumpSnap.Ip6, ip6, o.Id)
						}
					}
					buf = make(map[string]struct{}, len(v.Subnet))
					if len(v.Subnet) > 0 {
						v0.Subnet = make([]TXSubnet, 0, len(v.Subnet))
						for i := range v.Subnet {
							AddRes(DumpSnap.Subnet, v.Subnet[i].Subnet, v.Id)
							buf[v.Subnet[i].Subnet] = struct{}{}
							v0.Subnet = append(v0.Subnet, TXSubnet{Subnet: v.Subnet[i].Subnet, Ts: parseTime(v.Ts)})
						}
					}
					for i := range o.Subnet {
						if _, ok := buf[o.Subnet[i].Subnet]; !ok {
							DelRes(DumpSnap.Subnet, o.Subnet[i].Subnet, o.Id)
						}
					}
					buf = make(map[string]struct{}, len(v.Subnet6))
					if len(v.Subnet6) > 0 {
						v0.Subnet6 = make([]TXSubnet6, 0, len(v.Subnet6))
						for i := range v.Subnet6 {
							AddRes(DumpSnap.Subnet6, v.Subnet6[i].Subnet6, v.Id)
							buf[v.Subnet6[i].Subnet6] = struct{}{}
							v0.Subnet6 = append(v0.Subnet6, TXSubnet6{Subnet6: v.Subnet6[i].Subnet6, Ts: parseTime(v.Ts)})
						}
					}
					for i := range o.Subnet6 {
						if _, ok := buf[o.Subnet6[i].Subnet6]; !ok {
							DelRes(DumpSnap.Subnet6, o.Subnet6[i].Subnet6, o.Id)
						}
					}
					buf = make(map[string]struct{}, len(v.Url))
					if len(v.Url) > 0 {
						v0.Url = make([]TXUrl, 0, len(v.Url))
						for i := range v.Url {
							_url := NormalizeUrl(v.Url[i].Url)
							AddRes(DumpSnap.Url, _url, v.Id)
							buf[_url] = struct{}{}
							v0.Url = append(v0.Url, TXUrl{Url: v.Url[i].Url, Ts: parseTime(v.Ts)})
							if _url[:8] == "https://" {
								v0.HTTPSBlock += 1
							}
						}
					}
					for i := range o.Url {
						_url := NormalizeUrl(o.Url[i].Url)
						if _, ok := buf[_url]; !ok {
							DelRes(DumpSnap.Url, _url, o.Id)
						}
					}
					buf = make(map[string]struct{}, len(v.Domain))
					if len(v.Domain) > 0 {
						v0.Domain = make([]TXDomain, 0, len(v.Domain))
						for i := range v.Domain {
							_domain := NormalizeDomain(v.Domain[i].Domain)
							AddRes(DumpSnap.Domain, _domain, v.Id)
							buf[_domain] = struct{}{}
							v0.Domain = append(v0.Domain, TXDomain{Domain: v.Domain[i].Domain, Ts: parseTime(v.Ts)})
						}
					}
					for i := range o.Domain {
						_domain := NormalizeDomain(o.Domain[i].Domain)
						if _, ok := buf[_domain]; !ok {
							DelRes(DumpSnap.Domain, _domain, o.Id)
						}
					}
					buf = nil
					SPass[v.Id] = struct{}{}
					CntUpdate++
				} else {
					o.RegistryUpdateTime = r.UpdateTime
					SPass[o.Id] = struct{}{}
					//v = nil
				}
				DumpSnap.Content.Unlock()
				Cnt++
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
				DelIP4(DumpSnap.Ip, o2.Ip[i].Ip, o2.Id)
			}
			for i := range o2.Ip6 {
				DelRes(DumpSnap.Ip6, o2.Ip6[i].Ip6, o2.Id)
			}
			for i := range o2.Subnet6 {
				DelRes(DumpSnap.Subnet6, o2.Subnet6[i].Subnet6, o2.Id)
			}
			for i := range o2.Subnet {
				DelRes(DumpSnap.Subnet, o2.Subnet[i].Subnet, o2.Id)
			}
			for i := range o2.Url {
				DelRes(DumpSnap.Url, NormalizeUrl(o2.Url[i].Url), o2.Id)
			}
			for i := range o2.Domain {
				DelRes(DumpSnap.Domain, NormalizeDomain(o2.Domain[i].Domain), o2.Id)
			}
			delete(DumpSnap.Content.C, id)
			CntRemove++
		}
	}
	DumpSnap.Content.Unlock()
	Info.Printf("Records: %d Add: %d Update: %d Remove: %d\n", Cnt, CntAdd, CntUpdate, CntRemove)
	Info.Printf("  IP: %d IPv6: %d Subnets: %d Subnets6: %d Domains: %d URSs: %d\n",
		len(DumpSnap.Ip), len(DumpSnap.Ip6), len(DumpSnap.Subnet), len(DumpSnap.Subnet6),
		len(DumpSnap.Domain), len(DumpSnap.Url))
	return err
}

func Parse2(UpdateTime int64) {
	DumpSnap.Content.Lock()
	for _, v := range DumpSnap.Content.C {
		v.RegistryUpdateTime = UpdateTime
	}
	DumpSnap.Content.Unlock()
}
