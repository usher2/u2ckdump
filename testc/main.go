//go:generate protoc -I ../msg --go_out=plugins=grpc:../msg ../msg/msg.proto

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"

	pb "github.com/usher2/u2ckdump/msg"
	"golang.org/x/net/idna"
	"google.golang.org/grpc"
)

type TContent struct {
	Id          int32      `json:"id"`
	EntryType   int32      `json:"et"`
	UrgencyType int32      `json:"ut,omitempty"`
	Decision    TDecision  `json:"d"`
	IncludeTime int64      `json:"it"`
	Ts          int64      `json:"ts,omitempty"`
	BlockType   string     `json:"bt,omitempty"`
	Hash        string     `json:"h"`
	Url         []TUrl     `json:"url,omitempty"`
	Ip4         []TIp4     `json:"ip4,omitempty"`
	Ip6         []TIp6     `json:"ip6,omitempty"`
	Subnet4     []TSubnet4 `json:"sb4,omitempty"`
	Subnet6     []TSubnet6 `json:"sb6,omitempty"`
	Domain      []TDomain  `json:"dm,omitempty"`
	HttpsBlock  int        `json:"hb"`
	U2Hash      uint32     `json:"u2h"`
}

type TSubnet6 struct {
	Subnet6 string `json:"sb6"`
	Ts      int64  `json:"ts,omitempty"`
}

type TSubnet4 struct {
	Subnet4 string `json:"sb4"`
	Ts      int64  `json:"ts,omitempty"`
}

type TDomain struct {
	Domain string `json:"dm"`
	Ts     int64  `json:"ts,omitempty"`
}

type TUrl struct {
	Url string `json:"u"`
	Ts  int64  `json:"ts,omitempty"`
}

type TIp4 struct {
	Ip4 uint32 `json:"ip4"`
	Ts  int64  `json:"ts,omitempty"`
}

type TIp6 struct {
	Ip6 string `json:"ip6"`
	Ts  int64  `json:"ts,omitempty"`
}

type TDecision struct {
	Date   string `xml:"date,attr" json:"dd"`
	Number string `xml:"number,attr" json:"dn"`
	Org    string `xml:"org,attr" json:"do"`
}

func validOptionalPort(port string) bool {
	if port == "" {
		return true
	}
	if port[0] != ':' {
		return false
	}
	for _, b := range port[1:] {
		if b < '0' || b > '9' {
			return false
		}
	}
	return true
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
		fmt.Printf("URL parse error: %s\n", err.Error())
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

func parseIp4(s string) uint32 {
	var ip, n uint32 = 0, 0
	var r uint = 24
	for i := 0; i < len(s); i++ {
		if '0' <= s[i] && s[i] <= '9' {
			n = n*10 + uint32(s[i]-'0')
			if n > 0xFF {
				// Debug.Printf("Bad IP (1) n=%d: %s\n", n, s)
				return 0xFFFFFFFF
			}
		} else if s[i] == '.' {
			if r != 0 {
				ip = ip + (n << r)
			} else {
				// Debug.Printf("Bad IP (2): %s\n", s)
				return 0xFFFFFFFF
			}
			r = r - 8
			n = 0
		} else {
			// Debug.Printf("Bad IP (3): %s\n", s)
			return 0xFFFFFFFF
		}
	}
	if r != 0 {
		// Debug.Printf("Bad IP (4): %s\n", s)
		return 0xFFFFFFFF
	}
	ip = ip + n
	return ip
}

func printContent(packet *pb.Content) {
	content := TContent{}
	err := json.Unmarshal(packet.Pack, &content)
	if err != nil {
		fmt.Printf("Oooops!!! %s\n", err.Error)
		return
	}
	if (content.BlockType == "" || content.BlockType == "default") && content.HttpsBlock == 0 {
		fmt.Print("URL block. ")
	} else if (content.BlockType == "" || content.BlockType == "default") && content.HttpsBlock > 0 {
		fmt.Print("HTTPS URL block. ")
	} else if content.BlockType == "domain" {
		fmt.Print("Domain block. ")
	} else if content.BlockType == "domain-mask" {
		fmt.Print("Domain mask block. ")
	} else if content.BlockType == "ip" {
		fmt.Print("IP block. ")
	}
	fmt.Printf("#%d %s №%s %s\n", content.Id, content.Decision.Org, content.Decision.Number, content.Decision.Date)
	fmt.Printf("    \\_IPv4: %d, IPv6: %d, URL: %d, Domains: %d, Subnet: %d, Subnet6: %d\n",
		len(content.Ip4), len(content.Ip6), len(content.Url), len(content.Domain), len(content.Subnet4), len(content.Subnet6))
	if packet.Aggr != "" {
		fmt.Printf("    by %s\n", packet.Aggr)
	}
}

func searchID(c pb.CheckClient) {
	ids := []int32{13344, 100, 79682}
	for _, id := range ids {
		fmt.Printf("Looking for content: %d\n", id)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		r, err := c.SearchContentID(ctx, &pb.ContentIDRequest{Query: id})
		if err != nil {
			fmt.Printf("%v.SearchID(_) = _, %v\n", c, err)
			return
		}
		if r.Error != "" {
			fmt.Printf("ERROR: %s\n", r.Error)
		} else if len(r.Results) == 0 {
			fmt.Printf("Nothing... \n")
		} else {
			for _, content := range r.Results {
				printContent(content)
			}
		}
		fmt.Println()
	}
}

func searchIP(c pb.CheckClient) {
	ips := []string{"1.1.1.1", "8.8.8.8", "149.154.167.99"}
	for _, ip := range ips {
		fmt.Printf("Looking for %s\n", ip)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		r, err := c.SearchIPv4(ctx, &pb.IPv4Request{Query: parseIp4(ip)})
		if err != nil {
			fmt.Printf("%v.SearchIP4(_) = _, %v\n", c, err)
			return
		}
		if r.Error != "" {
			fmt.Printf("ERROR: %s\n", r.Error)
		} else if len(r.Results) == 0 {
			fmt.Printf("Nothing... \n")
		} else {
			for _, content := range r.Results {
				printContent(content)
			}
		}
		fmt.Println()
	}
}

func searchIP6(c pb.CheckClient) {
	ips := []string{"diphost.ru", "2606:4700:0030:0000:0000:0000:6818:626b", "2606:4700:0030:0000:0000:0000:6818:6dfb", "2c0f:f930:0000:0004:0000:0000:0000:0108"}
	for _, ip := range ips {
		fmt.Printf("Looking for %s\n", ip)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		ip6 := net.ParseIP(ip)
		if len(ip6) == 0 {
			fmt.Printf("Can't parse IP: %s\n", ip)
		}
		r, err := c.SearchIPv6(ctx, &pb.IPv6Request{Query: ip6})
		if err != nil {
			fmt.Printf("%v.SearchIP6(_) = _, %v\n", c, err)
			return
		}
		if r.Error != "" {
			fmt.Printf("ERROR: %s\n", r.Error)
		} else if len(r.Results) == 0 {
			fmt.Printf("Nothing... \n")
		} else {
			for _, content := range r.Results {
				printContent(content)
			}
		}
		fmt.Println()
	}
}

func searchURL(c pb.CheckClient) {
	urls := []string{"http://muzlishko.ru/mp3/%D0%93%D1%80%D0%B0%D1%87%D0%B8%20%D0%A3%D0%BB%D0%B5%D1%B82%D0%B5%D0%BB%D0%B8,%20%D0%A5%D0%B0%D1%87%D0%B8%20%D0%BF%D1%80%D0%D8%D0%BB%D0%B5%D1%82%D0%B5%D0%BB%D0%B8%", "https://гей-порно.com/", "https://grclip.com/rev/%D1%80%D1%83%D0%B1%D0%B5%D0%BD+%D1%82%D0%B0%D1%82%D1%83%D0%BB%D1%8F%D0%BD+2018/", "http://genocid.net/в-сочи-пришлые-бандиты-крепко-держат-власть-в-своих-руках/"}
	for _, u := range urls {
		_url := NormalizeUrl(u)
		if _url != u {
			fmt.Printf("Input was %s\n", u)
		}
		fmt.Printf("Looking for %s\n", _url)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		r, err := c.SearchURL(ctx, &pb.URLRequest{Query: _url})
		if err != nil {
			fmt.Printf("%v.SearchURL(_) = _, %v\n", c, err)
			return
		}
		if r.Error != "" {
			fmt.Printf("ERROR: %s\n", r.Error)
		} else if len(r.Results) == 0 {
			fmt.Printf("Nothing... \n")
		} else {
			for _, content := range r.Results {
				printContent(content)
			}
		}
		fmt.Println()
	}
}

func searchDomain(c pb.CheckClient) {
	domains := []string{"pro100farma.net\\stanozolol\\", "stulchik.net"}
	for _, domain := range domains {
		_domain := NormalizeDomain(domain)
		if _domain != domain {
			fmt.Printf("Input was %s\n", domain)
		}
		fmt.Printf("Looking for %s\n", _domain)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		r, err := c.SearchDomain(ctx, &pb.DomainRequest{Query: NormalizeDomain(domain)})
		if err != nil {
			fmt.Printf("%v.SearchURL(_) = _, %v\n", c, err)
			return
		}
		if r.Error != "" {
			fmt.Printf("ERROR: %s\n", r.Error)
		} else if len(r.Results) == 0 {
			fmt.Printf("Nothing... \n")
		} else {
			for _, content := range r.Results {
				printContent(content)
			}
		}
		fmt.Println()
	}
}

func makePing(c pb.CheckClient) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	r, err := c.Ping(ctx, &pb.PingRequest{Ping: "How are you?"})
	if err != nil {
		fmt.Printf("%v.Ping(_) = _, %v\n", c, err)
	}
	fmt.Printf("Pong: %s\n", r.Pong)
}

func main() {
	var opts []grpc.DialOption
	opts = append(opts, grpc.WithInsecure())
	opts = append(opts, grpc.WithBlock())
	conn, err := grpc.Dial("localhost:50001", opts...)
	if err != nil {
		fmt.Printf("fail to dial: %v", err)
	}
	defer conn.Close()
	fmt.Printf("Connect...\n")
	c := pb.NewCheckClient(conn)
	makePing(c)
	searchID(c)
	searchIP(c)
	searchIP6(c)
	searchURL(c)
	searchDomain(c)
	makePing(c)
}
