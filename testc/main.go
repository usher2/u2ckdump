//go:generate protoc -I ../msg --go_out=plugins=grpc:../msg ../msg/msg.proto

package main

import (
	"context"
	"encoding/json"
	"log"
	"time"

	pb "github.com/usher-2/u2ckdump/msg"
	"google.golang.org/grpc"
)

func parseIp4(s string) uint32 {
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

func searchID(c pb.CheckClient) {
	ids := []int32{13344, 100, 79682}
	for _, id := range ids {
		log.Printf("Looking for content: %d\n", id)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		r, err := c.SearchID(ctx, &pb.IDRequest{Query: id})
		if err != nil {
			log.Fatalf("%v.SearchID(_) = _, %v", c, err)
		}
		if r.Error != "" {
			log.Printf("ERROR: %s\n", r.Error)
		} else if len(r.Results) == 0 {
			log.Printf("Nothing... \n")
		} else {
			for i := range r.Results {
				b, _ := json.MarshalIndent(r.Results[i], "    ", "    ")
				log.Printf(string(b))
			}
		}
	}
}

func searchIP(c pb.CheckClient) {
	ips := []string{"1.1.1.1", "8.8.8.8", "149.154.167.99"}
	for _, ip := range ips {
		log.Printf("Looking for %s\n", ip)
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		r, err := c.SearchIP4(ctx, &pb.IP4Request{Query: parseIp4(ip)})
		if err != nil {
			log.Fatalf("%v.SearchIP4(_) = _, %v", c, err)
		}
		if r.Error != "" {
			log.Printf("ERROR: %s\n", r.Error)
		} else if len(r.Results) == 0 {
			log.Printf("Nothing... \n")
		} else {
			for i := range r.Results {
				b, _ := json.MarshalIndent(r.Results[i], "    ", "    ")
				log.Printf(string(b))
			}
		}
	}
}

func main() {
	var opts []grpc.DialOption
	opts = append(opts, grpc.WithInsecure())
	opts = append(opts, grpc.WithBlock())
	conn, err := grpc.Dial("localhost:50001", opts...)
	if err != nil {
		log.Fatalf("fail to dial: %v", err)
	}
	defer conn.Close()
	log.Printf("Connect...\n")
	c := pb.NewCheckClient(conn)
	//searchIP(c)
	searchID(c)
}
