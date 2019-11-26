package main

//go:generate protoc -I msg --go_out=plugins=grpc:msg msg/msg.proto

import (
	"context"
	"time"

	pb "github.com/usher2/u2ckdump/msg"
)

type server struct {
	pb.UnimplementedCheckServer
}

func (s *server) SearchID(ctx context.Context, in *pb.IDRequest) (*pb.SearchResponse, error) {
	query := in.GetQuery()
	Debug.Printf("Received content ID: %d\n", query)
	if DumpSnap != nil && DumpSnap.utime > 0 {
		DumpSnap.RLock()
		r := &pb.SearchResponse{}
		if v, ok := DumpSnap.Content[query]; ok {
			r.Results = make([]*pb.Content, 1)
			r.Results[0] = v.newPbContent(0, nil, "", "", "")
		}
		DumpSnap.RUnlock()
		return r, nil
	} else {
		return &pb.SearchResponse{Error: "Data not ready"}, nil
	}
}

func (s *server) SearchIP4(c context.Context, in *pb.IP4Request) (*pb.SearchResponse, error) {
	var v1, v2 ArrayIntSet
	var vnw []string
	query := in.GetQuery()
	ipb := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, byte((query & 0xFF000000) >> 24), byte((query & 0x00FF0000) >> 16), byte((query & 0x0000FF00) >> 8), byte(query & 0x000000FF)}
	Debug.Printf("Received IPv4: %d.%d.%d.%d\n", ipb[12], ipb[13], ipb[14], ipb[15])
	if DumpSnap != nil && DumpSnap.utime > 0 {
		DumpSnap.RLock()
		r := &pb.SearchResponse{}
		cnw, err := DumpSnap.net.ContainingNetworks(ipb)
		if err != nil {
			Debug.Printf("Can't get containing networks: %d.%d.%d.%d: %s\n", ipb[12], ipb[13], ipb[14], ipb[15], err.Error())
		} else {
			for _, nw := range cnw {
				_nw := nw.Network()
				nwstr := _nw.String()
				if a, ok := DumpSnap.subnet[nwstr]; ok {
					for _, id := range a {
						v1 = append(v1, id)
						vnw = append(vnw, nwstr)
					}
				}
			}
		}
		if a, ok := DumpSnap.ip[query]; ok {
			for _, id := range a {
				v2 = append(v2, id)
			}
		}
		r.Results = make([]*pb.Content, len(v1)+len(v2))
		j := 0
		for i, id := range v1 {
			if v, ok := DumpSnap.Content[id]; ok {
				r.Results[j] = v.newPbContent(0, nil, "", "", vnw[i])
				j++
			}
		}
		for _, id := range v2 {
			if v, ok := DumpSnap.Content[id]; ok {
				r.Results[j] = v.newPbContent(query, nil, "", "", "")
				j++
			}
		}
		DumpSnap.RUnlock()
		return r, nil
	} else {
		return &pb.SearchResponse{Error: "Data not ready"}, nil
	}
}

func (s *server) SearchIP6(ctx context.Context, in *pb.IP6Request) (*pb.SearchResponse, error) {
	query := in.GetQuery()
	Debug.Printf("Received IPv6: %v\n", query)
	if DumpSnap != nil && DumpSnap.utime > 0 {
		DumpSnap.RLock()
		r := &pb.SearchResponse{}
		a := DumpSnap.ip6[string(query)]
		r.Results = make([]*pb.Content, len(a))
		i := 0
		for _, id := range a {
			if v, ok := DumpSnap.Content[id]; ok {
				r.Results[i] = v.newPbContent(0, query, "", "", "")
				i++
			}
		}
		DumpSnap.RUnlock()
		return r, nil
	} else {
		return &pb.SearchResponse{Error: "Data not ready"}, nil
	}
}

func (s *server) SearchURL(ctx context.Context, in *pb.URLRequest) (*pb.SearchResponse, error) {
	query := in.GetQuery()
	Debug.Printf("Received URL: %v\n", query)
	if DumpSnap != nil && DumpSnap.utime > 0 {
		DumpSnap.RLock()
		r := &pb.SearchResponse{}
		a := DumpSnap.url[query]
		r.Results = make([]*pb.Content, len(a))
		i := 0
		for _, id := range a {
			if v, ok := DumpSnap.Content[id]; ok {
				r.Results[i] = v.newPbContent(0, nil, "", query, "")
				i++
			}
		}
		DumpSnap.RUnlock()
		return r, nil
	} else {
		return &pb.SearchResponse{Error: "Data not ready"}, nil
	}
}

func (s *server) SearchDomain(ctx context.Context, in *pb.DomainRequest) (*pb.SearchResponse, error) {
	query := in.GetQuery()
	Debug.Printf("Received Domain: %v\n", query)
	if DumpSnap != nil && DumpSnap.utime > 0 {
		DumpSnap.RLock()
		r := &pb.SearchResponse{}
		a := DumpSnap.domain[query]
		r.Results = make([]*pb.Content, len(a))
		i := 0
		for _, id := range a {
			if v, ok := DumpSnap.Content[id]; ok {
				r.Results[i] = v.newPbContent(0, nil, query, "", "")
				i++
			}
		}
		DumpSnap.RUnlock()
		return r, nil
	} else {
		return &pb.SearchResponse{Error: "Data not ready"}, nil
	}
}
func (s *server) Ping(ctx context.Context, in *pb.PingRequest) (*pb.PingResponse, error) {
	ping := in.GetPing()
	Debug.Printf("Received Ping: %v\n", ping)
	dumptime := time.Unix(DumpSnap.utime, 0).In(time.FixedZone("MSK", 3)).Format(time.RFC3339)
	r := &pb.PingResponse{Pong: "I heed my lord\n" + "Last dump: " + dumptime + "\n"}
	return r, nil
}
