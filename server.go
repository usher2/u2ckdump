package main

//go:generate protoc -I msg --go_out=plugins=grpc:msg msg/msg.proto

import (
	"context"

	pb "github.com/usher-2/u2ckdump/msg"
)

type server struct {
	pb.UnimplementedCheckServer
}

func (s *server) SearchID(ctx context.Context, in *pb.IDRequest) (*pb.SearchResponse, error) {
	query := in.GetQuery()
	Debug.Printf("Received content ID: %d\n", query)
	if DumpSnap != nil && DumpSnap.utime > 0 {
		DumpSnap.Content.RLock()
		r := &pb.SearchResponse{}
		if v, ok := DumpSnap.Content.C[query]; ok {
			r.Results = make([]*pb.Content, 1)
			r.Results[0] = v
		}
		DumpSnap.Content.RUnlock()
		return r, nil
	} else {
		return &pb.SearchResponse{Error: "Data not ready"}, nil
	}
}

func (s *server) SearchIP4(c context.Context, in *pb.IP4Request) (*pb.SearchResponse, error) {
	var v1 []ArrayIntSet
	query := in.GetQuery()
	ipb := []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, byte((query & 0xFF000000) >> 24), byte((query & 0x00FF0000) >> 16), byte((query & 0x0000FF00) >> 8), byte(query & 0x000000FF)}
	Debug.Printf("Received IPv4: %d.%d.%d.%d\n", ipb[12], ipb[13], ipb[14], ipb[15])
	if DumpSnap != nil && DumpSnap.utime > 0 {
		DumpSnap.Content.RLock()
		r := &pb.SearchResponse{}
		v := DumpSnap.ip[query]
		vc := 0
		cnw, err := DumpSnap.net.ContainingNetworks(ipb)
		if err != nil {
			Debug.Printf("Can't get containing networks: %d.%d.%d.%d: %s\n", ipb[12], ipb[13], ipb[14], ipb[15], err.Error())
		} else {
			for _, nw := range cnw {
				_nw := nw.Network()
				if _v, ok := DumpSnap.subnet[_nw.String()]; ok {
					v1 = append(v1, _v)
					vc += len(_v)
				}
			}
		}
		r.Results = make([]*pb.Content, len(v)+vc)
		i := 0
		for _, id := range v {
			r.Results[i] = DumpSnap.Content.C[id]
			i++
		}
		for j, _ := range v1 {
			for _, id := range v1[j] {
				r.Results[i] = DumpSnap.Content.C[id]
				i++
			}
		}
		DumpSnap.Content.RUnlock()
		return r, nil
	} else {
		return &pb.SearchResponse{Error: "Data not ready"}, nil
	}
}

func (s *server) SearchIP6(ctx context.Context, in *pb.IP6Request) (*pb.SearchResponse, error) {
	query := in.GetQuery()
	Debug.Printf("Received IPv6: %v\n", query)
	if DumpSnap != nil && DumpSnap.utime > 0 {
		DumpSnap.Content.RLock()
		r := &pb.SearchResponse{}
		v := DumpSnap.ip6[string(query)]
		r.Results = make([]*pb.Content, len(v))
		i := 0
		for _, id := range v {
			r.Results[i] = DumpSnap.Content.C[id]
			i++
		}
		DumpSnap.Content.RUnlock()
		return r, nil
	} else {
		return &pb.SearchResponse{Error: "Data not ready"}, nil
	}
}

func (s *server) SearchURL(ctx context.Context, in *pb.URLRequest) (*pb.SearchResponse, error) {
	query := in.GetQuery()
	Debug.Printf("Received URL: %v\n", query)
	if DumpSnap != nil && DumpSnap.utime > 0 {
		DumpSnap.Content.RLock()
		r := &pb.SearchResponse{}
		v := DumpSnap.url[query]
		r.Results = make([]*pb.Content, len(v))
		i := 0
		for _, id := range v {
			r.Results[i] = DumpSnap.Content.C[id]
			i++
		}
		DumpSnap.Content.RUnlock()
		return r, nil
	} else {
		return &pb.SearchResponse{Error: "Data not ready"}, nil
	}
}

func (s *server) SearchDomain(ctx context.Context, in *pb.DomainRequest) (*pb.SearchResponse, error) {
	query := in.GetQuery()
	Debug.Printf("Received Domain: %v\n", query)
	if DumpSnap != nil && DumpSnap.utime > 0 {
		DumpSnap.Content.RLock()
		r := &pb.SearchResponse{}
		v := DumpSnap.domain[query]
		r.Results = make([]*pb.Content, len(v))
		i := 0
		for _, id := range v {
			r.Results[i] = DumpSnap.Content.C[id]
			i++
		}
		DumpSnap.Content.RUnlock()
		return r, nil
	} else {
		return &pb.SearchResponse{Error: "Data not ready"}, nil
	}
}
