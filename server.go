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
		DumpSnap.RLock()
		r := &pb.SearchResponse{}
		if v, ok := DumpSnap.Content[query]; ok {
			r.Results = make([]*pb.Content, 1)
			r.Results[0] = v.newPbContent("")
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
				if _a, ok := DumpSnap.subnet[nwstr]; ok {
					for _, id := range _a {
						_c := len(v1)
						v1 = v1.Add(id)
						if len(v1) != _c {
							vnw = append(vnw, nwstr)
						} else {
							for i, _id := range v1 {
								if _id == id {
									vnw[i] += "," + nwstr
								}
							}
						}
					}
				}
			}
		}
		a := DumpSnap.ip[query]
	Loop1:
		for _, v := range a {
			for _, id := range v1 {
				if v == id {
					continue Loop1
				}
				v2 = v2.Add(v)
			}
		}
		r.Results = make([]*pb.Content, len(v1)+len(v2))
		j := 0
		for i, id := range v1 {
			if v, ok := DumpSnap.Content[id]; ok {
				r.Results[j] = v.newPbContent(vnw[i])
				j++
			}
		}
		for _, id := range v2 {
			if v, ok := DumpSnap.Content[id]; ok {
				r.Results[j] = v.newPbContent("")
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
				r.Results[i] = v.newPbContent("")
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
				r.Results[i] = v.newPbContent("")
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
				r.Results[i] = v.newPbContent("")
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
	r := &pb.PingResponse{Pong: "I heed my lord"}
	return r, nil
}
