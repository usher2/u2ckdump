package main

//go:generate protoc -I msg --go-grpc_out=msg --go_out=msg --go_opt=paths=source_relative --go-grpc_opt=paths=source_relative msg/msg.proto

import (
	"context"
	"net"

	pb "github.com/usher2/u2ckdump/msg"
)

// server - our grpc server.
type server struct {
	pb.UnimplementedCheckServer
}

// SearchDecision - search by decision number.
func (s *server) SearchDecision(ctx context.Context, in *pb.DecisionRequest) (*pb.SearchResponse, error) {
	query := in.GetQuery()

	Debug.Printf("Received decision: %d\n", query)

	// TODO: Change to DunpSnap search method.
	if DumpSnap != nil && DumpSnap.utime > 0 {
		DumpSnap.RLock()

		r := &pb.SearchResponse{RegistryUpdateTime: DumpSnap.utime}
		a := DumpSnap.decision[query]
		r.Results = make([]*pb.Content, 0, len(a))

		for _, id := range a {
			if v, ok := DumpSnap.Content[id]; ok {
				r.Results = append(r.Results, v.newPbContent(0, nil, "", "", ""))
			}
		}

		DumpSnap.RUnlock()

		return r, nil
	}

	return &pb.SearchResponse{Error: SrvDataNotReady}, nil
}

// SearchID - search by content ID.
func (s *server) SearchID(ctx context.Context, in *pb.IDRequest) (*pb.SearchResponse, error) {
	query := in.GetQuery()

	Debug.Printf("Received content ID: %d\n", query)

	// TODO: Change to DunpSnap search method.
	if DumpSnap != nil && DumpSnap.utime > 0 {
		DumpSnap.RLock()

		r := &pb.SearchResponse{RegistryUpdateTime: DumpSnap.utime}

		if v, ok := DumpSnap.Content[query]; ok {
			r.Results = append(r.Results, v.newPbContent(0, nil, "", "", ""))
		}

		DumpSnap.RUnlock()

		return r, nil
	}

	return &pb.SearchResponse{Error: SrvDataNotReady}, nil
}

// SearchID - search by IPv4.
func (s *server) SearchIP4(c context.Context, in *pb.IP4Request) (*pb.SearchResponse, error) {
	query := in.GetQuery()
	ipb := net.IP{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff,
		byte((query & 0xFF000000) >> 24),
		byte((query & 0x00FF0000) >> 16),
		byte((query & 0x0000FF00) >> 8),
		byte(query & 0x000000FF),
	}

	Debug.Printf("Received IPv4: %s\n", ipb)

	var v1, v2 ArrayIntSet
	var vnw []string

	// TODO: Change to DunpSnap search method.
	if DumpSnap != nil && DumpSnap.utime > 0 {
		DumpSnap.RLock()

		r := &pb.SearchResponse{RegistryUpdateTime: DumpSnap.utime}

		// TODO: Change to DumpSnap search method
		cnw, err := DumpSnap.net.ContainingNetworks(ipb)
		if err != nil {
			Debug.Printf("Can't get containing networks: %s: %s\n", ipb, err)
		} else {
			for _, entry := range cnw {
				nw := entry.Network()
				nwstr := nw.String()

				if a, ok := DumpSnap.subnet[nwstr]; ok {
					v1 = append(v1, a...)

					for range a {
						vnw = append(vnw, nwstr)
					}
				}
			}
		}

		if a, ok := DumpSnap.ip[query]; ok {
			v2 = append(v2, a...)
		}

		r.Results = make([]*pb.Content, 0, len(v1)+len(v2))

		for i, id := range v1 {
			if v, ok := DumpSnap.Content[id]; ok {
				r.Results = append(r.Results, v.newPbContent(0, nil, "", "", vnw[i]))
			}
		}

		for _, id := range v2 {
			if v, ok := DumpSnap.Content[id]; ok {
				r.Results = append(r.Results, v.newPbContent(query, nil, "", "", ""))
			}
		}

		DumpSnap.RUnlock()

		return r, nil
	}

	return &pb.SearchResponse{Error: SrvDataNotReady}, nil
}

// SearchID - search by IPv6.
func (s *server) SearchIP6(ctx context.Context, in *pb.IP6Request) (*pb.SearchResponse, error) {
	query := in.GetQuery()

	Debug.Printf("Received IPv6: %v\n", query)

	// TODO: Change to DunpSnap search method.
	if DumpSnap != nil && DumpSnap.utime > 0 {
		DumpSnap.RLock()

		r := &pb.SearchResponse{RegistryUpdateTime: DumpSnap.utime}
		a := DumpSnap.ip6[string(query)]
		r.Results = make([]*pb.Content, 0, len(a))

		for _, id := range a {
			if v, ok := DumpSnap.Content[id]; ok {
				r.Results = append(r.Results, v.newPbContent(0, query, "", "", ""))
			}
		}

		DumpSnap.RUnlock()

		return r, nil
	}

	return &pb.SearchResponse{Error: SrvDataNotReady}, nil
}

// SearchID - search by URL.
func (s *server) SearchURL(ctx context.Context, in *pb.URLRequest) (*pb.SearchResponse, error) {
	query := in.GetQuery()

	Debug.Printf("Received URL: %v\n", query)

	// TODO: Change to DunpSnap search method.
	if DumpSnap != nil && DumpSnap.utime > 0 {
		DumpSnap.RLock()

		r := &pb.SearchResponse{RegistryUpdateTime: DumpSnap.utime}
		a := DumpSnap.url[query]
		r.Results = make([]*pb.Content, 0, len(a))

		for _, id := range a {
			if v, ok := DumpSnap.Content[id]; ok {
				r.Results = append(r.Results, v.newPbContent(0, nil, "", query, ""))
			}
		}

		DumpSnap.RUnlock()

		return r, nil
	}

	return &pb.SearchResponse{Error: SrvDataNotReady}, nil
}

// SearchID - search by domain.
func (s *server) SearchDomain(ctx context.Context, in *pb.DomainRequest) (*pb.SearchResponse, error) {
	query := in.GetQuery()

	Debug.Printf("Received Domain: %v\n", query)

	// TODO: Change to DunpSnap search method.
	if DumpSnap != nil && DumpSnap.utime > 0 {
		DumpSnap.RLock()

		r := &pb.SearchResponse{RegistryUpdateTime: DumpSnap.utime}
		a := DumpSnap.domain[query]
		r.Results = make([]*pb.Content, 0, len(a))

		for _, id := range a {
			if v, ok := DumpSnap.Content[id]; ok {
				r.Results = append(r.Results, v.newPbContent(0, nil, query, "", ""))
			}
		}

		DumpSnap.RUnlock()

		return r, nil
	}

	return &pb.SearchResponse{Error: SrvDataNotReady}, nil
}

// Ping - just ping.
func (s *server) Ping(ctx context.Context, in *pb.PingRequest) (*pb.PongResponse, error) {
	ping := in.GetPing()

	Debug.Printf("Received Ping: %v\n", ping)

	// TODO: Change to DunpSnap search method.
	if DumpSnap != nil && DumpSnap.utime > 0 {
		DumpSnap.RLock()

		r := &pb.PongResponse{Pong: SrvPongMessage, RegistryUpdateTime: DumpSnap.utime}

		DumpSnap.RUnlock()

		return r, nil
	}

	return &pb.PongResponse{Error: SrvDataNotReady}, nil
}
