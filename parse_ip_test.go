package main

import "testing"
import "net"
import "encoding/binary"

func ip2int(s string) uint32 {
        ip := net.ParseIP(s)
	if len(ip) == 16 {
		return binary.BigEndian.Uint32(ip[12:16])
	}
	return binary.BigEndian.Uint32(ip)
}

var ips []string = []string{"10.10.10.1", "192.168.1.1", "8.8.8.8"}

func Benchmark_ip2int(b *testing.B) {
        for i := 0; i < b.N; i++ {
                for _,ip := range ips {
                        ip2int(ip)
                }
        }
}

func Benchmark_parseIp4(b *testing.B) {
        for i := 0; i < b.N; i++ {
                for _,ip := range ips {
                        parseIp4(ip)
                }
        }
}
