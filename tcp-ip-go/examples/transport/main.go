package main

import (
	"fmt"
	"tcp/internet"
	"tcp/network"
	"tcp/transport"
)

func main() {
	network, _ := network.NewTun()
	network.Bind()
	ip := internet.NewIpPacketQueue()
	ip.ManageQueues(network)
	tcp := transport.NewTcpPacketQueue()
	tcp.ManageQueues(ip)

	for {
		pkt, _ := tcp.ReadAcceptConnection()
		fmt.Printf("TCP Header: %+v\n", pkt.Pkt.TcpHeader)
	}
}
