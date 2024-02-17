package main

import (
	"fmt"
	"tcp/internet"
	"tcp/network"
)

func main() {
	network, _ := network.NewTun()
	network.Bind()
	ip := internet.NewIpPacketQueue()
	ip.ManageQueues(network)

	for {
		pkt, _ := ip.Read()
		fmt.Printf("IP Header: %+v\n", pkt.IpHeader)
	}
}
