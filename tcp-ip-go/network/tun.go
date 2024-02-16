package network

import (
	"context"
	"os"
)

// interface request 用于获取和设置网络接口相关的参数 eg: ip地址，mac地址，mtu等
type ifreq struct {
	ifrName  [16]byte
	ifrFlags int16
}

const (
	TUNSETIFF   = 0x400454ca // 设置tun/tap设备的名称
	IFF_TUN     = 0x0001     // tun设备
	IFF_NO_PI   = 0x1000     // 不包含包头 protocol information
	PACKET_SIZE = 2048       // 数据包大小
	QUEUE_SIZE  = 10         // 队列大小
)

type Packet struct {
	Buf []byte
	N   uintptr
}

type NetDevice struct {
	file          *os.File
	incomingQueue chan Packet
	outgoingQueue chan Packet
	ctx           context.Context
	cancel        context.CancelFunc
}

func NewTun() (*NetDevice, error) {
	return nil, nil

}
