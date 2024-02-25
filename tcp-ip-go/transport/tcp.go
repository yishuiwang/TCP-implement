package transport

import (
	"context"
	"fmt"
	"log"
	"tcp/internet"
	"tcp/network"
)

const (
	QUEUESIZE = 100
)

type TcpPacket struct {
	IpHeader  *internet.Header
	TcpHeader *Header
	Packet    network.Packet
}

// TCP数据包队列
type TcpPacketQueue struct {
	manager       *ConnectionManager
	outgoingQueue chan network.Packet
	ctx           context.Context
	cancel        context.CancelFunc
}

func NewTcpPacketQueue() *TcpPacketQueue {
	ConnectionManager := NewConnectionManager()
	context, cancel := context.WithCancel(context.Background())
	return &TcpPacketQueue{
		manager:       ConnectionManager,
		outgoingQueue: make(chan network.Packet, QUEUESIZE),
		ctx:           context,
		cancel:        cancel,
	}
}

func (tcp *TcpPacketQueue) ManageQueues(ip *internet.IpPacketQueue) {
	go func() {
		for {
			select {
			case <-tcp.ctx.Done():
				return
			default:
				ipPkt, err := ip.Read()
				if err != nil {
					fmt.Printf("read error: %s", err.Error())
				}
				tcpHeader, err := unmarshal(ipPkt.Packet.Buf[ipPkt.IpHeader.IHL*4 : ipPkt.Packet.N])
				if err != nil {
					fmt.Printf("unmarshal error: %s", err)
					continue
				}
				tcpPkt := TcpPacket{
					IpHeader:  ipPkt.IpHeader,
					TcpHeader: tcpHeader,
					Packet:    ipPkt.Packet,
				}
				tcp.manager.recv(tcp, tcpPkt)
			}
		}
	}()

	go func() {
		for {
			select {
			case <-tcp.ctx.Done():
				return
			default:
				pkt := <-tcp.outgoingQueue
				err := ip.Write(pkt)
				if err != nil {
					log.Printf("write error: %s", err.Error())
				}
			}
		}
	}()
}

func (tcp *TcpPacketQueue) Close() {
	tcp.cancel()
}

// 向接收队列中添加数据包
func (tcp *TcpPacketQueue) Write(conn Connection, flgs HeaderFlags, data []byte) {
	pkt := conn.Pkt
	// tcp有效数据长度为：数据包总长度 - tcp头部长度 - ip头部长度
	tcpDataLen := int(pkt.Packet.N) - int(pkt.TcpHeader.DataOffs)*4 - int(pkt.IpHeader.IHL)*4

	var incrementAckNum uint32
	if tcpDataLen == 0 {
		incrementAckNum = 1
	} else {
		incrementAckNum = uint32(len(data))
	}

	// 期待的下一个序列号
	ackNum := pkt.TcpHeader.SeqNum + incrementAckNum
	// data的第一个序列号
	seqNum := conn.initialSeqNum + conn.incrementSeqNum

	writeIphdr := internet.NewHeader(pkt.IpHeader.DstIP, pkt.IpHeader.SrcIP, len(data)+LENGTH)
	writeTcphdr := NewHeader(pkt.TcpHeader.DstPort, pkt.TcpHeader.SrcPort, seqNum, ackNum, flgs)

	ipHdr := writeIphdr.Marshal()
	tcpHdr := writeTcphdr.Marshal(conn.Pkt.IpHeader, data)

	writePkt := append(ipHdr, tcpHdr...)
	writePkt = append(writePkt, data...)

	var incrementSeqNum uint32
	// 如果SYN或FIN，则消耗一个序列号
	if flgs.SYN || flgs.FIN {
		incrementSeqNum += 1
	}
	incrementSeqNum += uint32(len(data))
	tcp.manager.updateSeqNum(pkt, incrementSeqNum)

	// 将数据包放入发送队列
	tcp.outgoingQueue <- network.Packet{
		Buf: writePkt,
		N:   uintptr(len(writePkt)),
	}
}

func (tcp *TcpPacketQueue) ReadAcceptConnection() (Connection, error) {
	pkt, ok := <-tcp.manager.AcceptConnectionQueue
	if !ok {
		return Connection{}, fmt.Errorf("connection queue is closed")
	}

	return pkt, nil
}
