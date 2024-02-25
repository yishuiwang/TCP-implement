package transport

import (
	"encoding/binary"
	"fmt"
	"tcp/internet"
)

const (
	LENGTH      = 20
	WINDOW_SIZE = 65535
	PROTOCOL    = 6 // TCP协议号
)

type Header struct {
	SrcPort  uint16
	DstPort  uint16
	SeqNum   uint32
	AckNum   uint32
	DataOffs uint8 // 数据偏移	TCP报文段的首部长度，以4字节为单位
	Reserved uint8 // 保留字段
	Flags    HeaderFlags
	Window   uint16
	Checksum uint16
	UrgPtr   uint16
}

type HeaderFlags struct {
	CWR bool // Congestion Window Reduced
	ECE bool // ECN-Echo
	URG bool // Urgent
	ACK bool // Acknowledgment
	PSH bool // Push	表示发送端 TCP 要求接收端尽快将数据推送给应用层，而不是等到缓冲区满或者等到超时再交付数据。
	RST bool // Reset
	SYN bool // Synchronize
	FIN bool // Finish
}

// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |          Source Port          |       Destination Port        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                        Sequence Number                        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    Acknowledgment Number                      |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  Data |       |C|E|U|A|P|R|S|F|                               |
// | Offset| Rsrvd |W|C|R|C|S|S|Y|I|            Window             |
// |       |       |R|E|G|K|H|T|N|N|                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |           Checksum            |         Urgent Pointer        |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                           [Options]                           |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                                                               :
// :                             Data                              :
// :                                                               |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

func unmarshal(pkt []byte) (*Header, error) {
	if len(pkt) < 20 {
		return nil, fmt.Errorf("invalid TCP header length: %d", len(pkt))
	}

	flags := unmarshalFlag(pkt[13])

	h := &Header{
		SrcPort:  binary.BigEndian.Uint16(pkt[0:2]),
		DstPort:  binary.BigEndian.Uint16(pkt[2:4]),
		SeqNum:   binary.BigEndian.Uint32(pkt[4:8]),
		AckNum:   binary.BigEndian.Uint32(pkt[8:12]),
		DataOffs: pkt[12] >> 4,
		Reserved: pkt[12] & 0x0E,
		Flags:    flags,
		Window:   binary.BigEndian.Uint16(pkt[14:16]),
		Checksum: binary.BigEndian.Uint16(pkt[16:18]),
		UrgPtr:   binary.BigEndian.Uint16(pkt[18:20]),
	}

	return h, nil

}

func unmarshalFlag(f uint8) HeaderFlags {
	return HeaderFlags{
		CWR: f&0x80 == 0x80, // 0x80 = 1000 0000
		ECE: f&0x40 == 0x40,
		URG: f&0x20 == 0x20,
		ACK: f&0x10 == 0x10,
		PSH: f&0x08 == 0x08,
		RST: f&0x04 == 0x04,
		SYN: f&0x02 == 0x02,
		FIN: f&0x01 == 0x01,
	}
}

func (h *Header) Marshal(ipHdr *internet.Header, data []byte) []byte {
	pkt := make([]byte, 20)
	binary.BigEndian.PutUint16(pkt[0:2], h.SrcPort)
	binary.BigEndian.PutUint16(pkt[2:4], h.DstPort)
	binary.BigEndian.PutUint32(pkt[4:8], h.SeqNum)
	binary.BigEndian.PutUint32(pkt[8:12], h.AckNum)
	pkt[12] = h.DataOffs
	pkt[13] = marshalFlag(h.Flags)
	binary.BigEndian.PutUint16(pkt[14:16], h.Window)
	binary.BigEndian.PutUint16(pkt[16:18], h.Checksum)
	binary.BigEndian.PutUint16(pkt[18:20], h.UrgPtr)

	h.setChecksum(ipHdr, append(pkt, data...))
	binary.BigEndian.PutUint16(pkt[16:18], h.Checksum)

	return pkt

}

// pseudo-header ipv4 96bit ipv6 320bit
// +--------+--------+--------+--------+
// |           Source Address          |
// +--------+--------+--------+--------+
// |         Destination Address       |
// +--------+--------+--------+--------+
// |  zero  |  PTCL  |    TCP Length   |
// +--------+--------+--------+--------+
func (h *Header) setChecksum(ipHeader *internet.Header, pkt []byte) {
	// 伪首部
	pseudoHeader := make([]byte, 12)
	copy(pseudoHeader[0:4], ipHeader.SrcIP[:])
	copy(pseudoHeader[4:8], ipHeader.DstIP[:])
	pseudoHeader[8] = 0
	pseudoHeader[9] = PROTOCOL
	binary.BigEndian.PutUint16(pseudoHeader[10:12], uint16(len(pkt)))

	buf := append(pseudoHeader, pkt...)
	if len(buf)%2 != 0 {
		// 如果buf的长度是奇数，则在buf的末尾添加一个0
		buf = append(buf, 0)
	}

	var checksum uint32
	for i := 0; i < len(buf); i += 2 {
		// 分为16位的字，逐个相加
		checksum += uint32(binary.BigEndian.Uint16(buf[i : i+2]))
	}

	// 如果有溢出，则将溢出部分加到低16位上
	for checksum > 0xffff {
		checksum = (checksum & 0xffff) + (checksum >> 16)
	}

	// 最后取反
	h.Checksum = ^uint16(checksum)
}

func marshalFlag(f HeaderFlags) uint8 {
	var flag uint8
	// 如果f.CWR为true，则设置对应的flag位为1，否则为0
	if f.CWR {
		flag |= 0x80
	}
	if f.ECE {
		flag |= 0x40
	}
	if f.URG {
		flag |= 0x20
	}
	if f.ACK {
		flag |= 0x10
	}
	if f.PSH {
		flag |= 0x08
	}
	if f.RST {
		flag |= 0x04
	}
	if f.SYN {
		flag |= 0x02
	}
	if f.FIN {
		flag |= 0x01
	}
	return flag
}

func NewHeader(srcPort, dstPort uint16, seqNum, ackNum uint32, flags HeaderFlags) *Header {
	return &Header{
		SrcPort: srcPort,
		DstPort: dstPort,
		SeqNum:  seqNum,
		AckNum:  ackNum,
		Flags:   flags,
		// TODO
		DataOffs: 5,
		Window:   WINDOW_SIZE,
	}
}
