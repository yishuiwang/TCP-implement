package internet

import (
	"encoding/binary"
	"fmt"
)

const (
	IP_VERSION_4         = 4       // IP协议版本
	IHL                  = 5       // Internet Header Length
	TOS                  = 0       // 服务类型
	TTL                  = 64      // 生存时间
	LENGTH               = IHL * 4 // IP头部长度
	TCP_PROTOCOL         = 6       // TCP协议
	IP_HEADER_MIN_LENGTH = 20      // IP头部最小长度
)

type Header struct {
	Version        uint8
	IHL            uint8 // 头部长度
	TOS            uint8
	TotalLength    uint16 // IP 标头和负载的总长度
	ID             uint16 // 标识
	Flags          uint8  // 标志位 是否分片
	FragmentOffset uint16 // 分片偏移
	TTL            uint8
	Protocol       uint8
	Checksum       uint16 // 校验和
	SrcIP          [4]byte
	DstIP          [4]byte
}

func NewHeader(srcIP, dstIP [4]byte, len int) *Header {
	return &Header{
		Version:     IP_VERSION_4,
		IHL:         IHL,
		TOS:         TOS,
		TotalLength: uint16(LENGTH + len),
		TTL:         TTL,
		Protocol:    TCP_PROTOCOL,
		SrcIP:       srcIP,
		DstIP:       dstIP,
		ID:          0,
		Flags:       0x40,
		Checksum:    0,
	}
}

// 0                   1                   2                   3
// 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |Version|  IHL  |Type of Service|         Total Length          |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |         Identification        |Flags|   Fragment Offset       |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |  Time to Live |    Protocol   |       Header Checksum         |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                        Source Address                         |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                     Destination Address                       |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
// |                    (Options)                    |  (Padding)  |
// +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

func unmarshal(pkt []byte) (*Header, error) {
	// IP头部最小长度为20字节
	if len(pkt) < IP_HEADER_MIN_LENGTH {
		return nil, fmt.Errorf("invalid ip header length")
	}

	header := &Header{
		Version:        pkt[0] >> 4,   // 第一个字节的高4位
		IHL:            pkt[0] & 0x0f, // 第一个字节的低4位
		TOS:            pkt[1],
		TotalLength:    binary.BigEndian.Uint16(pkt[2:4]), // 2字节 按照大端序解析
		ID:             binary.BigEndian.Uint16(pkt[4:6]), // 2字节
		Flags:          pkt[6] >> 5,
		FragmentOffset: binary.BigEndian.Uint16(pkt[6:8]) & 0x1fff,
		TTL:            pkt[8],
		Protocol:       pkt[9],
		Checksum:       binary.BigEndian.Uint16(pkt[10:12]),
	}

	copy(header.SrcIP[:], pkt[12:16])
	copy(header.DstIP[:], pkt[16:20])

	return header, nil
}

func (h *Header) Marshal() []byte {
	versionAndIHL := (h.Version << 4) | h.IHL // 高4位为版本号，低4位为头部长度
	flagsAndFragmentOffset := (uint16(h.Flags) << 13) | h.FragmentOffset

	pkt := make([]byte, h.IHL*4)
	pkt[0] = byte(versionAndIHL)
	pkt[1] = byte(h.TOS)
	binary.BigEndian.PutUint16(pkt[2:4], h.TotalLength) // 将h.TotalLength的值以大端序写入到pkt字节切片的指定位置。
	binary.BigEndian.PutUint16(pkt[4:6], h.ID)
	binary.BigEndian.PutUint16(pkt[6:8], flagsAndFragmentOffset)
	pkt[8] = byte(h.TTL)
	pkt[9] = byte(h.Protocol)
	binary.BigEndian.PutUint16(pkt[10:12], h.Checksum)
	copy(pkt[12:16], h.SrcIP[:])
	copy(pkt[16:20], h.DstIP[:])

	h.setChecksum(pkt)
	binary.BigEndian.PutUint16(pkt[10:12], h.Checksum)

	return pkt
}

func (h *Header) setChecksum(pkt []byte) {
	length := len(pkt)
	var checksum uint32

	// 1. 将数据包的每 2 个字节加在一起作为 16 位整数
	for i := 0; i < length; i += 2 {
		checksum += uint32(binary.BigEndian.Uint16(pkt[i : i+2]))
	}

	// 2. 如果总数超过16位，则将高16位和低16位相加
	for checksum > 0xffff {
		checksum = (checksum & 0xffff) + (checksum >> 16)
	}

	// 3. 取反
	h.Checksum = ^uint16(checksum)
}
