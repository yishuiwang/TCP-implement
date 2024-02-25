package transport

import (
	"log"
	"math/rand"
	"sync"
	"time"
)

type State int

// 服务器端的连接状态
const (
	Listen State = iota
	SynReceived
	Established
	CloseWait
	LastAck
	Closed
)

// 一条TCP连接
type Connection struct {
	SrcPort uint16
	DstPort uint16
	State   State
	Pkt     TcpPacket
	N       uintptr // 数据包长度

	initialSeqNum   uint32 // 初始序列号
	incrementSeqNum uint32 // 增量序列号

	isAccept bool // 是否接受连接
}

// TCP连接管理
type ConnectionManager struct {
	Connections           []Connection
	AcceptConnectionQueue chan Connection
	lock                  sync.Mutex
}

func NewConnectionManager() *ConnectionManager {
	return &ConnectionManager{
		Connections:           make([]Connection, 0),
		AcceptConnectionQueue: make(chan Connection, QUEUESIZE),
	}
}

// 服务器端接收到数据包处理
func (m *ConnectionManager) recv(queue *TcpPacketQueue, pkt TcpPacket) {
	// 查找是否有已经建立的连接
	conn, ok := m.find(pkt)
	if ok {
		conn.Pkt = pkt
	} else {
		// 如果连接不存在，则添加该连接
		conn = m.addConnection(pkt)
	}

	// 如果是建立连接的SYN包
	if pkt.TcpHeader.Flags.SYN && !ok {
		log.Printf("recv SYN packet, src port: %d, dst port: %d", pkt.TcpHeader.SrcPort, pkt.TcpHeader.DstPort)
		// 转为SYN_RECEIVED状态
		m.updateState(pkt, SynReceived, false)
		// 发送SYN+ACK包
		queue.Write(conn, HeaderFlags{SYN: true, ACK: true}, nil)
	}

	// 如果是建立连接的ACK包
	if ok && pkt.TcpHeader.Flags.ACK && conn.State == SynReceived {
		log.Printf("recv ACK packet, src port: %d, dst port: %d", pkt.TcpHeader.SrcPort, pkt.TcpHeader.DstPort)
		// 转为ESTABLISHED状态
		m.updateState(pkt, Established, false)
	}

	// 当发送端的应用程序发送了一个数据块（chunk）时，它会设置 PSH 标志位，这样接收端的应用程序就会尽快地从 TCP 缓冲区中读取数据。
	if ok && pkt.TcpHeader.Flags.PSH && conn.State == Established {
		log.Printf("recv PSH packet, src port: %d, dst port: %d", pkt.TcpHeader.SrcPort, pkt.TcpHeader.DstPort)
		// 将数据包放入接收队列
		m.updateState(pkt, Established, true)
		m.AcceptConnectionQueue <- conn
	}

	if ok && pkt.TcpHeader.Flags.FIN && conn.State == Established {
		log.Printf("recv FIN packet, src port: %d, dst port: %d", pkt.TcpHeader.SrcPort, pkt.TcpHeader.DstPort)
		// 转为CLOSE_WAIT状态
		m.updateState(pkt, CloseWait, false)
		// 发送ACK包
		queue.Write(conn, HeaderFlags{ACK: true}, nil)
		// 默认没有数据传送
		// 转为LAST_ACK状态
		m.updateState(pkt, LastAck, false)
		// 发送FIN+ACK包
		queue.Write(conn, HeaderFlags{
			FIN: true,
			ACK: true,
		}, nil)
	}

	if ok && pkt.TcpHeader.Flags.ACK && conn.State == LastAck {
		log.Printf("recv ACK packet, src port: %d, dst port: %d", pkt.TcpHeader.SrcPort, pkt.TcpHeader.DstPort)
		// 转为CLOSED状态
		m.updateState(pkt, Closed, false)
		// 关闭连接
		m.remove(conn)
	}
}

func (m *ConnectionManager) find(pkt TcpPacket) (Connection, bool) {
	m.lock.Lock()
	defer m.lock.Unlock()

	// 遍历所有连接，通过源端口和目的端口查找连接
	for _, conn := range m.Connections {
		if conn.SrcPort == pkt.TcpHeader.SrcPort && conn.DstPort == pkt.TcpHeader.DstPort {
			return conn, true
		}
	}

	return Connection{}, false
}

func (m *ConnectionManager) remove(conn Connection) {
	m.lock.Lock()
	defer m.lock.Unlock()

	for i, c := range m.Connections {
		if c.SrcPort == conn.SrcPort && c.DstPort == conn.DstPort {
			m.Connections = append(m.Connections[:i], m.Connections[i+1:]...)
			return
		}
	}
}

// 更新连接状态
func (m *ConnectionManager) updateState(pkt TcpPacket, state State, isAccept bool) {
	m.lock.Lock()
	defer m.lock.Unlock()

	for i, conn := range m.Connections {
		if conn.SrcPort == pkt.TcpHeader.SrcPort && conn.DstPort == pkt.TcpHeader.DstPort {
			m.Connections[i].State = state
			m.Connections[i].isAccept = isAccept
			return
		}
	}
}

// 添加新的连接
func (m *ConnectionManager) addConnection(pkt TcpPacket) Connection {
	m.lock.Lock()
	defer m.lock.Unlock()
	seed := time.Now().UnixNano()
	r := rand.New(rand.NewSource(seed))

	conn := Connection{
		SrcPort:         pkt.TcpHeader.DstPort,
		DstPort:         pkt.TcpHeader.SrcPort,
		State:           SynReceived,
		Pkt:             pkt,
		N:               pkt.Packet.N,
		initialSeqNum:   r.Uint32(), // 随机生成初始序列号
		incrementSeqNum: 0,
		isAccept:        false,
	}

	m.Connections = append(m.Connections, conn)

	return conn
}

func (m *ConnectionManager) updateSeqNum(pkt TcpPacket, incrementSeqNum uint32) {
	m.lock.Lock()
	defer m.lock.Unlock()

	for i, conn := range m.Connections {
		if conn.SrcPort == pkt.TcpHeader.SrcPort && conn.DstPort == pkt.TcpHeader.DstPort {
			m.Connections[i].incrementSeqNum += incrementSeqNum
			return
		}
	}
}
