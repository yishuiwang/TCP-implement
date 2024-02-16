package network

import (
	"context"
	"fmt"
	"log"
	"os"
	"syscall"
	"unsafe"
)

// interface request 用于获取和设置网络接口相关的参数 eg: ip地址，mac地址，mtu等
type ifreq struct {
	ifrName  [16]byte
	ifrFlags int16
}

const (
	TUNSETIFF   = 0x400454ca // 设置tun/tap设备的名称
	IFF_TUN     = 0x0001     // 表示tun设备
	IFF_NO_PI   = 0x1000     // 表示不包含包头 protocol information
	PACKET_SIZE = 2048       // 数据包大小
	QUEUE_SIZE  = 10         // 队列大小
)

type Packet struct {
	Buf []byte
	N   uintptr
}

type NetDevice struct {
	file          *os.File    // 文件描述符
	incomingQueue chan Packet // 接收网络数据包
	outgoingQueue chan Packet // 发送网络数据包
	ctx           context.Context
	cancel        context.CancelFunc //上下文相关的操作将被取消
}

func NewTun() (*NetDevice, error) {
	// 打开TUN设备
	file, err := os.OpenFile("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}

	ifr := ifreq{}
	copy(ifr.ifrName[:], []byte("tun0"))
	// 将这两个标志进行按位或操作,可以将它们合并到一个字段中
	ifr.ifrFlags = IFF_TUN | IFF_NO_PI
	// ioctl()是一个用于设备、套接字和其他文件描述符的I/O控制操作的系统调用
	_, _, sysErr := syscall.Syscall(syscall.SYS_IOCTL, file.Fd(), uintptr(TUNSETIFF), uintptr(unsafe.Pointer(&ifr)))
	if sysErr != 0 {
		return nil, sysErr
	}

	ctx, cancel := context.WithCancel(context.Background())

	return &NetDevice{
		file:          file,
		incomingQueue: make(chan Packet, QUEUE_SIZE),
		outgoingQueue: make(chan Packet, QUEUE_SIZE),
		ctx:           ctx,
		cancel:        cancel,
	}, nil
}

// 向TUN设备发送数据包
func (t *NetDevice) read(buf []byte) (uintptr, error) {
	// Read系统调用，从文件描述符fd指向的文件中读取字节到buf中
	n, _, sysErr := syscall.Syscall(syscall.SYS_READ, t.file.Fd(), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if sysErr != 0 {
		return n, sysErr
	}
	return n, nil
}

// 从TUN设备接收数据包
func (t *NetDevice) write(buf []byte) (uintptr, error) {
	// Write系统调用，将buf中的字节写入文件描述符fd指向的文件
	n, _, sysErr := syscall.Syscall(syscall.SYS_WRITE, t.file.Fd(), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)))
	if sysErr != 0 {
		return n, sysErr
	}
	return n, nil
}

// Bind 函数启动两个goroutine，一个用于接收数据包，一个用于发送数据包
func (tun *NetDevice) Bind() {
	// tun.ctx, tun.cancel = context.WithCancel(context.Background())
	go func() {
		for {
			select {
			case <-tun.ctx.Done():
				log.Println("tun is closed")
				return
			default:
				buf := make([]byte, PACKET_SIZE)
				n, err := tun.read(buf)
				if err != nil {
					log.Println("read from tun error:", err)
				}
				Packet := Packet{
					Buf: buf,
					N:   n,
				}
				tun.incomingQueue <- Packet
			}
		}
	}()

	go func() {
		for {
			select {
			case <-tun.ctx.Done():
				log.Println("tun is closed")
				return
			case pkt := <-tun.outgoingQueue:
				_, err := tun.write(pkt.Buf[:pkt.N])
				if err != nil {
					log.Println("write to tun error:", err)
				}
			}
		}
	}()
}

// Read 从tun.incomingQueue中读取数据包
func (t *NetDevice) Read() (Packet, error) {
	pkt, ok := <-t.incomingQueue
	if !ok {
		return Packet{}, fmt.Errorf("incoming queue is closed")
	}
	return pkt, nil
}

// Write 将数据包写入tun.outgoingQueue
func (t *NetDevice) Write(pkt Packet) error {
	select {
	case t.outgoingQueue <- pkt:
		return nil
	case <-t.ctx.Done():
		return fmt.Errorf("device closed")
	}
}
