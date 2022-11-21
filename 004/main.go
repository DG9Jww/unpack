package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"log"
	"strings"
	"time"

	"golang.org/x/exp/mmap"
)

const (
	BE              = "A1B2C3D4" //大端
	LE              = "D4C3B2A1" //小端
	PCAPHEADER_SIZE = 24         //文件头大小为24B
)

//文件头
type PcapHeader struct {
	magic    [4]byte
	major    [2]byte
	minor    [2]byte
	thisZone [4]byte
	sigfigs  [4]byte
	snaplen  [4]byte
	linkType [4]byte
}

//数据包头
type PacketHeader struct {
	timeSec      [4]byte
	timeMicrosec [4]byte
	capLen       [4]byte
	length       [4]byte
}

//数据包
type Packet struct {
	packetHeader *PacketHeader
	data         []byte
}

//pcap文件
type Pcap struct {
	pcapHeader  *PcapHeader
	packetsData []*Packet
    ByteOrder   binary.ByteOrder
}

//获取大小端信息
func getByteOrder(order []byte) binary.ByteOrder {
    fmt.Println(strings.ToUpper(hex.EncodeToString(order)))
    switch strings.ToUpper(hex.EncodeToString(order)) {
    case BE:
        return binary.BigEndian
    case LE:
        return binary.LittleEndian
    default:
        log.Fatal("Get file ByteOrder error")
        return nil
    }
}

//从数据包里提取时间信息
func (p *Packet) getPacketTime(order binary.ByteOrder) string {
    t := time.Unix(int64(order.Uint32(p.packetHeader.timeSec[:])),
              int64(order.Uint32(p.packetHeader.timeMicrosec[:])))
    return t.Local().String()
}


//初始化数据
func initData(b []byte) *Pcap {
	reader := NewByteReader(b)
	//先提取文件头数据
	header := &PcapHeader{}
	copy(header.magic[:], reader.read(4))
	copy(header.major[:], reader.read(2))
	copy(header.minor[:], reader.read(2))
	copy(header.thisZone[:], reader.read(4))
	copy(header.sigfigs[:], reader.read(4))
	copy(header.snaplen[:], reader.read(4))
	copy(header.linkType[:], reader.read(4))
	pcap := &Pcap{pcapHeader: header}

    //获取大小端
    byteOrder := getByteOrder(header.magic[:])
    pcap.ByteOrder = byteOrder

	//再提取数据包
	for {
        if reader.isEOF() {
            break
        }
		packet := &Packet{}
		packetHeader := &PacketHeader{}

        //提取数据包头
		copy(packetHeader.timeSec[:], reader.read(4))
		copy(packetHeader.timeMicrosec[:], reader.read(4))
		copy(packetHeader.capLen[:], reader.read(4))
		copy(packetHeader.length[:], reader.read(4))
        packet.packetHeader = packetHeader

        //按照字节序读取数据，得到数据包长度
        dataLen := byteOrder.Uint32(packetHeader.capLen[:]) 
        //copy(packet.data,reader.read(int(dataLen)))   //无效
        packet.data = reader.read(int(dataLen))
        pcap.packetsData = append(pcap.packetsData, packet)
	}
    return pcap
}

//byteReader 用于按字节读取数据
type byteReader struct {
	src    []byte //数据源
	offSet int    //偏移量
}

func NewByteReader(data []byte) *byteReader {
	return &byteReader{src: data, offSet: 0}
}

//按字节读取，读取完偏移量也跟着改变，返回读取数据
func (reader *byteReader) read(size int) []byte {
	end := reader.offSet + size
	d := reader.src[reader.offSet:end]
	reader.offSet = end
	return d
}

//判断是否到结尾
func (reader *byteReader) isEOF() bool {
    //由于偏移量从 0 开始算的，所以最后加1
    if reader.offSet + 1 == len(reader.src) {
        return true
    }
    return false
}

func main() {
	//映射文件获取数据
	readerAt, err := mmap.Open("test.pcap")
	if err != nil {
		log.Fatalln("open file failed")
	}
	b := make([]byte, readerAt.Len())
	_, err = readerAt.ReadAt(b, 0)
	if err != nil {
		log.Fatalln("error:", err)
	}
    pcap := initData(b)
    fmt.Printf("Total packets amount:%d\n",len(pcap.packetsData))
    for _,p := range pcap.packetsData {
        fmt.Printf("[%s] %d bytes\n",p.getPacketTime(pcap.ByteOrder),len(p.data))
    }
}

