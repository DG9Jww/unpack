package pcap

import (
	"encoding/binary"
	"encoding/hex"
	"log"
	"strings"
	"time"

	"golang.org/x/exp/mmap"
)

const (
	BE              = "A1B2C3D4" //大端
	LE              = "D4C3B2A1" //小端
	PCAPHEADER_SIZE = 24         //文件头大小为24B
    ChinaDateFormat = "2006-01-02 15:04:05.000000"
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

func (p *Packet) GetHeader() *PacketHeader {
    return p.packetHeader
}

func (p *Packet) GetData() []byte {
    return p.data
}

//pcap文件
type Pcap struct {
	pcapHeader  *PcapHeader
	packetsData []*Packet
	ByteOrder   binary.ByteOrder
}

func (p *Pcap) GetPacketsList() []*Packet {
    return p.packetsData
}

//获取大小端信息
func getByteOrder(order []byte) binary.ByteOrder {
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
func (p *Packet) GetPacketTime(order binary.ByteOrder) string {
    packetHeader := p.packetHeader

    unixTime := time.Unix(
        int64(order.Uint32(packetHeader.timeSec[:])),
        int64(order.Uint32(packetHeader.timeMicrosec[:])))
	return unixTime.Format(ChinaDateFormat)
}

//映射文件,返回整个文件数据
func MapFile(path string) []byte {
	//映射文件获取数据
	readerAt, err := mmap.Open(path)
    
	if err != nil {
		log.Fatalln("open file failed")
	}
	b := make([]byte, readerAt.Len())
	_, err = readerAt.ReadAt(b, 0)
	if err != nil {
		log.Fatalln("error:", err)
	}
    return b
}

//初始化数据,返回pcap
func InitData(b []byte) *Pcap {
	reader := NewByteReader(b)
	//先提取文件头数据
	header := &PcapHeader{}
	copy(header.magic[:], reader.Read(4))
	copy(header.major[:], reader.Read(2))
	copy(header.minor[:], reader.Read(2))
	copy(header.thisZone[:], reader.Read(4))
	copy(header.sigfigs[:], reader.Read(4))
	copy(header.snaplen[:], reader.Read(4))
	copy(header.linkType[:], reader.Read(4))
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
		copy(packetHeader.timeSec[:], reader.Read(4))
		copy(packetHeader.timeMicrosec[:], reader.Read(4))
		copy(packetHeader.capLen[:], reader.Read(4))
		copy(packetHeader.length[:], reader.Read(4))
		packet.packetHeader = packetHeader

		//按照字节序读取数据，得到数据包长度
		dataLen := byteOrder.Uint32(packetHeader.capLen[:])
		//copy(packet.data,reader.read(int(dataLen)))   //无效
		packet.data = reader.Read(int(dataLen))
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
func (reader *byteReader) Read(size int) []byte {
	end := reader.offSet + size
	d := reader.src[reader.offSet:end]
	reader.offSet = end
	return d
}

//判断是否到结尾
func (reader *byteReader) isEOF() bool {
	//由于偏移量从 0 开始算的，所以最后加1
	if reader.offSet+1 == len(reader.src) {
		return true
	}
	return false
}
