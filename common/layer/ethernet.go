package layer

import (
	"encoding/binary"
	"log"
	"unpack/common/pcap"
)

const (
	IPv4 = 0x0800
	ARP  = 0x0806 // Address Resulotion Protocol
	RARP = 0x0835 // Resever Address Resulotion Protoco
	IPv6 = 0x86DD // Internet Protocol Version 6
)

type EthernetPacket struct {
	DstAddr [6]byte //目标地址
	SrcAddr [6]byte //源地址
	Type    [2]byte //类型
}

func NewEthernetPacket() *EthernetPacket {
	return &EthernetPacket{}
}

//解析数据,传入的data应该为数据包实际数据
func (e *EthernetPacket) parse(data []byte) {
	reader := pcap.NewByteReader(data)
	copy(e.DstAddr[:], reader.Read(6))
	copy(e.SrcAddr[:], reader.Read(6))
	copy(e.Type[:], reader.Read(2))
}

//获取协议类型
func (e *EthernetPacket) getType() string {
	t := binary.BigEndian.Uint16(e.Type[:])
	switch t {
	case IPv4:
		return "IPv4"
	case ARP:
		return "ARP"
	case RARP:
		return "RARP"
	case IPv6:
		return "IPv6"
	default:
		log.Fatal("error type")
		return ""
	}
}
