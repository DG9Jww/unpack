package main

import (
	"fmt"
	"unpack/common/layer"
	"unpack/common/pcap"
)

func main() {
    //初始化
    data := pcap.MapFile("test.pcap")
    pcap := pcap.InitData(data)
    
    //此时数据已经全部保存到pcap里了，循环遍历数据包,打印任务信息
    for _,packet := range pcap.GetPacketsList() {
        data := packet.GetData() 
        p := layer.NewEthernetPacket()
        p.Parse(data)
        fmt.Printf("time:[%s]  %s\n",packet.GetPacketTime(pcap.ByteOrder),p)
    }
}

