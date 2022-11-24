package main

import "unpack/common/pcap"

func main() {
    //初始化
    data := pcap.MapFile("test.pcap")
    pcap := pcap.InitData(data)
    
    //此时数据已经全部保存到pcap里了，循环遍历数据包
    for _,packet := range pcap.GetPacketsList() {
        
    }
}

