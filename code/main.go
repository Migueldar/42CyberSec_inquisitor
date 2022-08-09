package main

import (
	"log"
	//"net"
	"syscall"
	//"golang.org/x/net/ipv4"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket"
	"fmt"
)

func main() {
	var err error
	fd, _ := syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	addr := syscall.SockaddrInet4{
		Port: 60002,
		Addr: [4]byte{172, 18, 0, 2},
	}
	p := pkt()
	fmt.Println(p)
	err = syscall.Sendto(fd, p, 0, &addr)
	if err != nil {
		log.Fatal("Sendto:", err)
	}
}

func pkt() []byte {
	eth := layers.Ethernet {
		DstMAC:       []byte{0x02, 0x42, 0xac, 0x12, 0x00, 0x02,},
		SrcMAC:       []byte{0x02, 0x42, 0xac, 0x12, 0x00, 0x03,},
		EthernetType: layers.EthernetTypeARP,
	}
	arp := layers.ARP {
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     6,
		ProtAddressSize:   4,
		Operation:         layers.ARPRequest,
		SourceHwAddress:   []byte{0x02, 0x42, 0xac, 0x12, 0x00, 0x03,},
		SourceProtAddress: []byte{172, 18, 0, 3},
		DstHwAddress:      []byte{0x02, 0x42, 0xac, 0x12, 0x00, 0x02,},
		DstProtAddress:    []byte{172, 18, 0, 2},
	}
	buf := gopacket.NewSerializeBuffer()
	opts := gopacket.SerializeOptions{
		// FixLengths:       true,
		// ComputeChecksums: true,
	}
	gopacket.SerializeLayers(buf, opts, &eth, &arp)
	return buf.Bytes()
}

// func pkt() []byte {
// 	pack := []byte{
// 		0x02, //target MAC
// 		0x42,
// 		0xac,
// 		0x12,
// 		0x00,
// 		0x02,
// 		0x02, //source MAC
// 		0x42,
// 		0xac,
// 		0x12,
// 		0x00,
// 		0x03,
// 		0x08, //type (arp)
// 		0x06,
// 		0x00, //ethernet
// 		0x01,
// 		0x08, //IP type
// 		0x00,
// 		0x06, //mac len
// 		0x04, //IP len
// 		0x00, //operation(response)
// 		0x02,
// 		0x02, //source MAC
// 		0x42,
// 		0xac,
// 		0x12,
// 		0x00,
// 		0x03,
// 		172,  //source IP
// 		18,
// 		0,
// 		3,
// 		0x02, //target MAC
// 		0x42,
// 		0xac,
// 		0x12,
// 		0x00,
// 		0x02,
// 		172,  //target IP
// 		18,
// 		0,
// 		2,
// 		0,
// 		0,
// 		0,
// 		0,
// 		0,
// 		0,
// 		0,
// 		0,
// 		0,
// 		0,
// 		0,
// 		0,
// 		0,
// 		0,
// 		0,
// 		0,
// 		0,
// 		0,
// 	}
// return pack
// }
