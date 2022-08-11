package main
/* package sniffer */

import (
	"github.com/google/gopacket"
	"fmt"
)

func parseCapturedPacket(packet gopacket.Packet) {
	fmt.Println(packet.String())
}