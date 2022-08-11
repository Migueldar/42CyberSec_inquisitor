package main
/* package sniffer */

import (
	"fmt"
	"log"
	"errors"
	"github.com/google/gopacket"
    "github.com/google/gopacket/pcap"
)

/* 
** Loops through array of available interfaces on host,
** then chooses first one that is not loopback (lo0)
*/ 
func selectInterface() (pcap.Interface, error) {
	ifaces, err := pcap.FindAllDevs()
	if err != nil {
		return pcap.Interface{}, err
	}
	for _, iface := range ifaces {
		if iface.Name != "lo0" && iface.Name != "lo" {
			return iface, nil
		}
	}
	return pcap.Interface{}, errors.New("could not find valid network interface")
}

func main() /*Sniffer*/ {
	iface, err := selectInterface()
	if err != nil {
		log.Fatal(err)
	}
	dev  := iface.Name
	/* nmsk := iface.Addresses[0].Netmask */
	handle, err := pcap.OpenLive(dev, 1024, false, pcap.BlockForever)
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()
	BPFins, err := handle.CompileBPFFilter("tcp port 21 and 22") /* falta testear este filtro */
	if err != nil {
		log.Fatal(err)
	}
	err = handle.SetBPFInstructionFilter(BPFins)
	if err != nil {
		fmt.Println(err)
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {
		fmt.Println(packet.String())
	}
}