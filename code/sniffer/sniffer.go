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
	/* provide interface name & subnet mask */
	iface, err := selectInterface()
	if err != nil {
		log.Fatal(err)
	}
	dev  := iface.Name
	/* nmsk := iface.Addresses[0].Netmask */

	/* 
	** Open provided device for sniffing (open session vaya)
	** func OpenLive(device string, snaplen int32, promisc bool, timeout time.Duration) (handle *Handle, _ error) 
	**		device:  device for which pcap will listen
	** 		snaplen: max. size to read for packet
	**		promisc: set promiscuous mode on/off
	**		timeout: tal
	*/
	handle, err := pcap.OpenLive(dev, 1024, false, pcap.BlockForever)
	if err != nil {
		fmt.Println(err)
		/* return err */
	}
	defer handle.Close()
	/*
	** Filter traffic: compile and apply (netmask needed)
	** func (p *Handle) CompileBPFFilter(expr string) ([]BPFInstruction, error)
	** 		expr:   BPF filter expresion (man 7 pcap-filter)
	**		return: Compiled BPF instruction
	*/
	BPFins, err := handle.CompileBPFFilter("tcp and port 80")
	if err != nil {
		fmt.Println(err)
		/* return err */
	}

	/* 
	** Set filter: set compiled filter to handler
	** func (p *Handle) SetBPFInstructionFilter(bpfInstructions []BPFInstruction) (err error)
	**		bpfInstruction: BPF filter in asm byte fmt. (from Compile func. or tcpdump -dd 'str)
	*/
	err = handle.SetBPFInstructionFilter(BPFins)
	if err != nil {
		fmt.Println(err)
	}

	/*
	** Pcap_loop eq.
	** func NewPacketSource(source PacketDataSource, decoder Decoder) *PacketSource
	** 		source:  handle (PacketDataSource implements ReadPacketData)
	**		decoder: handle.LinkType() -> returns pcap_datalink(), or link layer header typ
	*/
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {

		parseCapturedPacket(packet)
	}
}