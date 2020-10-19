# etherconn
[![Build Status](https://travis-ci.org/hujun-open/etherconn.svg?branch=master)](https://travis-ci.org/hujun-open/etherconn)
[![PkgGoDev](https://pkg.go.dev/badge/github.com/hujun-open/etherconn)](https://pkg.go.dev/github.com/hujun-open/etherconn)

Package etherconn is a golang pkg that allow user to send/receive Ethernet
payload (like IP pkt) or UDP packet ,with custom Ethernet encapsulation like
MAC address, VLAN tags, without creating corresponding interface in OS;

For example, with etherconn, a program could send/recive a UDP or IP packet
with a source MAC address and VLAN tags don't exists/provisioned in any of OS
interfaces;

Another benefit is since etherconn bypasses "normal" Linux kernel routing and
IP stack, in scale setup like tens of thousands conns no longer subject to
linux kernel limitation like # of socket/fd limitations, UDP buffer size...etc;

Lastly etherconn.RUDPConn implements the net.PacketConn interface,
so it could be easily integrated into existing code;

## Usage:

	interface <---> PacketRelay <----> EtherConn <---> RUDPConn
	                            <----> EtherConn <---> RUDPConn
	                            <----> EtherConn <---> RUDPConn


1. Create a PacketRelay instance and bound to an interface.PacketRelay is the
"forward engine" that does actual packet sending/receiving for all EtherConn
instances registered with it; PacketRelay send/receive Ethernet packet

2. Create one EtherConn for each source MAC+VLAN(s) combination needed,
and register with the PacketRelay instance. EtherConn send/receive Ethernet
payload like IP packet;

3. Create one RUDPConn instance for each UDP endpoint (IP+Port) needed, with a
EtherConn. RUDPConn send/receive UDP payload.

4. RUDPConn and EtherConn is 1:1 mapping, while EtherConn and PacketRelay is
N:1 mapping; since EtherConn and RUDPConn is 1:1 mapping, which means EtherConn
will forward all received UDP pkts to RUDPConn even when its IP/UDP port is
different from RUDPConn's endpoint, and RUDPConn could either only accept correct
pkt or accept any UDP packet;


## Egress direction:

	UDP_payload -> RUDPConn(add UDP&IP header) -> EtherConn(add Ethernet header) -> PacketRelay

## Ingress direction:

	Ethernet_pkt -> PacketRelay (parse pkt) --- EtherPayload(e.g IP_pkt) --> EtherConn
	Ethernet_pkt -> PacketRelay (parse pkt) --- UDP_payload --> RUDPConn (option to accept any UDP pkt)

Note: PacketRelay parse pkt for Ethernet payload based on following rules:

* PacketRelay has list of EtherTypes, by default are  0x0800 (IPv4) and 0x86dd (IPv6)
* If Ethernet pkt doesn't have VLAN tag, EtherType in Ethernet header is used to see if the pkt contains the interested payload
* else, EtherType in last VLAN tag is used 

## Limitations:

* linux only
* since etherconn bypassed linux IP routing stack, it is user's job to provide functions like:
    * routing next-hop lookup
    * IP -> MAC address resolution
* no IP packet fragementation/reassembly support
* using of etherconn requires to put interface in promiscuous mode, which requires root privileges
