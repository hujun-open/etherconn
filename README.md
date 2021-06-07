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
which also has performance gain, specially when using XDPRelay, which uses high performance AF_XDP socket.

Lastly etherconn.RUDPConn implements the net.PacketConn interface,
so it could be easily integrated into existing code;

Usage:

see [doc](https://pkg.go.dev/github.com/hujun-open/etherconn)

Limitations:

	* linux only
	* since etherconn bypassed linux IP stack, it is user's job to provide functions like:
	    * routing next-hop lookup
	    * IP -> MAC address resolution
	* no IP packet fragementation/reassembly support
	* using of etherconn requires root privileges
