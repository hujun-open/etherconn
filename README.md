# etherconn
[![CI](https://github.com/hujun-open/etherconn/actions/workflows/main.yml/badge.svg)](https://github.com/hujun-open/etherconn/actions/workflows/main.yml)
[![PkgGoDev](https://pkg.go.dev/badge/github.com/hujun-open/etherconn)](https://pkg.go.dev/github.com/hujun-open/etherconn)

Package etherconn is a golang pkg that allow user to send/receive Ethernet
payload (like IP pkt) or UDP packet ,with custom Ethernet encapsulation like
MAC address, VLAN tags, without creating corresponding interface in OS;

For example, with etherconn, a program could send/recive a UDP or IP packet
with a source MAC address and VLAN tags don't exists/provisioned in any of OS
interfaces;

Another benefit is since etherconn bypasses "normal" OS kernel routing and
IP stack, in scale setup like tens of thousands conns no longer subject to
kernel limitation like # of socket/fd limitations, UDP buffer size...etc;

Lastly etherconn.RUDPConn implements the net.PacketConn interface,
so it could be easily integrated into existing code;

etherconn supports following types of fowarding engines:

* RawSocketRelay: uses AF_PACKET socket, linux only
* XDPRelay: uses xdp socket, linux only
* RawSocketRelayPcap: uses libpcap, windows and linux


XDPRelay could achieve higher performance than RawSocketRelay, specially in multi-queue, multi-core enviroment.

## Performance
Tested in a KVM VM with 8 hyperthreading cores, and Intel 82599ES 10GE NIC, achieves 1Mpps with XDPRelay (1000B packet).

## What's New

1. add RawSocketRelayPcap, supports both windows and linux


## Dependencies 
etherconn require libpcap on linux, npcap on windows.

## Usage

	interface <---> PacketRelay <----> EtherConn <---> RUDPConn
	                            <----> EtherConn <---> RUDPConn
	                            <----> EtherConn <---> RUDPConn

1. Create a PacketRelay instance and bound to an interface.PacketRelay is the
"forward engine" that does actual packet sending/receiving for all EtherConn
instances registered with it; PacketRelay send/receive Ethernet packet;

2. Create one EtherConn for each source MAC+VLAN(s)+EtherType(s) combination needed,
and register with the PacketRelay instance. EtherConn send/receive Ethernet
payload like IP packet;

3. Create one RUDPConn instance for each UDP endpoint (IP+Port) needed, with a
EtherConn. RUDPConn send/receive UDP payload.

4. RUDPConn and EtherConn is 1:1 mapping, while EtherConn and PacketRelay is
N:1 mapping; since EtherConn and RUDPConn is 1:1 mapping, which means EtherConn
will forward all received UDP pkts to RUDPConn even when its IP/UDP port is
different from RUDPConn's endpoint, and RUDPConn could either only accept correct
pkt or accept any UDP packet;

Egress direction:

	UDP_payload -> RUDPConn(add UDP&IP header) -> EtherConn(add Ethernet header) -> PacketRelay

Ingress direction:

	Ethernet_pkt -> (BPFilter) PacketRelay (parse pkt) --- EtherPayload(e.g IP_pkt) --> EtherConn
	Ethernet_pkt -> (BPFilter) PacketRelay (parse pkt) --- UDP_payload --> RUDPConn (option to accept any UDP pkt)

Note: PacketRelay parse pkt for Ethernet payload based on following rules:
* PacketRelay has default BPFilter set to only allow IPv4/ARP/IPv6 packet
* If Ethernet pkt doesn't have VLAN tag, dstMAC + EtherType in Ethernet header is used to locate registered EtherConn
* else, dstMAC + VLANs +  EtherType in last VLAN tag is used

### SharedEtherConn and SharingRUDPConn
EtherConn and RUDPConn are 1:1 mapping,which means two RUDPConn can't share same MAC+VLAN+EtherType combination;

SharedEtherConn and SharingRUDPConn solve this issue:

	                                    L2Endpointkey-1
	interface <---> PacketRelay <----> SharedEtherConn <---> SharingRUDPConn (L4Recvkey-1)
	                                                   <---> SharingRUDPConn (L4Recvkey-2)
	                                                   <---> SharingRUDPConn (L4Recvkey-3)
	                                    L2Endpointkey-2
	                            <----> SharedEtherConn <---> SharingRUDPConn (L4Recvkey-4)
	                                                   <---> SharingRUDPConn (L4Recvkey-5)
	                                                   <---> SharingRUDPConn (L4Recvkey-6)


## Example:
```
	// This is an example of using RUDPConn, a DHCPv4 client
	// it also uses "github.com/insomniacslk/dhcp/dhcpv4/nclient4" for dhcpv4 client part

	// create PacketRelay for interface "enp0s10"
	relay, err := etherconn.NewRawSocketRelay(context.Background(), "enp0s10")
	if err != nil {
		log.Fatalf("failed to create PacketRelay,%v", err)
	}
	defer relay.Stop()
	mac, _ := net.ParseMAC("aa:bb:cc:11:22:33")
	vlanLlist := []*etherconn.VLAN{
		&etherconn.VLAN{
			ID:        100,
			EtherType: 0x8100,
		},
	}
	// create EtherConn, with src mac "aa:bb:cc:11:22:33" , VLAN 100 and DefaultEtherTypes,
	// with DOT1Q EtherType 0x8100, the mac/vlan doesn't need to be provisioned in OS
	econn := etherconn.NewEtherConn(mac, relay, etherconn.WithVLANs(vlanLlist))
	// create RUDPConn to use 0.0.0.0 and UDP port 68 as source, with option to accept any UDP packet
	// since DHCP server will send reply to assigned IP address
	rudpconn, err := etherconn.NewRUDPConn("0.0.0.0:68", econn, etherconn.WithAcceptAny(true))
	if err != nil {
		log.Fatalf("failed to create RUDPConn,%v", err)
	}
	// create DHCPv4 client with the RUDPConn
	clnt, err := nclient4.NewWithConn(rudpconn, mac, nclient4.WithDebugLogger())
	if err != nil {
		log.Fatalf("failed to create dhcpv4 client for %v", err)
	}
	// do DORA
	_, _, err = clnt.Request(context.Background())
	if err != nil {
		log.Fatalf("failed to finish DORA,%v", err)
	}
```

There is a more complicated example in [example](/example/) folder

## Limitations:

	* linux and windows only
	* since etherconn bypassed OS IP stack, it is user's job to provide functions like:
	    * routing next-hop lookup
	    * IP -> MAC address resolution
	* no IP packet fragementation/reassembly support
	* using of etherconn requires root privileges on linux

## Built-in XDP Kernel Program
etherconn includes a built-in XDP kernel program binary, its source is in [etherconnkern](https://github.com/hujun-open/etherconnkern)