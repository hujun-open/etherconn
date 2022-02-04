// Copyright 2021 Hu Jun. All rights reserved.
// This project is licensed under the terms of the MIT license.

/*Package etherconn is a golang pkg that allow user to send/receive Ethernet
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

Usage:

	interface <---> PacketRelay <----> EtherConn <---> RUDPConn
	                            <----> EtherConn <---> RUDPConn
	                            <----> EtherConn <---> RUDPConn


1. Create a PacketRelay instance and bound to an interface.PacketRelay is the
"forward engine" that does actual packet sending/receiving for all EtherConn
instances registered with it; PacketRelay send/receive Ethernet packet;
PacketRelay is a GO interface, currently there are two implementations:

	- RawSocketRelay: uses AF_PACKET socket
	- XDPRelay: uses AF_XDP socket

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

Limitations:
	 * linux only
	 * since etherconn bypassed linux IP stack, it is user's job to provide functions like:
	    * routing next-hop lookup
	    * IP -> MAC address resolution
	* no IP packet fragementation/reassembly support
	* using of etherconn requires root privileges

Example:

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



*/
package etherconn

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

const (
	// DefaultSendChanDepth is the default value for PacketRelay send channel depth, e.g. send buffer
	DefaultSendChanDepth = 1024
	// DefaultPerClntRecvChanDepth is the defaul value for per registered client(EtherConn)'s receive channel depth. e.g. recv buffer
	DefaultPerClntRecvChanDepth = 1024
	// DefaultMaxEtherFrameSize is the deafult max size of Ethernet frame that PacketRelay could receive from the interface
	DefaultMaxEtherFrameSize = 2048
	// DefaultRelayRecvTimeout is the default value for PacketReceive receiving timeout
	DefaultRelayRecvTimeout = time.Second
	DefaultTTL              = 255
)

var (
	// ErrTimeOut is the error returned when opeartion timeout
	ErrTimeOut = fmt.Errorf("timeout")
	// ErrRelayStopped is the error returned when relay already stopped
	ErrRelayStopped = fmt.Errorf("relay stopped")
	// BroadCastMAC is the broadcast MAC address
	BroadCastMAC = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
)

const (
	// NOVLANTAG is the value to represents NO vlan tag in L2EndpointKey
	NOVLANTAG = 0xffff
)

// VLAN reprents a VLAN tag
type VLAN struct {
	ID        uint16
	EtherType uint16
}

// VLANs is a slice of VLAN
type VLANs []*VLAN

//String return a string representation
func (vlans VLANs) String() string {
	s := ""
	for _, v := range vlans {
		s += fmt.Sprintf("|%d", v.ID)
	}
	return s
}

//IDs return a VLAN IDs as a slice of uint16
func (vlans VLANs) IDs() []uint16 {
	r := []uint16{}
	for _, v := range vlans {
		r = append(r, v.ID)
	}
	return r
}

//SetIDs set VLAN ID with the specified uint16 slice
func (vlans VLANs) SetIDs(ids []uint16) error {
	if len(vlans) != len(ids) {
		return fmt.Errorf("the number of specified ID is different from what is needed")
	}
	for i, id := range ids {
		vlans[i].ID = id
	}
	return nil
}

//Clone return a deep copy
func (vlans VLANs) Clone() VLANs {
	r := VLANs{}
	for _, v := range vlans {
		r = append(r, &VLAN{
			ID:        v.ID,
			EtherType: v.EtherType,
		},
		)
	}
	return r
}

//Copy copy value of lvans2 to vlans
func (vlans *VLANs) Copy(vlans2 VLANs) {
	*vlans = VLANs{}
	for _, v := range vlans2 {
		*vlans = append(*vlans, &VLAN{
			ID:        v.ID,
			EtherType: v.EtherType,
		})
	}

}

//Equal returns true if vlans == vlans2
func (vlans VLANs) Equal(vlans2 VLANs) bool {
	if len(vlans) != len(vlans2) {
		return false
	}
	for i := range vlans {
		if vlans[i].ID != vlans2[i].ID {
			return false
		}
		if vlans[i].EtherType != vlans2[i].EtherType {
			return false
		}
	}
	return true
}

// L2Endpoint represents a layer2 endpoint that send/receives Ethernet frame
type L2Endpoint struct {
	HwAddr net.HardwareAddr
	VLANs  []uint16
	Etype  uint16 //inner most EtherType (e.g payload type)
}

func newL2Endpoint() *L2Endpoint {
	r := new(L2Endpoint)
	r.HwAddr = net.HardwareAddr(make([]byte, 6))
	r.VLANs = []uint16{}
	return r
}

// NewL2EndpointFromMACVLAN creates a new L2Endpoint from mac and vlans;
// its Etype  is set to any
func NewL2EndpointFromMACVLAN(mac net.HardwareAddr, vlans VLANs) *L2Endpoint {
	r := newL2Endpoint()
	copy(r.HwAddr, mac)
	r.VLANs = []uint16{}
	for _, v := range vlans {
		r.VLANs = append(r.VLANs, v.ID)
	}
	return r
}

// NewL2EndpointFromMACVLANEtype creates a new L2Endpoint from mac, vlans and etype
func NewL2EndpointFromMACVLANEtype(mac net.HardwareAddr, vlans VLANs, etype uint16) *L2Endpoint {
	r := NewL2EndpointFromMACVLAN(mac, vlans)
	r.Etype = etype
	return r
}

// p is a ethernet packet in byte slice,
func getL2EPandReceival(p []byte, auxdata []interface{}) (*L2Endpoint, *RelayReceival) {
	l2ep := newL2Endpoint()
	rcv := newRelayReceival()
	rcv.EtherBytes = p
	copy(l2ep.HwAddr, p[:6])
	rcv.RemoteMAC = p[6:12]
	index := 12
	var etype, vlan2bytes uint16
	for {
		etype = binary.BigEndian.Uint16(p[index : index+2])
		if etype == 0x8100 || etype == 0x88a8 {
			vlan2bytes = binary.BigEndian.Uint16(p[index+2 : index+4])
			l2ep.VLANs = append(l2ep.VLANs, vlan2bytes&0x0fff)
		} else {
			l2ep.Etype = etype
			break
		}
		index += 4
	}
	rcv.EtherPayloadBytes = p[index+2:]
	for _, adata := range auxdata {
		if v, ok := adata.(afpacket.AncillaryVLAN); ok {
			l2ep.VLANs = append([]uint16{uint16(v.VLAN)}, l2ep.VLANs...)
		}
	}
	var l4index int

	switch l2ep.Etype {
	case 0x0800: //ipv4
		rcv.RemoteIP = rcv.EtherPayloadBytes[12:16]
		rcv.LocalIP = rcv.EtherPayloadBytes[16:20]
		rcv.Protocol = rcv.EtherPayloadBytes[9]
		l4index = 20 //NOTE: this means no supporting of any ipv4 options
	case 0x86dd: //ipv6
		rcv.Protocol = rcv.EtherPayloadBytes[6]
		rcv.RemoteIP = rcv.EtherPayloadBytes[8:24]
		rcv.LocalIP = rcv.EtherPayloadBytes[24:40]
		l4index = 40 //NOTE: this means no supporting of any ipv4 options
	}
	switch rcv.Protocol {
	case 17: //udp
		rcv.RemotePort = binary.BigEndian.Uint16(rcv.EtherPayloadBytes[l4index : l4index+2])
		rcv.LocalPort = binary.BigEndian.Uint16(rcv.EtherPayloadBytes[l4index+2 : l4index+4])
		rcv.TransportPayloadBytes = rcv.EtherPayloadBytes[l4index+8:]
	}

	return l2ep, rcv
}

const (
	// MaxNumVLAN specifies max number vlan this pkg supports
	MaxNumVLAN = 2
	// L2EndpointKeySize is the size of L2EndpointKey in bytes
	L2EndpointKeySize = 6 + 2*MaxNumVLAN + 2 //must be 6+2*n
)

// L2EndpointKey is key identify a L2EndPoint,first 6 bytes are MAC address,
// VLAN Ids in order (from outside to inner),
// each VLAN id are two bytes in network endian, if VLAN id is NOVLANTAG,
// then it means no such tag; last two bytes are inner most EtherType.
type L2EndpointKey [L2EndpointKeySize]byte

func (l2epkey L2EndpointKey) String() string {
	r := fmt.Sprintf("%v", net.HardwareAddr(l2epkey[:6]))
	for i := 6; i+2 <= L2EndpointKeySize-2; i += 2 {
		vid := binary.BigEndian.Uint16(l2epkey[i : i+2])
		if vid != NOVLANTAG {
			r += fmt.Sprintf("|%d", vid)
		}
	}
	r += fmt.Sprintf("#0x%x", l2epkey[len(l2epkey)-2:])
	return r
}

// GetKey returns the key of the L2Endpoint
func (l2e *L2Endpoint) GetKey() (key L2EndpointKey) {
	copy(key[:6], l2e.HwAddr[:6])
	j := 0
	for i := 6; i+2 <= L2EndpointKeySize; i += 2 {
		if j < len(l2e.VLANs) {
			binary.BigEndian.PutUint16(key[i:i+2], l2e.VLANs[j])
		} else {
			binary.BigEndian.PutUint16(key[i:i+2], NOVLANTAG)
		}
		j++
	}
	binary.BigEndian.PutUint16(key[len(key)-2:], l2e.Etype)
	return
}

// Network implements net.Addr interface, return "l2ep"
func (l2e *L2Endpoint) Network() string {
	return "l2ep"
}

// String implements net.Addr interface, return a string with format:
// l2ep&<l2EndpointKey_str>, see L2EndpointKey.String for format of <l2EndpointKey_str>
func (l2e *L2Endpoint) String() (s string) {
	return fmt.Sprintf("%v&%v", l2e.Network(), l2e.GetKey().String())
}

// DefaultVLANEtype is the default Ethernet type for vlan tags,
// used by function GetVLANs()
const DefaultVLANEtype = 0x8100

// GetVLANsWithDefaultEtype return an instance of VLANs with VLAN ethernet type set as DefaultVLANEtype
func (l2e *L2Endpoint) GetVLANsWithDefaultEtype() (r VLANs) {
	for _, vid := range l2e.VLANs {
		r = append(r, &VLAN{
			ID:        vid,
			EtherType: DefaultVLANEtype,
		})
	}
	return
}

// RelayReceival is the what PacketRelay received and parsed
type RelayReceival struct {
	//RemoteMAC is the remote MAC address
	RemoteMAC net.HardwareAddr
	// EtherBytes is the Ethernet frame bytes
	EtherBytes []byte
	// EtherPayloadBytes is the Ethernet payload bytes within the EtherBytes,
	// where payload belongs to the specified EtherTypes,
	// default are 0x0800 (IPv4) and 0x86dd (IPv6),
	// nil if there is no payload with specified EtherTypes;
	EtherPayloadBytes []byte
	// TransportPayloadBytes is the transport layer(UDP/TCP/SCTP) payload bytes within the IPBytes,nil for unsupport transport layer
	TransportPayloadBytes []byte
	// RemoteIP is the remote IP address
	RemoteIP net.IP
	// RemotePort is the remote transport layer port, 0 for unsupport transport layer
	RemotePort uint16
	// Protocol is the IP protocol number
	Protocol uint8
	// LocalIP is the local IP address
	LocalIP net.IP
	// LocalPort is the local transport layer port, 0 for unsupport transport layer
	LocalPort uint16
}

func newRelayReceival() *RelayReceival {
	recval := new(RelayReceival)
	recval.EtherPayloadBytes = nil
	recval.EtherBytes = nil
	recval.TransportPayloadBytes = nil
	return recval

}

func (rr *RelayReceival) GetL4Key() (r L4RecvKey) {
	copy(r[:16], []byte(rr.LocalIP.To16()))
	r[16] = rr.Protocol
	binary.BigEndian.PutUint16(r[17:], rr.LocalPort)
	return
}

// L4Endpoint represents a Layer4 (e.g. UDP) endpoint
// type L4Endpoint struct {
// 	IPAddr     net.IP
// 	IPProtocol uint8
// 	Port       uint16
// }

// func (l4ep L4Endpoint) String() string {
// 	return fmt.Sprintf("%v:%v:%v", l4ep.IPProtocol, l4ep.IPAddr, l4ep.Port)
// }

type chanMap struct {
	cmlist map[interface{}]chan *RelayReceival
	lock   *sync.RWMutex
}

func newchanMap() *chanMap {
	r := &chanMap{}
	r.cmlist = make(map[interface{}]chan *RelayReceival)
	r.lock = &sync.RWMutex{}
	return r
}

func (cm *chanMap) CloseAll() {
	cm.lock.Lock()
	for _, c := range cm.cmlist {
		close(c)
	}
	cm.lock.Unlock()
}

func (cm *chanMap) Set(k interface{}, v chan *RelayReceival) {
	cm.lock.Lock()
	cm.cmlist[k] = v
	cm.lock.Unlock()
}

func (cm *chanMap) SetList(ks []interface{}, v chan *RelayReceival) {
	cm.lock.Lock()
	for _, k := range ks {
		cm.cmlist[k] = v
	}
	cm.lock.Unlock()
}

func (cm *chanMap) Get(k interface{}) chan *RelayReceival {
	cm.lock.RLock()
	defer cm.lock.RUnlock()
	return cm.cmlist[k]
}

func (cm *chanMap) Del(k interface{}) {
	cm.lock.Lock()
	delete(cm.cmlist, k)
	cm.lock.Unlock()
}
func (cm *chanMap) DelList(ks []interface{}) {
	cm.lock.Lock()
	for _, k := range ks {
		delete(cm.cmlist, k)
	}
	cm.lock.Unlock()
}

func (cm *chanMap) GetList() []chan *RelayReceival {
	rlist := []chan *RelayReceival{}
	cm.lock.RLock()
	for _, c := range cm.cmlist {
		rlist = append(rlist, c)
	}
	cm.lock.RUnlock()
	return rlist
}

// PacketRelay is a interface for the packet forwarding engine,
// RawSocketRelay implements this interface;
type PacketRelay interface {
	// Register register a list of L2EndpointKey of a EtherConn, PacketRely send/recv pkt on its behalf,
	// it returns following channels:
	// recv is the channel used to recive;
	// send is the channel used to send;
	// stop is a channel that will be closed when PacketRelay stops sending;
	// if recvMulticast is true, then multicast ethernet traffic will be recvied as well;
	// if one of key is already registered, then existing key will be overriden;
	Register(ks []L2EndpointKey, recvMulticast bool) (recv chan *RelayReceival, send chan []byte, stop chan struct{})
	// RegisterDefault return default receive channel,
	// meaning a received pkt doesn't match any other specific EtherConn registered with L2Endpointkey will be send to this channel;
	// multicast traffic will be also sent to this channel;
	RegisterDefault() (recv chan *RelayReceival, send chan []byte, stop chan struct{})
	// Deregister removes L2EndpointKey from registration
	Deregister(ks []L2EndpointKey)
	// Stop stops the forwarding of PacketRelay
	Stop()
	// IfName return binding interface name
	IfName() string
	// GetStats returns stats
	GetStats() *RelayPacketStats
}

// RawSocketRelay implements PacketRelay interface, using AF_PACKET socket
type RawSocketRelay struct {
	conn                 *afpacket.TPacket
	toSendChan           chan []byte
	stopToSendChan       chan struct{}
	recvList             *chanMap
	wg                   *sync.WaitGroup
	cancelFunc           context.CancelFunc
	recvTimeout          time.Duration
	multicastList        *chanMap
	perClntRecvChanDepth uint
	sendChanDepth        uint
	maxEtherFrameSize    uint
	stats                *RelayPacketStats
	logger               *log.Logger
	// etherTypeList        map[uint16]struct{} //TODO: remove this , this is duplicate with bpfFilter
	ifName          string
	bpfFilter       *string
	defaultRecvChan chan *RelayReceival
	mirrorToDefault bool
	engineCount     uint
}

// RelayOption is a function use to provide customized option when creating RawSocketRelay
type RelayOption func(*RawSocketRelay)

// WithMultiEngine specifies the number of internal send/recv routine,
// count must >=1, default value is 1
func WithMultiEngine(count uint) RelayOption {
	return func(relay *RawSocketRelay) {
		if count > 0 {
			relay.engineCount = count
		}
	}
}

// WithDebug enable/disable debug log output
func WithDebug(debug bool) RelayOption {
	return func(relay *RawSocketRelay) {
		if debug {
			relay.logger = log.New(os.Stderr, "", log.Ldate|log.Ltime)
		} else {
			relay.logger = nil
		}
	}
}

// WithPerClntChanRecvDepth specifies the per Client(EtherConn) receive channel depth,
// By default, DefaultPerClntRecvChanDepth is used
func WithPerClntChanRecvDepth(depth uint) RelayOption {
	return func(relay *RawSocketRelay) {
		relay.perClntRecvChanDepth = depth
	}
}

// WithSendChanDepth specifies the send channel depth,
// by default, DefaultSendChanDepth is used
func WithSendChanDepth(depth uint) RelayOption {
	return func(relay *RawSocketRelay) {
		relay.sendChanDepth = depth
	}
}

// WithMaxEtherFrameSize specifies the max Ethernet frame size the RawSocketRelay could receive
func WithMaxEtherFrameSize(size uint) RelayOption {
	return func(relay *RawSocketRelay) {
		relay.maxEtherFrameSize = size
	}
}

// WithBPFFilter set BPF filter, which is a pcap filter string;
// if filter is an empty string, then it means no filter;
// by default, Relay will have a filter only allow traffic with specified EtherType.
func WithBPFFilter(filter string) RelayOption {
	return func(relay *RawSocketRelay) {
		relay.bpfFilter = new(string)
		*relay.bpfFilter = filter
	}
}

// WithRecvTimeout specifies the receive timeout for RawSocketRelay
func WithRecvTimeout(t time.Duration) RelayOption {
	return func(relay *RawSocketRelay) {
		relay.recvTimeout = t
	}
}

// WithDefaultReceival creates a default receiving channel,
// all received pkt doesn't match any explicit EtherConn, will be sent to this channel;
// using RegisterDefault to get the default receiving channel.
// if mirroring is true, then every received pkt will be sent to this channel.
func WithDefaultReceival(mirroring bool) RelayOption {
	return func(relay *RawSocketRelay) {
		relay.defaultRecvChan = make(chan *RelayReceival, relay.perClntRecvChanDepth)
		relay.mirrorToDefault = mirroring
	}
}

// var exists = struct{}{}

// DefaultEtherTypes is the default list of Ethernet types for RawPacketRelay and EtherConn
var DefaultEtherTypes = []uint16{
	uint16(layers.EthernetTypeARP),
	uint16(layers.EthernetTypeIPv4),
	uint16(layers.EthernetTypeIPv6)}

// NewRawSocketRelay creates a new RawSocketRelay instance,
// bound to the interface ifname,
// optionally along with RelayOption functions.
// This function will put the interface in promisc mode, which means it requires root privilage
func NewRawSocketRelay(parentctx context.Context, ifname string, options ...RelayOption) (*RawSocketRelay, error) {
	r := &RawSocketRelay{}
	var err error
	//NOTE:interface must be put in promisc mode, otherwise only pkt with real mac will be received
	err = setPromisc(ifname)
	if err != nil {
		return nil, fmt.Errorf("failed to set %v to Promisc mode,%w", ifname, err)

	}
	r.ifName = ifname
	r.recvTimeout = DefaultRelayRecvTimeout
	r.conn, err = afpacket.NewTPacket(
		afpacket.OptInterface(ifname),
		afpacket.OptFrameSize(afpacket.DefaultFrameSize),
		afpacket.OptBlockSize(afpacket.DefaultBlockSize),
		afpacket.OptNumBlocks(afpacket.DefaultNumBlocks),
		afpacket.OptAddVLANHeader(false),
		afpacket.OptPollTimeout(r.recvTimeout),
		afpacket.SocketRaw,
		afpacket.TPacketVersionHighestAvailable)
	if err != nil {
		return nil, fmt.Errorf("failed to create rawsocketrelay,%w", err)
	}
	r.stopToSendChan = make(chan struct{})
	// r.etherTypeList = map[uint16]struct{}{0x0800: exists, 0x86dd: exists}
	r.perClntRecvChanDepth = DefaultPerClntRecvChanDepth
	r.sendChanDepth = DefaultSendChanDepth
	r.maxEtherFrameSize = DefaultMaxEtherFrameSize
	var ctx context.Context
	ctx, r.cancelFunc = context.WithCancel(parentctx)
	r.toSendChan = make(chan []byte, r.sendChanDepth)

	r.recvList = newchanMap()
	r.multicastList = newchanMap()
	r.stats = newRelayPacketStats()
	r.wg = new(sync.WaitGroup)
	r.bpfFilter = nil
	r.defaultRecvChan = nil
	r.engineCount = 1
	for _, op := range options {
		op(r)
	}
	if r.bpfFilter != nil {
		// if *r.bpfFilter != "" {
		err = r.setBPFFilter(*r.bpfFilter)
		// }
	} else {
		err = r.setBPFFilter(buildPCAPFilterStrForEtherType(DefaultEtherTypes))
	}
	if err != nil {
		return nil, err
	}

	for i := 0; i < int(r.engineCount); i++ {
		r.wg.Add(2)
		go r.recv(ctx)
		go r.send(ctx)
	}
	return r, nil
}

func (rsr *RawSocketRelay) log(format string, a ...interface{}) {
	if rsr.logger == nil {
		return
	}
	msg := fmt.Sprintf(format, a...)
	_, fname, linenum, _ := runtime.Caller(1)
	rsr.logger.Print(fmt.Sprintf("%v:%v:%v:%v", filepath.Base(fname), linenum, rsr.ifName, msg))
}

// Register implements PacketRelay interface;
func (rsr *RawSocketRelay) Register(ks []L2EndpointKey, recvMulticast bool) (chan *RelayReceival, chan []byte, chan struct{}) {
	// return nil, nil, nil
	// ch := rsr.recvList.Get(k)
	// if ch != nil {
	// 	return ch, rsr.toSendChan, rsr.stopToSendChan
	// }
	ch := make(chan *RelayReceival, rsr.perClntRecvChanDepth)
	// rsr.logger.Printf("register for %v, with recv depth %d", ks, rsr.perClntRecvChanDepth)
	list := make([]interface{}, len(ks))
	for i := range ks {
		list[i] = ks[i]
	}
	rsr.recvList.SetList(list, ch)
	if recvMulticast {
		//NOTE: only set one key in multicast, otherwise the EtherConn will receive multiple copies
		rsr.multicastList.Set(ks[0], ch)
	}
	return ch, rsr.toSendChan, rsr.stopToSendChan
}

// RegisterDefault implements PacketRelay interface
func (rsr *RawSocketRelay) RegisterDefault() (chan *RelayReceival, chan []byte, chan struct{}) {
	return rsr.defaultRecvChan, rsr.toSendChan, rsr.stopToSendChan
}

// Deregister implements PacketRelay interface;
func (rsr *RawSocketRelay) Deregister(ks []L2EndpointKey) {
	list := make([]interface{}, len(ks))
	for i := range ks {
		list[i] = ks[i]
	}
	rsr.recvList.DelList(list)
	rsr.multicastList.DelList(list)
}

func (rsr *RawSocketRelay) send(ctx context.Context) {
	runtime.LockOSThread()
	defer rsr.wg.Done()
	// defer close(rsr.stopToSendChan)
	for {
		select {
		case <-ctx.Done():
			rsr.log("relay send routine cancelled")
			return
		case data := <-rsr.toSendChan:
			err := rsr.conn.WritePacketData(data)
			if err != nil {
				rsr.log(fmt.Sprintf("relay failed to send frame, %v", err))
				return
			}
			atomic.AddUint64(rsr.stats.Tx, 1)
		}
	}
}

func checkPacketBytes(p []byte) error {
	if len(p) < 14 {
		return fmt.Errorf("ethernet frame size is smaller than 14B")
	}
	return nil
}

// IfName returns the name of the binding interface
func (rsr *RawSocketRelay) IfName() string {
	return rsr.ifName
}
func sendToChanWithCounter(receival *RelayReceival, ch chan *RelayReceival, counter, fullcounter *uint64) {
	fullcounted := false
	if len(receival.EtherPayloadBytes) == 0 {
		return
	}
	for { //keep sending until pkt is sent to channel
		select {
		case ch <- receival:
			atomic.AddUint64(counter, 1)
			return
		default:
			<-ch //channel is full, remove the oldest pkt in channel
			if !fullcounted {
				log.Printf("recv chan has cap of %d and len %d\n", cap(ch), len(ch))
				atomic.AddUint64(fullcounter, 1)
				fullcounted = true
			}
		}
	}
}

// GetStats return pkt forwarding stats as *RelayPacketStats
func (rsr *RawSocketRelay) GetStats() *RelayPacketStats {
	return rsr.stats
}

func (rsr *RawSocketRelay) recv(ctx context.Context) {
	runtime.LockOSThread()
	var logf LogFunc = nil
	if rsr.logger != nil {
		logf = rsr.log
	}
	defer rsr.wg.Done()
	// defer rsr.recvList.CloseAll() //TODO: this might create race issue, given sendToChanWithCounter will also use the ch, does this really need to be closed?
	for {
		b := make([]byte, rsr.maxEtherFrameSize)
		ci, err := rsr.conn.ReadPacketDataTo(b)

		if err != nil {
			if errors.Is(err, afpacket.ErrTimeout) {
				select {
				case <-ctx.Done():
					rsr.log("relay recv routine cancelled")
					return
				default:
					continue
				}
			} else {
				rsr.log(fmt.Sprintf("error reading from raw connection: %v", err))
				return
			}
		}
		handleRcvPkt(b[:ci.CaptureLength], rsr.stats, logf, rsr.recvList,
			rsr.mirrorToDefault, rsr.defaultRecvChan, rsr.multicastList, ci.AncillaryData)
	}
}

// Stop implements PacketRelay interface
func (rsr *RawSocketRelay) Stop() {
	rsr.log("relay stopping")
	rsr.cancelFunc()
	// this ticker is to make sure relay stop in case poll timeout is not supported by kernel(need TPacketV3)
	// ticker time can't be too small, otherwise, if the rsr.conn.Close before recv or send routine quit, it might cause panic
	ticker := time.NewTicker(rsr.recvTimeout + 5*time.Second)
	defer ticker.Stop()
	done := make(chan bool)
	go func(d chan bool) {
		rsr.wg.Wait()
		close(rsr.stopToSendChan)
		d <- true

	}(done)
	select {
	case <-done:
	case <-ticker.C:
	}
	rsr.log(fmt.Sprintf("RawSocketRelay stats:\n%v", rsr.stats.String()))
	_, rawstat, err := rsr.conn.SocketStats()
	if err != nil {
		rsr.log("failed to get raw stats %v", err)
	}
	rsr.log("raw stats:%+v", rawstat)
	//NOTE: without closing this, the recreating relay on same interface might cause issue
	rsr.conn.Close()
}

// EtherConn send/recv Ethernet payload like IP packet with
// customizable Ethernet encapsualtion like MAC and VLANs without
// provisioning them in OS.
// it needs to be registed with a PacketRelay instance to work.
type EtherConn struct {
	recvL2EPs         []*L2Endpoint
	recvEtypes        []uint16
	relay             PacketRelay
	ownMAC            net.HardwareAddr //for egress
	vlans             VLANs            //for egress
	sendChan          chan []byte
	recvChan          chan *RelayReceival
	stopSendChan      chan struct{}
	readDeadline      time.Time
	readDeadlineLock  *sync.RWMutex
	writeDeadline     time.Time
	writeDeadlineLock *sync.RWMutex
	recvMulticast     bool
	isDefault         bool
}

// EtherConnOption is a function use to provide customized option when creating EtherConn
type EtherConnOption func(ec *EtherConn)

// WithVLANs specifies VLAN(s) as part of EtherConn's L2Endpoint.
// by default, there is no VLAN.
func WithVLANs(vlans VLANs) EtherConnOption {
	return func(ec *EtherConn) {
		ec.vlans.Copy(vlans)
	}
}

// WithRecvMulticast allow/disallow EtherConn to receive multicast/broadcast Ethernet traffic
func WithRecvMulticast(recv bool) EtherConnOption {
	return func(ec *EtherConn) {
		ec.recvMulticast = recv
	}
}

// WithDefault will register the EtherConn to be the default EtherConn for received traffic,
// see PacketRelay.RegisterDefault for details.
// if relay is created with mirroring to default, then the etherconn will get a copy of all received pkt by the relay
func WithDefault() EtherConnOption {
	return func(ec *EtherConn) {
		ec.isDefault = true
	}
}

// WithEtherTypes specifies a list of Ethernet types that this EtherConn is interested in,
// the specified Ethernet types is the types of inner payload,
// the default list is DefaultEtherTypes
func WithEtherTypes(ets []uint16) EtherConnOption {
	return func(ec *EtherConn) {
		ec.recvEtypes = make([]uint16, len(ets))
		copy(ec.recvEtypes, ets)
	}
}

// NewEtherConn creates a new EtherConn instance, mac is used as part of EtherConn's L2Endpoint;
// relay is the PacketRelay that EtherConn instance register with;
// options specifies EtherConnOption(s) to use;
func NewEtherConn(mac net.HardwareAddr, relay PacketRelay, options ...EtherConnOption) *EtherConn {
	r := new(EtherConn)
	r.recvEtypes = DefaultEtherTypes
	r.ownMAC = make(net.HardwareAddr, len(mac))
	copy(r.ownMAC, mac)
	for _, option := range options {
		option(r)
	}
	//generate recvL2EPs
	for _, et := range r.recvEtypes {
		r.recvL2EPs = append(r.recvL2EPs, &L2Endpoint{
			HwAddr: r.ownMAC,
			VLANs:  r.vlans.IDs(),
			Etype:  et,
		})
	}
	//generate l2ep keys
	l2keys := []L2EndpointKey{}
	for _, ep := range r.recvL2EPs {
		l2keys = append(l2keys, ep.GetKey())
	}
	if !r.isDefault {
		r.recvChan, r.sendChan, r.stopSendChan = relay.Register(l2keys, r.recvMulticast)
	} else {
		r.recvChan, r.sendChan, r.stopSendChan = relay.RegisterDefault()
	}
	r.readDeadlineLock = new(sync.RWMutex)
	r.writeDeadlineLock = new(sync.RWMutex)
	r.relay = relay
	return r
}

// LocalAddr return EtherConn's L2Endpoint
func (ec *EtherConn) LocalAddr() *L2Endpoint {
	return ec.recvL2EPs[0]
}

// SetReadDeadline implements net.PacketConn interface
func (ec *EtherConn) SetReadDeadline(t time.Time) error {
	ec.readDeadlineLock.Lock()
	ec.readDeadline = t
	ec.readDeadlineLock.Unlock()
	return nil
}

// SetWriteDeadline implements net.PacketConn interface
func (ec *EtherConn) SetWriteDeadline(t time.Time) error {
	ec.writeDeadlineLock.Lock()
	ec.writeDeadline = t
	ec.writeDeadlineLock.Unlock()
	return nil
}

// SetDeadline implements net.PacketConn interface
func (ec *EtherConn) SetDeadline(t time.Time) error {
	ec.SetReadDeadline(t)
	ec.SetWriteDeadline(t)
	return nil
}

//ResolveNexhopMACWithBrodcast is the default resolve function that always return broadcast mac
func ResolveNexhopMACWithBrodcast(ip net.IP) net.HardwareAddr {
	return BroadCastMAC
}

//getAddr return src/dst IP address from an IP packet ipbytes

func (ec *EtherConn) buildEthernetHeaderWithSrcVLAN(srcmac, dstmac net.HardwareAddr, vlans VLANs, payloadtype uint16) []byte {
	ethheader := make([]byte, 14+len(vlans)*4)
	copy(ethheader[:6], dstmac)
	copy(ethheader[6:12], srcmac)
	currentPos := 12
	for _, vlan := range vlans {
		binary.BigEndian.PutUint16(ethheader[currentPos:currentPos+2], vlan.EtherType)
		binary.BigEndian.PutUint16(ethheader[currentPos+2:currentPos+4], vlan.ID)
		currentPos += 4
	}
	binary.BigEndian.PutUint16(ethheader[currentPos:currentPos+2], payloadtype)
	return ethheader
	// //NOTE:follow padding is needed to avoid Ethernet layer serialization to pad to 60B
	// const paddingLen = 60
	// layerList = append(layerList, gopacket.Payload(make([]byte, paddingLen)))
	// opts := gopacket.SerializeOptions{}
	// gopacket.SerializeLayers(buf, opts, layerList...)
	// return buf.Bytes()[:len(buf.Bytes())-paddingLen]
}

// buildEthernetHeader return a Ethernet header byte slice
// func (ec *EtherConn) buildEthernetHeader(dstmac net.HardwareAddr, payloadtype uint16) []byte {
// 	return ec.buildEthernetHeaderWithSrcVLAN(ec.ownMAC, dstmac, ec.vlans, payloadtype)

// eth := layers.Ethernet{
// 	SrcMAC: ec.ownMAC,
// }
// eth.DstMAC = make(net.HardwareAddr, len(dstmac))
// copy(eth.DstMAC, dstmac)
// switch len(ec.vlans) {
// case 0:
// 	eth.EthernetType = layers.EthernetType(payloadtype)
// default:
// 	eth.EthernetType = layers.EthernetType(ec.vlans[0].EtherType)
// }
// layerList := []gopacket.SerializableLayer{&eth}
// for i, v := range ec.vlans {
// 	vlan := layers.Dot1Q{
// 		VLANIdentifier: v.ID,
// 	}
// 	if i == len(ec.vlans)-1 {
// 		vlan.Type = layers.EthernetType(payloadtype)
// 	} else {
// 		vlan.Type = layers.EthernetType(ec.vlans[i+1].EtherType)
// 	}
// 	layerList = append(layerList, &vlan)
// }
// buf := gopacket.NewSerializeBuffer()
// //NOTE:follow padding is needed to avoid Ethernet layer serialization to pad to 60B
// const paddingLen = 60
// layerList = append(layerList, gopacket.Payload(make([]byte, paddingLen)))
// opts := gopacket.SerializeOptions{}
// gopacket.SerializeLayers(buf, opts, layerList...)
// return buf.Bytes()[:len(buf.Bytes())-paddingLen]
// }

// WriteIPPktTo sends an IPv4/IPv6 packet,
// the pkt will be sent to dstmac, along with EtherConn.L2EP.VLANs.
func (ec *EtherConn) WriteIPPktTo(p []byte, dstmac net.HardwareAddr) (int, error) {
	return ec.WriteIPPktToFrom(p, ec.ownMAC, dstmac, ec.vlans)
}

// WriteIPPktToFrom is same as WriteIPPktTo beside send pkt with srcmac
func (ec *EtherConn) WriteIPPktToFrom(p []byte,
	srcmac, dstmac net.HardwareAddr, vlans VLANs) (int, error) {
	return ec.writeIPPktToFrom(p, srcmac, dstmac, vlans)
}

func (ec *EtherConn) writeIPPktToFrom(p []byte, srcmac, dstmac net.HardwareAddr,
	vlans VLANs) (int, error) {
	var payloadtype layers.EthernetType
	switch p[0] >> 4 {
	case 4:
		payloadtype = layers.EthernetTypeIPv4
	case 6:
		payloadtype = layers.EthernetTypeIPv6
	default:
		return 0, fmt.Errorf("failed to write to EtherConn, invalid IP version, %d", p[0]>>4)
	}
	return ec.writePktToFrom(p, uint16(payloadtype), srcmac, dstmac, vlans)
}

//writePktToFrom support both RawPacketRelay and XDPRelay,
//in case xdp,if xdpsockid<0, then use EtherConn's own socket,
//otherwise use the specified socket
func (ec *EtherConn) writePktToFrom(p []byte, etype uint16,
	srcmac, dstmac net.HardwareAddr,
	vlans VLANs) (int, error) {
	h := ec.buildEthernetHeaderWithSrcVLAN(srcmac, dstmac, vlans, etype)
	fullp := append(h, p...)
	select {
	case <-ec.stopSendChan:
		return 0, ErrRelayStopped
	default:
	}
	ec.writeDeadlineLock.RLock()
	deadline := ec.writeDeadline
	ec.writeDeadlineLock.RUnlock()
	d := time.Until(deadline)
	timeout := false
	if d > 0 {
		select {
		case <-ec.stopSendChan:
			return 0, ErrRelayStopped
		case <-time.After(d):
			timeout = true
		case ec.sendChan <- fullp:
		}
	} else {
		select {
		case ec.sendChan <- fullp:
		case <-ec.stopSendChan:
			return 0, ErrRelayStopped
		}

	}
	if timeout {
		return 0, ErrTimeOut
	}
	return len(p), nil
}

// WritePktToFrom is same as WritePktTo except with srcmac
func (ec *EtherConn) WritePktToFrom(p []byte, etype uint16, srcmac,
	dstmac net.HardwareAddr, vlans VLANs) (int, error) {
	return ec.writePktToFrom(p, etype, srcmac, dstmac, vlans)
}

// WritePktTo sends an Ethernet payload, along with specified EtherType,
// the pkt will be sent to dstmac, along with EtherConn.L2EP.VLANs.
func (ec *EtherConn) WritePktTo(p []byte, etype uint16, dstmac net.HardwareAddr) (int, error) {
	return ec.WritePktToFrom(p, etype, ec.ownMAC, dstmac, ec.vlans)
}

func (ec *EtherConn) getReceival() (*RelayReceival, error) {
	ec.readDeadlineLock.RLock()
	deadline := ec.readDeadline
	ec.readDeadlineLock.RUnlock()
	d := time.Until(deadline)
	timeout := false
	var receival *RelayReceival
	if d > 0 {
		select {
		case <-time.After(d):
			timeout = true
		case receival = <-ec.recvChan:
		}
	} else {
		receival = <-ec.recvChan
	}
	if receival == nil {
		if timeout {
			return nil, ErrTimeOut
		}
		return nil, fmt.Errorf("failed to read from relay")
	}
	return receival, nil
}

// ReadPktFrom copies the received Ethernet payload to p;
// it calls ReadPkt to get the payload,
// it return number bytes of IP packet, remote MAC address
func (ec *EtherConn) ReadPktFrom(p []byte) (int, net.HardwareAddr, error) {
	buf, srcmac, err := ec.ReadPkt()
	if err != nil {
		return 0, nil, err
	}
	copy(p, buf)
	return len(buf), srcmac, nil
}

// ReadPkt return received Ethernet payload bytes with an already allocated byte slice;
// ReadPkt only return payload that matches one of underlying PacketRelay's configured EtherTypes
func (ec *EtherConn) ReadPkt() ([]byte, net.HardwareAddr, error) {
	receival, err := ec.getReceival()
	if err != nil {
		return nil, nil, err
	}

	return receival.EtherPayloadBytes, receival.RemoteMAC, nil
}

// Close implements net.PacketConn interface, deregister itself from PacketRelay
func (ec *EtherConn) Close() error {
	l2keys := []L2EndpointKey{}
	for _, ep := range ec.recvL2EPs {
		l2keys = append(l2keys, ep.GetKey())
	}
	ec.relay.Deregister(l2keys)
	// TODO: can't close here bluntly, otehrwise there could be send to closed channel panic
	// close(ec.recvChan)
	return nil
}

// RUDPConn implement net.PacketConn interface;
// it used to send/recv UDP payload, using a underlying EtherConn for pkt forwarding.
type RUDPConn struct {
	localAddress                      *net.UDPAddr
	addrLock                          *sync.RWMutex
	conn                              *EtherConn
	acceptAnyUDP                      bool
	resolveNexthopFunc                func(net.IP) net.HardwareAddr
	ipHeader, pseudoHeader, udpHeader []byte
}

// RUDPConnOption is a function use to provide customized option when creating RUDPConn
type RUDPConnOption func(rudpc *RUDPConn)

// WithAcceptAny allows RUDPConn to accept any UDP pkts, even it is not destinated to its address
func WithAcceptAny(accept bool) RUDPConnOption {
	return func(rudpc *RUDPConn) {
		rudpc.acceptAnyUDP = accept
	}
}

// WithResolveNextHopMacFunc specifies a function to resolve a destination
// IP address to next-hop MAC address;
// by default, ResolveNexhopMACWithBrodcast is used.
func WithResolveNextHopMacFunc(f func(net.IP) net.HardwareAddr) RUDPConnOption {
	return func(rudpc *RUDPConn) {
		rudpc.resolveNexthopFunc = f
	}
}

// NewRUDPConn creates a new RUDPConn, with specified EtherConn, and, optionally RUDPConnOption(s).
// src is the string represents its UDP Address as format supported by net.ResolveUDPAddr().
// note the src UDP address could be any IP address, even address not provisioned in OS, like 0.0.0.0
func NewRUDPConn(src string, c *EtherConn, options ...RUDPConnOption) (*RUDPConn, error) {
	r := new(RUDPConn)
	var err error
	r.localAddress, err = net.ResolveUDPAddr("udp", src)
	if err != nil {
		return nil, err
	}
	r.conn = c
	r.resolveNexthopFunc = ResolveNexhopMACWithBrodcast
	r.addrLock = new(sync.RWMutex)
	for _, opt := range options {
		opt(r)
	}
	r.udpHeader = make([]byte, 8)
	binary.BigEndian.PutUint16(r.udpHeader[:2], uint16(r.localAddress.Port)) //src port
	if r.localAddress.IP.To4() == nil {
		//v6
		r.ipHeader = make([]byte, 40)
		r.ipHeader[0] = 0x60                                  //version
		r.ipHeader[6] = 17                                    //next header
		r.ipHeader[7] = DefaultTTL                            //TTL
		copy(r.ipHeader[8:24], r.localAddress.IP.To16()[:16]) //src addr
		r.pseudoHeader = make([]byte, 40)
		copy(r.pseudoHeader[:16], r.localAddress.IP.To16()[:16]) //src addr
		r.pseudoHeader[39] = 17                                  //next header
	} else {
		//v4
		r.ipHeader = make([]byte, 20)
		r.ipHeader[0] = 0x45
		r.ipHeader[8] = DefaultTTL
		r.ipHeader[9] = 17                                   //protocol
		copy(r.ipHeader[12:16], r.localAddress.IP.To4()[:4]) //src addr
		r.pseudoHeader = make([]byte, 12)
		copy(r.pseudoHeader[:4], r.localAddress.IP.To4()[:4]) //src addr
		r.pseudoHeader[9] = 17                                //ip proto
	}
	return r, nil

}

// Close implements net.PacketConn interface, it closes underlying EtherConn
func (ruc *RUDPConn) Close() error {
	return ruc.conn.Close()
}

// LocalAddr implements net.PacketConn interface, it returns its UDPAddr
func (ruc *RUDPConn) LocalAddr() net.Addr {
	return ruc.localAddress
}

// ReadFrom implements net.PacketConn interface, it copy UDP payload to p;
// note: the underlying EtherConn will send all received pkts as *RelayReceival to RUDPConn,
// RUDPConn will ignore pkts that is not destined to its UDPAddr,
// unless WithAcceptAny(true) is specified when creating the RUDPConn, in that case,
// RUDPConn will accept any UDP packet;
func (ruc *RUDPConn) ReadFrom(p []byte) (int, net.Addr, error) {
	for {
		receival, err := ruc.conn.getReceival()
		if err != nil {
			return 0, nil, err
		}
		if receival.Protocol == 17 {
			if ruc.acceptAnyUDP || (!ruc.acceptAnyUDP && (ruc.localAddress.IP.Equal(receival.LocalIP) && ruc.localAddress.Port == int(receival.LocalPort))) {
				copy(p, receival.TransportPayloadBytes)
				return len(receival.TransportPayloadBytes), &net.UDPAddr{IP: receival.RemoteIP, Port: int(receival.RemotePort), Zone: "udp"}, nil
			}
		}
	}

}

func (ruc *RUDPConn) buildPkt(p []byte, srcaddr, dstaddr net.Addr) ([]byte, net.IP) {
	dst := dstaddr.(*net.UDPAddr)
	src := srcaddr.(*net.UDPAddr)
	var fullp []byte
	if len(ruc.ipHeader) > 20 {
		//v6
		fullp = append(make([]byte, 48), p...)
		psuHeader := make([]byte, 40)
		copy(psuHeader, ruc.pseudoHeader)
		copy(fullp[:40], ruc.ipHeader)
		copy(fullp[40:48], ruc.udpHeader)
		//ip header
		binary.BigEndian.PutUint16(fullp[4:6], uint16(48+len(p))) //length
		copy(fullp[8:24], src.IP.To16()[:16])                     //src addr
		copy(fullp[24:40], dst.IP.To16()[:16])                    //dst addr
		//psudo header
		copy(psuHeader[:16], src.IP.To16()[:16])                       //src addr
		copy(psuHeader[16:32], dst.IP.To16()[:16])                     //dst addr
		binary.BigEndian.PutUint32(psuHeader[32:36], uint32(8+len(p))) //udp len
		//udp header
		binary.BigEndian.PutUint16(fullp[40:42], uint16(src.Port))                     //src port
		binary.BigEndian.PutUint16(fullp[42:44], uint16(dst.Port))                     //dst port
		binary.BigEndian.PutUint16(fullp[44:46], uint16(8+len(p)))                     //udp len
		binary.BigEndian.PutUint16(fullp[46:48], v6udpChecksum(fullp[40:], psuHeader)) //udp checksum

	} else {
		//v4
		fullp = append(make([]byte, 28), p...)
		psuHeader := make([]byte, 12)
		copy(psuHeader, ruc.pseudoHeader)
		copy(fullp[:20], ruc.ipHeader)
		copy(fullp[20:28], ruc.udpHeader)
		//ip header
		binary.BigEndian.PutUint16(fullp[2:4], uint16(28+len(p)))          //length
		copy(fullp[12:16], src.IP.To4()[:4])                               //src addr
		copy(fullp[16:20], dst.IP.To4()[:4])                               //dst addr
		binary.BigEndian.PutUint16(fullp[10:12], ipv4Checksum(fullp[:20])) //ipv4 header checksum
		//psudo header
		copy(psuHeader[:4], src.IP.To4()[:4])                          //src addr
		copy(psuHeader[4:8], dst.IP.To4()[:4])                         //dst addr
		binary.BigEndian.PutUint16(psuHeader[10:12], uint16(8+len(p))) //udp len
		//udp header
		binary.BigEndian.PutUint16(fullp[20:22], uint16(src.Port)) //src port
		binary.BigEndian.PutUint16(fullp[22:24], uint16(dst.Port)) //dst port
		binary.BigEndian.PutUint16(fullp[24:26], uint16(8+len(p))) //udp len
		//v4 doesn't do checksum
	}
	return fullp, dst.IP
}

// WriteToFrom is same as WriteTo except sending payload p to dst with source address as src
func (ruc *RUDPConn) WriteToFrom(p []byte, srcaddr, dstaddr net.Addr) (int, error) {
	pktbuf, dstip := ruc.buildPkt(p, srcaddr, dstaddr)
	nexthopMAC := ruc.resolveNexthopFunc(dstip)
	_, err := ruc.conn.WriteIPPktTo(pktbuf, nexthopMAC)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// WriteTo implements net.PacketConn interface, it sends UDP payload;
// This function adds UDP and IP header, and uses RUDPConn's resolve function
// to get nexthop's MAC address, and use underlying EtherConn to send IP packet,
// with EtherConn's Ethernet encapsulation, to nexthop MAC address;
// by default ResolveNexhopMACWithBrodcast is used for nexthop mac resolvement
func (ruc *RUDPConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	ruc.addrLock.RLock()
	src := *(ruc.localAddress)
	ruc.addrLock.RUnlock()
	return ruc.WriteToFrom(p, &src, addr)
}

// SetReadDeadline implements net.PacketConn interface
func (ruc *RUDPConn) SetReadDeadline(t time.Time) error {

	return ruc.conn.SetReadDeadline(t)
}

// SetWriteDeadline implements net.PacketConn interface
func (ruc *RUDPConn) SetWriteDeadline(t time.Time) error {
	return ruc.conn.SetWriteDeadline(t)
}

// SetDeadline implements net.PacketConn interface
func (ruc *RUDPConn) SetDeadline(t time.Time) error {

	return ruc.conn.SetDeadline(t)
}

// SetAddr set RUDPConn's UDP address to src
func (ruc *RUDPConn) SetAddr(src *net.UDPAddr) {
	ruc.addrLock.Lock()
	defer ruc.addrLock.Unlock()
	ruc.localAddress = src
}

func setPromisc(ifname string) error {
	intf, err := net.InterfaceByName(ifname)
	if err != nil {
		return fmt.Errorf("couldn't query interface %s: %s", ifname, err)
	}
	htons := func(data uint16) uint16 { return data<<8 | data>>8 }
	fd, err := unix.Socket(unix.AF_PACKET, unix.SOCK_RAW, int(htons(unix.ETH_P_ALL)))
	if err != nil {
		return fmt.Errorf("couldn't open packet socket: %s", err)
	}
	mreq := unix.PacketMreq{
		Ifindex: int32(intf.Index),
		Type:    unix.PACKET_MR_PROMISC,
	}

	opt := unix.PACKET_ADD_MEMBERSHIP
	return unix.SetsockoptPacketMreq(fd, unix.SOL_PACKET, opt, &mreq)
}

// RelayPacketStats is the PacketRelay's forwding stats;
// use atomic.LoadUint64 to read the values
type RelayPacketStats struct {
	// Tx is number of pkts sent successfully
	Tx *uint64
	// RxOffered is number of pkts relay get from interface
	RxOffered *uint64
	// RxInvalid is nunber of pkts relay get but ignored due to failed valid check
	RxInvalid *uint64
	// RxBufferFull is the number of pkts can't send to receiver's channel right away due to it is full
	RxBufferFull *uint64
	// RxMiss is the number of pkts relay can't find receiver
	RxMiss *uint64
	// Rx is the number of pkts relay successfully deliver to receiver
	Rx *uint64
	// RxNonHitMulticast is the number of multicast pkts that doesn't have direct receiver, but deliver to a multicast recevier
	RxNonHitMulticast *uint64
	// RxMulticastIgnored is the number of multicast pkts ignored
	RxMulticastIgnored *uint64
}

func newRelayPacketStats() *RelayPacketStats {
	rps := new(RelayPacketStats)
	rps.Tx = new(uint64)
	rps.RxOffered = new(uint64)
	rps.RxInvalid = new(uint64)
	rps.RxBufferFull = new(uint64)
	rps.RxMiss = new(uint64)
	rps.Rx = new(uint64)
	rps.RxNonHitMulticast = new(uint64)
	rps.RxMulticastIgnored = new(uint64)
	return rps
}

func (rps RelayPacketStats) String() string {
	rs := ""
	val := reflect.ValueOf(rps)
	for i := 0; i < val.NumField(); i++ {
		rs += fmt.Sprintf("%v:%v\n", val.Type().Field(i).Name, atomic.LoadUint64(val.FieldByIndex([]int{i}).Interface().(*uint64)))
		// rs += fmt.Sprintf("%v:%v\n", val.Type().Field(i).Name, atomic.LoadUint64(reflect.Indirect(val.FieldByIndex([]int{i})).Interface().(uint64)))
	}
	return rs
}

// buildPCAPFilterStrForEtherType return a PCAP filter string to filter
// all EtherType in etypes, include no tag, one tag and two tag
func buildPCAPFilterStrForEtherType(etypes []uint16) string {
	s := ""
	i := 0
	for _, t := range etypes {
		s += fmt.Sprintf("0x%x", t)
		if i < len(etypes)-1 {
			s += " or "
		}
		i++
	}
	//NOTE: it seems the order of these 2 parts are important, otherwise qinq won't be capatured
	return fmt.Sprintf("(ether proto %s) or  (vlan and ether proto %s)", s, s)
}

// setBPFFilter translates a BPF filter string into BPF RawInstruction and applies them.
func (rsr *RawSocketRelay) setBPFFilter(filter string) (err error) {
	rsr.log("set BPF filter to %v", filter)
	pcapBPF, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet, int(rsr.maxEtherFrameSize), filter)
	if err != nil {
		return err
	}
	bpfIns := []bpf.RawInstruction{}
	for _, ins := range pcapBPF {
		bpfIns2 := bpf.RawInstruction{
			Op: ins.Code,
			Jt: ins.Jt,
			Jf: ins.Jf,
			K:  ins.K,
		}
		bpfIns = append(bpfIns, bpfIns2)
	}
	// if relay.conn.SetBPF(bpfIns); err != nil {
	// 	return err
	// }
	return rsr.conn.SetBPF(bpfIns)
}
