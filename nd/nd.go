package nd

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type SendPktFunc func(p []byte, dstmac net.HardwareAddr) (int, error)
type LoggerFunc func(format string, a ...interface{})
type NeiState uint32

const (
	StateStale NeiState = iota
	StateProbing
)
const (
	DefaultLifeTime      = time.Hour
	DefaultRecvChanDepth = 1024
	DefaultProbeInterval = 5 * time.Second
)

var (
	BroadCastMAC = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
)

type Neighbor struct {
	IPAddr        netip.Addr
	HWAddr        net.HardwareAddr
	Expiration    time.Time
	lastProbeSent time.Time
}

// GetLLAFromMAC returns an IPv6 LLA from mac, according to the alg described in Appendix A of RFC4291
func GetLLAFromMAC(mac net.HardwareAddr) netip.Addr {
	var r = [16]byte{0xFE, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	copy(r[13:16], mac[3:6])
	copy(r[11:13], []byte{0xff, 0xfe})
	copy(r[8:11], mac[:3])
	r[0] = r[0] | 0b00000010
	return netip.AddrFrom16(r)
}

func GetSolicitedNodeMulticastAddr(addr netip.Addr) netip.Addr {
	var r = [16]byte{0xFF, 0x02, 0, 0, 0, 0, 1, 0xFF, 0, 0, 0}
	if !addr.Is6() {
		return netip.Addr{}
	}
	copy(r[13:16], addr.AsSlice()[13:16])
	return netip.AddrFrom16(r)
}

func GetMulticastMACfromIPv6Addr(addr netip.Addr) net.HardwareAddr {
	var r = []byte{0x33, 0x33, 0, 0, 0, 0}
	copy(r[2:6], addr.AsSlice()[12:16])
	return r
}

// IPv6ND does two jobs: 1. respond to NS for local address; 2. resolve IPv6 to MAC
type IPv6ND struct {
	neiList                            map[netip.Addr]*Neighbor
	listLock                           *sync.RWMutex
	liftime                            time.Duration
	debug                              bool
	pktSendF                           SendPktFunc
	recvProcessErrCount, probeErrCount uint
	recvCh                             chan []byte //recevied ICMPv6 packet, IP pkt
	logf                               LoggerFunc
	activeProbe                        bool //probe for unknown IP if this is true
	ownMAC                             net.HardwareAddr
	ownIP                              netip.Addr
	probeInterval                      time.Duration
}

// NewIPv6ND creates a new IPv6ND, with following parameters:
// ownmac, ownip is used as source MAC/IP for egress NS;
// life specifies how long an existing entry need to be re-probed;
// recvchandepth is the depth of receives msg channel;
// logf is the logging function;
// if probe is true, then system will send probe for unresolved IP, probeinterval is the retry interval for probe;
func NewIPv6ND(ctx context.Context,
	ownmac net.HardwareAddr,
	ownip netip.Addr,
	recvc chan []byte,
	sendf SendPktFunc,
	life time.Duration, recvchandepth int,
	logf LoggerFunc, probe bool, probeinterval time.Duration) *IPv6ND {
	r := new(IPv6ND)
	r.neiList = make(map[netip.Addr]*Neighbor)
	r.liftime = life
	r.listLock = new(sync.RWMutex)
	r.recvCh = recvc
	r.logf = logf
	r.pktSendF = sendf
	r.activeProbe = probe
	r.ownMAC = ownmac
	r.ownIP = ownip
	r.probeInterval = probeinterval
	go r.recv(ctx)
	go r.houseKeeping(ctx)
	return r
}

// NewDefaultIPv6ND creats a new IPv6ND with default settings
func NewDefaultIPv6ND(ctx context.Context, ownmac net.HardwareAddr,
	ownip netip.Addr, recvc chan []byte, sendf SendPktFunc) *IPv6ND {
	logger := log.New(os.Stdout, "IPv6ND", log.Ldate|log.Ltime|log.Lshortfile)
	return NewIPv6ND(ctx, ownmac, ownip, recvc, sendf,
		DefaultLifeTime, DefaultRecvChanDepth,
		logger.Printf, true, DefaultProbeInterval)
}

func (v6nd *IPv6ND) sendNA(reqsrc, target net.IP, targetmac, dstmac net.HardwareAddr) (err error) {
	resp := &layers.ICMPv6NeighborAdvertisement{
		TargetAddress: target,
		Flags:         0b01000000,
		Options: []layers.ICMPv6Option{
			{
				Type: layers.ICMPv6OptTargetAddress,
				Data: []byte(targetmac),
			},
		},
	}
	respicmp6Layer := &layers.ICMPv6{
		TypeCode: layers.CreateICMPv6TypeCode(136, 0),
	}

	buf := gopacket.NewSerializeBuffer()
	iplayer := &layers.IPv6{
		Version:    6,
		SrcIP:      target,
		DstIP:      reqsrc,
		NextHeader: layers.IPProtocol(58),
		HopLimit:   255, //must be 255, otherwise won't be accepted
	}
	respicmp6Layer.SetNetworkLayerForChecksum(iplayer)
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	gopacket.SerializeLayers(buf, opts,
		iplayer,
		respicmp6Layer,
		resp)

	_, err = v6nd.pktSendF(buf.Bytes(), dstmac)
	return err
}

func (v6nd *IPv6ND) log(format string, a ...interface{}) {
	if v6nd.debug {
		v6nd.logf(format, a...)
	}
}

// Register adds a IP addr and MAC pairing to local list
func (v6nd *IPv6ND) Register(addr netip.Addr, mac net.HardwareAddr) {
	v6nd.listLock.Lock()
	newEntry := &Neighbor{
		IPAddr:        addr,
		HWAddr:        mac,
		Expiration:    time.Now().Add(v6nd.liftime),
		lastProbeSent: time.Time{},
	}
	if nei, ok := v6nd.neiList[addr]; ok {
		newEntry.lastProbeSent = nei.lastProbeSent
	}
	v6nd.neiList[addr] = newEntry
	v6nd.listLock.Unlock()
}

// GetRecvChan returns the channel used to receve ICMPv6 packet, must be an IP packet.
func (v6nd *IPv6ND) GetRecvChan() chan []byte {
	return v6nd.recvCh
}

// GetList returns current list as a slice of *Neighbor
func (v6nd *IPv6ND) GetList() (rlist []*Neighbor) {
	v6nd.listLock.RLock()
	defer v6nd.listLock.RUnlock()
	for _, nei := range v6nd.neiList {
		rlist = append(rlist, nei)
	}
	return
}

func (v6nd *IPv6ND) probe(nei *Neighbor) (err error) {
	resp := &layers.ICMPv6NeighborSolicitation{
		TargetAddress: nei.IPAddr.AsSlice(),
		Options: []layers.ICMPv6Option{
			{
				Type: layers.ICMPv6OptSourceAddress,
				Data: []byte(v6nd.ownMAC),
			},
		},
	}
	respicmp6Layer := &layers.ICMPv6{
		TypeCode: layers.CreateICMPv6TypeCode(135, 0),
	}

	buf := gopacket.NewSerializeBuffer()
	iplayer := &layers.IPv6{
		Version:    6,
		SrcIP:      v6nd.ownIP.AsSlice(),
		DstIP:      GetSolicitedNodeMulticastAddr(nei.IPAddr).AsSlice(),
		NextHeader: layers.IPProtocol(58),
		HopLimit:   255, //must be 255, otherwise won't be accepted
	}
	respicmp6Layer.SetNetworkLayerForChecksum(iplayer)
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	gopacket.SerializeLayers(buf, opts,
		iplayer,
		respicmp6Layer,
		resp)

	_, err = v6nd.pktSendF(buf.Bytes(), GetMulticastMACfromIPv6Addr(nei.IPAddr))
	return err

}

func (v6nd *IPv6ND) houseKeeping(ctx context.Context) {
	tikcer := time.NewTicker(time.Second)
	for {
		select {
		case <-ctx.Done():
			return
		case <-tikcer.C:
			for _, nei := range v6nd.GetList() {
				if nei.HWAddr == nil || nei.Expiration.Before(time.Now()) {
					//send probe
					if nei.lastProbeSent.Add(v6nd.probeInterval).Before(time.Now()) {
						go func() {
							err := v6nd.probe(nei)
							if err != nil {
								v6nd.log("failed to send probe, %v", err)
								v6nd.probeErrCount++
							}
						}()
						nei.lastProbeSent = time.Now()
					}
				}
			}
		}
	}
}

//pkt is should be an IP packet
func (v6nd *IPv6ND) handleNDPkt(pkt gopacket.Packet) error {
	var mac net.HardwareAddr = nil
	var addr, target netip.Addr
	var icmp6Layer gopacket.Layer
	var found_mac bool
	var ok bool
	var nei *Neighbor
	defer func() {
		if found_mac && addr.IsValid() {
			v6nd.Register(addr, mac)
		}
	}()
	if icmp6Layer = pkt.Layer(layers.LayerTypeICMPv6NeighborSolicitation); icmp6Layer != nil {
		//NS
		if v6l := pkt.Layer(layers.LayerTypeIPv6); v6l != nil {
			req := icmp6Layer.(*layers.ICMPv6NeighborSolicitation)
			//update local list
			if addr, ok = netip.AddrFromSlice(v6l.(*layers.IPv6).SrcIP); ok {
				//looking for source link addr
				for _, opt := range req.Options {
					if opt.Type == layers.ICMPv6OptSourceAddress {
						mac = make([]byte, 6)
						copy(mac, opt.Data[:6])
						found_mac = true
						break
					}
				}
			}
			//to see if the NS is target on local address, if yes, send NA back
			if target, ok = netip.AddrFromSlice(req.TargetAddress); ok {
				//valid target
				v6nd.listLock.RLock()
				if nei, ok = v6nd.neiList[target]; ok {
					v6nd.listLock.RUnlock()
					//found target in local list
					dmac := BroadCastMAC
					if mac != nil {
						dmac = mac
					}
					return v6nd.sendNA(v6l.(*layers.IPv6).SrcIP, req.TargetAddress, nei.HWAddr, dmac)
				}
				v6nd.listLock.RUnlock()

			}
		}
	} else if icmp6Layer = pkt.Layer(layers.LayerTypeICMPv6NeighborAdvertisement); icmp6Layer != nil {
		//NA
		adv := icmp6Layer.(*layers.ICMPv6NeighborAdvertisement)
		if addr, ok = netip.AddrFromSlice(adv.TargetAddress); !ok {
			return fmt.Errorf("failed to find target IP address in NA")
		}
		for _, opt := range adv.Options {
			if opt.Type == layers.ICMPv6OptTargetAddress {
				mac = make([]byte, 6)
				copy(mac, opt.Data[:6])
				found_mac = true
				break
			}
		}

	}

	return nil
}

//Resolve resolve addr to mac based on local list, if not found and activeProbe is true, then send probe
func (v6nd *IPv6ND) Resolve(addr netip.Addr) net.HardwareAddr {
	v6nd.listLock.RLock()
	if nei, ok := v6nd.neiList[addr]; ok {
		v6nd.listLock.RUnlock()
		return nei.HWAddr
	}
	v6nd.listLock.RUnlock()
	if v6nd.activeProbe {
		nei := &Neighbor{
			HWAddr:        nil,
			IPAddr:        addr,
			lastProbeSent: time.Time{},
			Expiration:    time.Time{},
		}
		v6nd.listLock.Lock()
		v6nd.neiList[addr] = nei
		v6nd.listLock.Unlock()
	}
	return nil
}

func (v6nd *IPv6ND) recv(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case pkt := <-v6nd.recvCh:
			gpkt := gopacket.NewPacket(pkt, layers.LayerTypeIPv6, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
			go func() {
				err := v6nd.handleNDPkt(gpkt)
				if err != nil {
					v6nd.log("failed to process %v, %v", gpkt, err)
					v6nd.recvProcessErrCount++
				}
			}()
		}
	}
}
