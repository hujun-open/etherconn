/*EtherConn and RUDPConn are 1:1 mapping,which means two RUDPConn can't share same MAC+VLAN+EtherType combination;

SharedEtherConn and SharingRUDPConn solve this issue:

                                        L2Endpointkey-1
    interface <---> PacketRelay <----> SharedEtherConn <---> SharingRUDPConn (L4Recvkey-1)
                                                       <---> SharingRUDPConn (L4Recvkey-2)
                                                       <---> SharingRUDPConn (L4Recvkey-3)
                                        L2Endpointkey-2
                                <----> SharedEtherConn <---> SharingRUDPConn (L4Recvkey-4)
                                                       <---> SharingRUDPConn (L4Recvkey-5)
                                                       <---> SharingRUDPConn (L4Recvkey-6)

*/
package etherconn

import (
	"context"
	"encoding/binary"
	"fmt"

	// "log"
	"net"
	"sync"
	"time"
)

// L4RecvKey resprsents a Layer4 recv endpoint:
// [0:15] bytes is the IP address,
// [16] is the IP protocol,
// [17:18] is the port number, in big endian
type L4RecvKey [19]byte

// NewL4RecvKeyViaUDPAddr returns a L4RecvKey from a net.UDPAddr
func NewL4RecvKeyViaUDPAddr(uaddr *net.UDPAddr) (r L4RecvKey) {
	copy(r[:16], []byte(uaddr.IP.To16()))
	r[16] = 17
	binary.BigEndian.PutUint16(r[17:], uint16(uaddr.Port))
	return

}

// String returns string representation of the l4k;
// in format of "Addr:protocol:Port"
func (l4k L4RecvKey) String() string {
	// return fmt.Sprintf("%v", [19]byte(l4k))
	// newip := net.IP(l4k[:16])
	// if newip.To4() != nil {
	// 	newip = newip.To4()
	// }
	return fmt.Sprintf("%v#%d#%d", net.IP(l4k[:16]), l4k[16], binary.BigEndian.Uint16(l4k[17:]))

}

// SharedEtherConn could be mapped to multiple RUDPConn
type SharedEtherConn struct {
	econn                *EtherConn
	recvList             *chanMap
	perClntRecvChanDepth uint
	cancelFunc           context.CancelFunc
}

// SharedEtherConnOption is the option to customize new SharedEtherConnOption
type SharedEtherConnOption func(sec *SharedEtherConn)

// NewSharedEtherConn creates a new SharedEtherConn;
// mac is the SharedEtherConn's own MAC address;
// relay is the underlying PacketRelay;
// ecopts is a list of EtherConnOption that could be used to customized new SharedEtherConnOption,
// all currently defined EtherConnOption could also be used for SharedEtherConn.
// options is a list of SharedEtherConnOption, not used currently;
func NewSharedEtherConn(parentctx context.Context,
	mac net.HardwareAddr, relay PacketRelay,
	ecopts []EtherConnOption, options ...SharedEtherConnOption) *SharedEtherConn {
	r := new(SharedEtherConn)
	r.econn = NewEtherConn(mac, relay, ecopts...)
	r.recvList = newchanMap()
	r.perClntRecvChanDepth = DefaultPerClntRecvChanDepth
	for _, opt := range options {
		opt(r)
	}
	var ctx context.Context
	ctx, r.cancelFunc = context.WithCancel(parentctx)
	go r.recv(ctx)
	return r
}

// Close stop the SharedEtherConn
func (sec *SharedEtherConn) Close() {
	sec.cancelFunc()
}

// Register register a key, return following channels:
// torecvch is the channel which is used to store received packets has one of registered key in keys;
func (sec *SharedEtherConn) Register(k L4RecvKey) (torecvch chan *RelayReceival) {
	ch := make(chan *RelayReceival, sec.perClntRecvChanDepth)
	sec.recvList.Set(k, ch)
	return ch
}

// RegisterList register a set of keys, return following channels:
// torecvch is the channel which is used to store received packets has one of registered key in keys;
func (sec *SharedEtherConn) RegisterList(keys []L4RecvKey) (torecvch chan *RelayReceival) {
	ch := make(chan *RelayReceival, sec.perClntRecvChanDepth)
	list := make([]interface{}, len(keys))
	for i := range keys {
		list[i] = keys[i]
	}
	sec.recvList.SetList(list, ch)
	return ch
}

// WriteIPPktTo sends an IP packet to dstmac,
// with EtherConn's vlan encapsualtaion, if any;
func (sec *SharedEtherConn) WriteIPPktTo(p []byte, dstmac net.HardwareAddr) (int, error) {
	return sec.econn.WriteIPPktTo(p, dstmac)
}

// WriteIPPktToFrom is same as WriteIPPktTo beside send pkt with srcmac
func (sec *SharedEtherConn) WriteIPPktToFrom(p []byte, srcmac, dstmac net.HardwareAddr, vlans VLANs) (int, error) {
	return sec.econn.WriteIPPktToFrom(p, srcmac, dstmac, vlans)
}

// WritePktTo sends an Ethernet payload, along with specified EtherType,
// the pkt will be sent to dstmac, along with EtherConn.L2EP.VLANs.
func (sec *SharedEtherConn) WritePktTo(p []byte, etype uint16, dstmac net.HardwareAddr) (int, error) {
	return sec.econn.WritePktTo(p, etype, dstmac)
}

// WritePktToFrom is same as WritePktTo except with srcmac
func (sec *SharedEtherConn) WritePktToFrom(p []byte, etype uint16, srcmac, dstmac net.HardwareAddr, vlans VLANs) (int, error) {
	return sec.econn.WritePktToFrom(p, etype, srcmac, dstmac, vlans)
}

func (sec *SharedEtherConn) recv(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case receival := <-sec.econn.recvChan:
			if ch := sec.recvList.Get(receival.GetL4Key()); ch != nil {
				//found registed channel
				go func() {
					for {
						select {
						case ch <- receival:
							return
						default:
							//channel is full, remove oldest pkt
							<-ch
						}
					}
				}()
			}
		}
	}
}

// SharingRUDPConn is the UDP connection could share same SharedEtherConn;
type SharingRUDPConn struct {
	udpconn          *RUDPConn
	conn             *SharedEtherConn
	readDeadline     time.Time
	readDeadlineLock *sync.RWMutex
	recvChan         chan *RelayReceival
}

// SharingRUDPConnOptions is is the option to customize new SharingRUDPConn
type SharingRUDPConnOptions func(srudpc *SharingRUDPConn)

// NewSharingRUDPConn creates a new SharingRUDPConn,
// src is the string represents its UDP Address as format supported by net.ResolveUDPAddr().
// c is the underlying SharedEtherConn,
// roptions is a list of RUDPConnOptions that use for customization,
// supported are: WithResolveNextHopMacFunc;
// note unlike RUDPConn, SharingRUDPConn doesn't support acceptting pkt is not destinated to own address
func NewSharingRUDPConn(src string, c *SharedEtherConn, roptions []RUDPConnOption, options ...SharingRUDPConnOptions) (*SharingRUDPConn, error) {
	r := new(SharingRUDPConn)
	var err error
	if r.udpconn, err = NewRUDPConn(src, nil, roptions...); err != nil {
		return nil, err
	}
	r.conn = c
	r.readDeadlineLock = new(sync.RWMutex)
	r.recvChan = c.Register(NewL4RecvKeyViaUDPAddr(r.udpconn.localAddress))
	for _, opt := range options {
		opt(r)
	}
	return r, nil

}

// ReadFrom implment net.PacketConn interface, it returns UDP payload;
func (sruc *SharingRUDPConn) ReadFrom(p []byte) (int, net.Addr, error) {
	sruc.readDeadlineLock.RLock()
	deadline := sruc.readDeadline
	sruc.readDeadlineLock.RUnlock()
	d := time.Until(deadline)
	timeout := false
	var receival *RelayReceival
	if d > 0 {
		select {
		case <-time.After(d):
			timeout = true
		case receival = <-sruc.recvChan:
		}
	} else {
		receival = <-sruc.recvChan
	}
	if receival == nil {
		if timeout {
			return 0, nil, ErrTimeOut
		}
		return 0, nil, fmt.Errorf("failed to read from SharedEtherConn")
	}
	copy(p, receival.TransportPayloadBytes)
	return len(receival.TransportPayloadBytes), &net.UDPAddr{IP: receival.RemoteIP, Port: int(receival.RemotePort), Zone: "udp"}, nil
}

// WriteTo implements net.PacketConn interface, it sends UDP payload;
// This function adds UDP and IP header, and uses sruc's resolve function
// to get nexthop's MAC address, and use underlying SharedEtherConn to send IP packet,
// with SharedEtherConn's Ethernet encapsulation, to nexthop MAC address;
// by default ResolveNexhopMACWithBrodcast is used for nexthop mac resolvement
func (sruc *SharingRUDPConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	pktbuf, dstip := sruc.udpconn.buildPkt(p, sruc.udpconn.LocalAddr(), addr)
	nexthopMAC := sruc.udpconn.resolveNexthopFunc(dstip)
	_, err := sruc.conn.WriteIPPktTo(pktbuf, nexthopMAC)
	if err != nil {
		return 0, err
	}
	return len(p), nil
}

// Close implements net.PacketConn interface, it closes underlying EtherConn
func (sruc *SharingRUDPConn) Close() error {
	return nil
}

// LocalAddr implements net.PacketConn interface, it returns its UDPAddr
func (sruc *SharingRUDPConn) LocalAddr() net.Addr {
	return sruc.udpconn.LocalAddr()
}

// SetReadDeadline implements net.PacketConn interface
func (sruc *SharingRUDPConn) SetReadDeadline(t time.Time) error {
	sruc.readDeadlineLock.Lock()
	defer sruc.readDeadlineLock.Unlock()
	sruc.readDeadline = t
	return nil
}

// SetWriteDeadline implements net.PacketConn interface
func (sruc *SharingRUDPConn) SetWriteDeadline(t time.Time) error {
	return sruc.conn.econn.SetWriteDeadline(t)
}

// SetDeadline implements net.PacketConn interface
func (sruc *SharingRUDPConn) SetDeadline(t time.Time) error {
	sruc.SetReadDeadline(t)
	sruc.SetWriteDeadline(t)
	return nil
}
