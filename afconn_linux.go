package etherconn

import (
	"context"
	"errors"
	"fmt"
	"net"

	"github.com/google/gopacket"
	"github.com/google/gopacket/afpacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"golang.org/x/net/bpf"
	"golang.org/x/sys/unix"
)

type afConn struct {
	*afpacket.TPacket
	maxFrameSize int
}

func newAfConn(maxEtherFrameSize int, others ...any) (*afConn, error) {
	r := &afConn{maxFrameSize: maxEtherFrameSize}
	var err error
	r.TPacket, err = afpacket.NewTPacket(others...)
	return r, err
}
func (afconn *afConn) CloseMe() {
	afconn.Close()
}

func (afconn *afConn) ReadPacketData() ([]byte, gopacket.CaptureInfo, error) {
	buf := make([]byte, afconn.maxFrameSize)
	ci, err := afconn.ReadPacketDataTo(buf)
	return buf, ci, err
}

func (afconn *afConn) setBPFFilter(filter string) error {
	pcapBPF, err := pcap.CompileBPFFilter(layers.LinkTypeEthernet, afconn.maxFrameSize, filter)
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
	return afconn.SetBPF(bpfIns)

}

func (afconn *afConn) isTimeout(err error) bool {
	return errors.Is(err, afpacket.ErrTimeout)
}

func (afconn *afConn) relayType() RelayType {
	return RelayTypeAFP
}

func (afconn *afConn) getRawStats() any {
	_, rawstat, err := afconn.SocketStats()
	if err != nil {
		return nil
	}
	return rawstat
}

func getVLANsFromAncDataAFPkt(existList []uint16, auxdata []interface{}) []uint16 {
	var r []uint16
	for _, adata := range auxdata {
		if v, ok := adata.(afpacket.AncillaryVLAN); ok {
			r = append([]uint16{uint16(v.VLAN)}, existList...)
		}
	}
	return r
}

func NewRawSocketRelay(parentctx context.Context, ifname string, options ...RelayOption) (*RawSocketRelay, error) {
	//NOTE:interface must be put in promisc mode, otherwise only pkt with real mac will be received
	err := SetPromisc(ifname)
	if err != nil {
		return nil, fmt.Errorf("failed to set %v to Promisc mode,%w", ifname, err)

	}
	conn, err := newAfConn(
		afpacket.DefaultFrameSize,
		afpacket.OptInterface(ifname),
		afpacket.OptBlockSize(afpacket.DefaultBlockSize),
		afpacket.OptNumBlocks(afpacket.DefaultNumBlocks),
		afpacket.OptAddVLANHeader(false),
		afpacket.OptPollTimeout(DefaultRelayRecvTimeout),
		afpacket.SocketRaw,
		afpacket.TPacketVersionHighestAvailable)
	if err != nil {
		return nil, fmt.Errorf("failed to create rawsocketrelay,%w", err)
	}
	return NewRawSocketRelayWithRelayConn(parentctx, ifname, conn, options...)

}

// SetPromisc put the interface in Promisc mode
func SetPromisc(ifname string) error {
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
