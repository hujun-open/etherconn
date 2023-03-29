package etherconn

import (
	"context"
	"fmt"
	"time"

	"github.com/google/gopacket/pcap"
)

type PcapConn struct {
	*pcap.Handle
}

// GetIfNameViaDesc returns interface name via its description,
// this could be used on windows to get the interface name
func GetIfNameViaDesc(desc string) (string, error) {
	iflist, err := pcap.FindAllDevs()
	if err != nil {
		return "", fmt.Errorf("failed to get interface list, %w", err)
	}
	for _, intf := range iflist {
		if intf.Description == desc {
			return intf.Name, nil
		}
	}
	return "", fmt.Errorf("%v not found", desc)
}

// NewPcapConn creates a new PcapRelay instances for specified ifname.
// Note: on windows, the ifname is the "\Device\NPF_xxxx"
func NewPcapConn(ifname string) (*PcapConn, error) {
	var err error
	r := &PcapConn{}
	r.Handle, err = pcap.OpenLive(ifname,
		DefaultMaxEtherFrameSize,
		true, time.Millisecond)
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (pconn *PcapConn) getRawStats() any {
	stats, _ := pconn.Stats()
	return stats
}

func (pconn *PcapConn) CloseMe() {
	pconn.WritePacketData([]byte{1, 2, 3, 4, 5, 5, 6, 6, 8})
	pconn.Close()
}

func (pconn *PcapConn) setBPFFilter(filter string) error {
	return pconn.SetBPFFilter(filter)
}
func (pconn *PcapConn) relayType() RelayType {
	return RelayTypePCAP
}
func (pconn *PcapConn) isTimeout(err error) bool {
	if e, ok := err.(pcap.NextError); !ok {
		return false
	} else {
		return e == pcap.NextErrorTimeoutExpired
	}
}

func NewRawSocketRelayPcap(parentctx context.Context, ifname string, options ...RelayOption) (*RawSocketRelay, error) {
	conn, err := NewPcapConn(ifname)
	if err != nil {
		return nil, fmt.Errorf("failed to create rawsocketrelay,%w", err)
	}
	return NewRawSocketRelayWithRelayConn(parentctx, ifname, conn, options...)

}
