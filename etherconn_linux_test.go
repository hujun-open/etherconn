//go:build linux
// +build linux

// etherconn_test

/*
Test setup reuqirements:
  - two interfaces name specified by argument testifA and testifB, these two interfaces are connected together
*/
package etherconn_test

import (
	"context"
	"fmt"

	"github.com/google/gopacket/layers"
	"github.com/hujun-open/etherconn"
	"github.com/vishvananda/netlink"
)

const (
	testifA = "A"
	testifB = "B"
)

func testCreateVETHLink(a, b string) error {
	linka := new(netlink.Veth)
	linka.Name = a
	linka.PeerName = b
	netlink.LinkDel(linka)
	err := netlink.LinkAdd(linka)
	if err != nil {
		return err
	}
	linkb, err := netlink.LinkByName(b)
	if err != nil {
		return err
	}
	err = netlink.LinkSetUp(linka)
	if err != nil {
		return err
	}
	err = netlink.LinkSetUp(linkb)
	if err != nil {
		return err
	}
	return nil
}

func getRawRelay(ctx context.Context, relayType etherconn.RelayType, ifname string, mods ...etherconn.RelayOption) (*etherconn.RawSocketRelay, error) {

	switch relayType {
	case etherconn.RelayTypePCAP:
		return etherconn.NewRawSocketRelayPcap(context.Background(), ifname, mods...)
	case etherconn.RelayTypeAFP:
		return etherconn.NewRawSocketRelay(context.Background(), ifname, mods...)

	}
	return nil, fmt.Errorf("%v is not a supported raw relay type", relayType)
}

func getPKTRelay(ctx context.Context, rtype etherconn.RelayType, ifname string, defaultconn, defualtconnmirror bool) (etherconn.PacketRelay, error) {
	switch rtype {
	case etherconn.RelayTypeAFP, etherconn.RelayTypePCAP:
		mods := []etherconn.RelayOption{
			etherconn.WithDebug(true),
		}
		if defaultconn {
			mods = append(mods, etherconn.WithDefaultReceival(defualtconnmirror))
		}
		return getRawRelay(ctx, rtype, ifname, mods...)
	case etherconn.RelayTypeXDP:
		mods := []etherconn.XDPRelayOption{
			etherconn.WithQueueID([]int{0}),
			etherconn.WithXDPUMEMNumOfTrunk(32768),
			// etherconn.WithXDPPerClntRecvChanDepth(32768),
			etherconn.WithXDPDebug(true),
			etherconn.WithXDPUMEMChunkSize(4096),
			etherconn.WithXDPEtherTypes([]uint16{
				uint16(layers.EthernetTypeIPv4),
				uint16(layers.EthernetTypeIPv6),
			}),
		}
		if defaultconn {
			mods = append(mods, etherconn.WithXDPDefaultReceival(defualtconnmirror))
		}
		return etherconn.NewXDPRelay(ctx, ifname, mods...)
	}
	return nil, fmt.Errorf("unknown relay type %v", rtype)
}
