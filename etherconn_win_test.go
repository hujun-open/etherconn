//go:build windows
// +build windows

// etherconn_test

/*
Test setup reuqirements:
  - two interfaces name specified by argument testifA and testifB, these two interfaces are connected together
*/
package etherconn_test

import (
	"context"
	"fmt"

	"github.com/hujun-open/etherconn"
)

const (
	testifA = `\Device\NPF_{E8EE7758-DA9A-417A-BB29-3FAAF086DAAB}` //hjsw2
	testifB = `\Device\NPF_{85419E30-E13A-4109-BBA5-C20F2AF23C02}` //hjsw
)

func testCreateVETHLink(a, b string) error {
	return nil
}

func getRawRelay(ctx context.Context, relayType etherconn.RelayType, ifname string, mods ...etherconn.RelayOption) (*etherconn.RawSocketRelay, error) {
	return etherconn.NewRawSocketRelayPcap(context.Background(), ifname, mods...)
}

func getPKTRelay(ctx context.Context, rtype etherconn.RelayType, ifname string, defaultconn, defualtconnmirror bool) (etherconn.PacketRelay, error) {
	if rtype == etherconn.RelayTypePCAP {
		mods := []etherconn.RelayOption{
			etherconn.WithDebug(true),
			etherconn.WithBPFFilter(""),
		}
		if defaultconn {
			mods = append(mods, etherconn.WithDefaultReceival(defualtconnmirror))
		}
		return getRawRelay(ctx, rtype, ifname, mods...)
	}
	return nil, fmt.Errorf("only pcap relay is supported on windows")
}
