// etherconn_test

/*
Test setup reuqirements:
  - two interfaces name specified by argument testifA and testifB, these two interfaces are connected together
*/
package etherconn_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"fmt"
	mathrand "math/rand"
	"net"
	"runtime"
	"testing"
	"time"

	"github.com/hujun-open/etherconn"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/hujun-open/myaddr"
)

type testEtherConnEndpoint struct {
	mac               net.HardwareAddr
	vlans             []*etherconn.VLAN
	ETypes            []uint16
	defaultConn       bool
	defaultConnMirror bool
	dstMACFlag        int
	recvMulticast     bool
	filter            string
}

type testEtherConnSingleCase struct {
	A          testEtherConnEndpoint
	B          testEtherConnEndpoint
	C          testEtherConnEndpoint //used only in testing default mirroring
	shouldFail bool
}

type testRUDPConnSingleCase struct {
	AEther     testEtherConnEndpoint
	BEther     testEtherConnEndpoint
	AIP        net.IP
	APort      int
	BIP        net.IP
	BPort      int
	shouldFail bool
}

// testGenDummyIPbytes return a dummy IP packet slice
func testGenDummyIPbytes(length int, v4 bool) []byte {
	payload := make([]byte, length)
	rand.Read(payload)
	buf := gopacket.NewSerializeBuffer()
	var iplayer gopacket.SerializableLayer
	udplayer := &layers.UDP{
		SrcPort: layers.UDPPort(3333),
		DstPort: layers.UDPPort(4444),
	}
	if v4 {
		srcip := make([]byte, 4)
		rand.Read(srcip)
		dstip := make([]byte, 4)
		rand.Read(dstip)
		iplayer = &layers.IPv4{
			Version:  4,
			SrcIP:    net.IP(srcip),
			DstIP:    net.IP(dstip),
			Protocol: layers.IPProtocol(17),
			TTL:      16,
		}
		udplayer.SetNetworkLayerForChecksum(iplayer.(*layers.IPv4))
	} else {
		srcip := make([]byte, 16)
		rand.Read(srcip)
		dstip := make([]byte, 16)
		rand.Read(dstip)
		iplayer = &layers.IPv6{
			Version:    6,
			SrcIP:      net.IP(srcip),
			DstIP:      net.IP(dstip),
			NextHeader: layers.IPProtocol(17),
			HopLimit:   16,
		}
		udplayer.SetNetworkLayerForChecksum(iplayer.(*layers.IPv6))
	}
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	gopacket.SerializeLayers(buf, opts,
		iplayer,
		udplayer,
		gopacket.Payload(payload))
	return buf.Bytes()

}

const (
	macTestCorrect = iota
	macTestBD
	macTestWrong
)

// checkEP check if rep matches with ec
func checkEP(rep *etherconn.L2Endpoint, ec *etherconn.EtherConn) error {
	ecaddr := ec.LocalAddr()
	if rep.HwAddr.String() != ecaddr.HwAddr.String() {
		return fmt.Errorf("ep mac addr %v is different from econn's mac %v",
			rep.HwAddr.String(), ecaddr.HwAddr.String())
	}
	if fmt.Sprintf("%X", rep.VLANs) != fmt.Sprintf("%X", ecaddr.VLANs) {
		return fmt.Errorf("ep vlan %v is different from econn's vlan %v",
			rep.VLANs, ecaddr.VLANs)
	}
	found := false
	for _, et := range ec.GetEtherTypes() {
		if et == rep.Etype {
			found = true
			break
		}
	}
	if !found {
		return fmt.Errorf("ep ethertype %d is not in econn's list %v", rep.Etype, ec.GetEtherTypes())
	}
	return nil
}

func TestEtherConn(t *testing.T) {
	testCaseList := []testEtherConnSingleCase{
		//0 good case, no Q
		{
			A: testEtherConnEndpoint{
				mac:   net.HardwareAddr{0x14, 0x11, 0x11, 0x11, 0x11, 0x1},
				vlans: []*etherconn.VLAN{},
			},
			B: testEtherConnEndpoint{
				mac:   net.HardwareAddr{0x14, 0x11, 0x11, 0x11, 0x11, 0x2},
				vlans: []*etherconn.VLAN{},
			},
		},
		//1 good case, dot1q
		{
			A: testEtherConnEndpoint{
				mac: net.HardwareAddr{0x14, 0x11, 0x11, 0x11, 0x11, 0x1},
				vlans: []*etherconn.VLAN{
					{
						ID:        100,
						EtherType: 0x8100,
					},
				},
			},
			B: testEtherConnEndpoint{
				mac: net.HardwareAddr{0x14, 0x11, 0x11, 0x11, 0x11, 0x2},
				vlans: []*etherconn.VLAN{
					{
						ID:        100,
						EtherType: 0x8100,
					},
				},
			},
		},
		//2 good case, qinq
		{
			A: testEtherConnEndpoint{
				mac: net.HardwareAddr{0x14, 0x11, 0x11, 0x11, 0x11, 0x1},
				vlans: []*etherconn.VLAN{
					{
						ID:        100,
						EtherType: 0x8100,
					},
					{
						ID:        222,
						EtherType: 0x8100,
					},
				},
			},
			B: testEtherConnEndpoint{
				mac: net.HardwareAddr{0x14, 0x11, 0x11, 0x11, 0x11, 0x2},
				vlans: []*etherconn.VLAN{
					{
						ID:        100,
						EtherType: 0x8100,
					},
					{
						ID:        222,
						EtherType: 0x8100,
					},
				},
			},
		},
		//3 negtive case, blocked by filter
		{
			A: testEtherConnEndpoint{
				mac: net.HardwareAddr{0x14, 0x11, 0x11, 0x11, 0x11, 0x1},
				vlans: []*etherconn.VLAN{
					{
						ID:        100,
						EtherType: 0x8100,
					},
					{
						ID:        222,
						EtherType: 0x8100,
					},
				},
			},
			B: testEtherConnEndpoint{
				mac: net.HardwareAddr{0x14, 0x11, 0x11, 0x11, 0x11, 0x2},
				vlans: []*etherconn.VLAN{
					{
						ID:        100,
						EtherType: 0x8100,
					},
					{
						ID:        222,
						EtherType: 0x8100,
					},
				},
				filter: "vlan 333",
			},
			shouldFail: true,
		},

		//4 negative case, different vlan
		{
			A: testEtherConnEndpoint{
				mac: net.HardwareAddr{0x12, 0x11, 0x11, 0x11, 0x11, 0x1},
				vlans: []*etherconn.VLAN{
					{
						ID:        100,
						EtherType: 0x8100,
					},
				},
			},
			B: testEtherConnEndpoint{
				mac: net.HardwareAddr{0x12, 0x11, 0x11, 0x11, 0x11, 0x2},
				vlans: []*etherconn.VLAN{
					{
						ID:        101,
						EtherType: 0x8100,
					},
				},
			},
			shouldFail: true,
		},

		//5 negative case, wrong mac
		{
			A: testEtherConnEndpoint{
				mac: net.HardwareAddr{0x12, 0x11, 0x11, 0x11, 0x11, 0x1},
				vlans: []*etherconn.VLAN{
					{
						ID:        100,
						EtherType: 0x8100,
					},
				},
				dstMACFlag: macTestWrong,
			},
			B: testEtherConnEndpoint{
				mac: net.HardwareAddr{0x12, 0x11, 0x11, 0x11, 0x11, 0x2},
				vlans: []*etherconn.VLAN{
					{
						ID:        100,
						EtherType: 0x8100,
					},
				},
			},
			shouldFail: true,
		},

		//6 send to broadcast good case, even recv has wrong vlan id
		{
			A: testEtherConnEndpoint{
				mac: net.HardwareAddr{0x12, 0x11, 0x11, 0x11, 0x11, 0x1},
				vlans: []*etherconn.VLAN{
					{
						ID:        100,
						EtherType: 0x8100,
					},
				},
				dstMACFlag: macTestBD,
			},
			B: testEtherConnEndpoint{
				mac: net.HardwareAddr{0x12, 0x11, 0x11, 0x11, 0x11, 0x2},
				vlans: []*etherconn.VLAN{
					{
						ID:        101,
						EtherType: 0x8100,
					},
				},
				recvMulticast: true,
			},
			shouldFail: false,
		},

		//7 send to broadcast negative case, recv doesn't accept multicast
		{
			A: testEtherConnEndpoint{
				mac: net.HardwareAddr{0x12, 0x11, 0x11, 0x11, 0x11, 0x1},
				vlans: []*etherconn.VLAN{
					{
						ID:        100,
						EtherType: 0x8100,
					},
				},
				dstMACFlag: macTestBD,
			},
			B: testEtherConnEndpoint{
				mac: net.HardwareAddr{0x12, 0x11, 0x11, 0x11, 0x11, 0x2},
				vlans: []*etherconn.VLAN{
					{
						ID:        101,
						EtherType: 0x8100,
					},
				},
				recvMulticast: false,
			},
			shouldFail: true,
		},

		//8 default receive case, no mirroring, no matching vlan&mac
		{
			A: testEtherConnEndpoint{
				mac: net.HardwareAddr{0x12, 0x11, 0x11, 0x11, 0x11, 0x1},
				vlans: []*etherconn.VLAN{
					{
						ID:        100,
						EtherType: 0x8100,
					},
				},
				dstMACFlag: macTestWrong,
			},
			B: testEtherConnEndpoint{
				defaultConn: true,
				mac:         net.HardwareAddr{0x12, 0x11, 0x11, 0x11, 0x11, 0x2},
				vlans: []*etherconn.VLAN{
					{
						ID:        101,
						EtherType: 0x8100,
					},
				},
				recvMulticast: false,
			},
		},
		//default receive case, mirroring, no matching vlan&mac
		{
			A: testEtherConnEndpoint{
				mac: net.HardwareAddr{0x12, 0x11, 0x11, 0x11, 0x11, 0x1},
				vlans: []*etherconn.VLAN{
					{
						ID:        100,
						EtherType: 0x8100,
					},
				},
				dstMACFlag: macTestCorrect,
			},
			B: testEtherConnEndpoint{
				defaultConn:       true,
				ETypes:            []uint16{1},
				defaultConnMirror: true,
				mac:               net.HardwareAddr{0x12, 0x11, 0x11, 0x11, 0x11, 0x2},
				vlans: []*etherconn.VLAN{
					{
						ID:        101,
						EtherType: 0x8100,
					},
				},
				recvMulticast: false,
			},
			C: testEtherConnEndpoint{
				mac: net.HardwareAddr{0x12, 0x11, 0x11, 0x11, 0x11, 0x2},
				vlans: []*etherconn.VLAN{
					{
						ID:        100,
						EtherType: 0x8100,
					},
				},
				recvMulticast: false,
			},
		},
		//negative case, default receive case, no mirroring, no matching vlan&mac
		{
			A: testEtherConnEndpoint{
				mac: net.HardwareAddr{0x12, 0x11, 0x11, 0x11, 0x11, 0x1},
				vlans: []*etherconn.VLAN{
					{
						ID:        100,
						EtherType: 0x8100,
					},
				},
				dstMACFlag: macTestCorrect,
			},
			B: testEtherConnEndpoint{
				defaultConn:       true,
				ETypes:            []uint16{1},
				defaultConnMirror: false,
				mac:               net.HardwareAddr{0x12, 0x11, 0x11, 0x11, 0x11, 0x2},
				vlans: []*etherconn.VLAN{
					{
						ID:        101,
						EtherType: 0x8100,
					},
				},
				recvMulticast: false,
			},
			C: testEtherConnEndpoint{
				mac: net.HardwareAddr{0x12, 0x11, 0x11, 0x11, 0x11, 0x2},
				vlans: []*etherconn.VLAN{
					{
						ID:        100,
						EtherType: 0x8100,
					},
				},
				recvMulticast: false,
			},
			shouldFail: true,
		},
		//negative case, ethertypes not allowed
		{
			A: testEtherConnEndpoint{
				mac: net.HardwareAddr{0x12, 0x11, 0x11, 0x11, 0x11, 0x1},
				vlans: []*etherconn.VLAN{
					{
						ID:        100,
						EtherType: 0x8100,
					},
				},
				dstMACFlag: macTestCorrect,
			},
			B: testEtherConnEndpoint{
				ETypes: []uint16{0x1},
				mac:    net.HardwareAddr{0x12, 0x11, 0x11, 0x11, 0x11, 0x2},
				vlans: []*etherconn.VLAN{
					{
						ID:        100,
						EtherType: 0x8100,
					},
				},
				recvMulticast: false,
			},
			shouldFail: true,
		},
	}

	testFunc := func(c testEtherConnSingleCase, relayType etherconn.RelayType) error {
		err := testCreateVETHLink(testifA, testifB)
		if err != nil {
			return err
		}
		// filterstr := "udp or (vlan and udp)"

		filterstr := ""
		switch relayType {
		case etherconn.RelayTypeAFP:
			filterstr = "udp or (vlan and udp)"
		case etherconn.RelayTypePCAP:
			if runtime.GOOS == "linux" {
				filterstr = "(udp) or (vlan and vlan and udp) or (vlan and udp)"
			}
		}

		if c.A.filter != "" {
			filterstr = c.A.filter
		}

		mods := []etherconn.RelayOption{
			etherconn.WithDebug(true),
			etherconn.WithBPFFilter(filterstr),
		}
		if c.A.defaultConn {
			mods = append(mods, etherconn.WithDefaultReceival(c.A.defaultConnMirror))
		}
		var peerA, peerB *etherconn.RawSocketRelay
		peerA, err = getRawRelay(context.Background(), relayType, testifA, mods...)
		// switch relayType {
		// case etherconn.RawRelayTypePCAP:
		// 	peerA, err = etherconn.NewRawSocketRelayPcap(context.Background(), testifA, mods...)
		// case etherconn.RawRelayTypeAFP:
		// 	peerA, err = etherconn.NewRawSocketRelay(context.Background(), testifA, mods...)
		// }

		if err != nil {
			return err
		}
		defer peerA.Stop()
		filterstr = ""
		switch relayType {
		case etherconn.RelayTypeAFP:
			filterstr = "udp or (vlan and udp)"
		case etherconn.RelayTypePCAP:
			if runtime.GOOS == "linux" {
				filterstr = "(udp) or (vlan and vlan and udp) or (vlan and udp)"
			}
		}
		if c.B.filter != "" {
			filterstr = c.B.filter
		}
		mods = []etherconn.RelayOption{
			etherconn.WithDebug(true),
			etherconn.WithBPFFilter(filterstr),
		}
		if c.B.defaultConn {
			mods = append(mods, etherconn.WithDefaultReceival(c.B.defaultConnMirror))
		}
		peerB, err = getRawRelay(context.Background(), relayType, testifB, mods...)
		// switch relayType {
		// case etherconn.RawRelayTypePCAP:
		// 	peerB, err = etherconn.NewRawSocketRelayPcap(context.Background(), testifB, mods...)
		// case etherconn.RawRelayTypeAFP:
		// 	peerB, err = etherconn.NewRawSocketRelay(context.Background(), testifB, mods...)
		// }
		if err != nil {
			return err
		}
		defer peerB.Stop()
		emods := []etherconn.EtherConnOption{
			etherconn.WithVLANs(c.A.vlans),
		}
		if len(c.A.ETypes) == 0 {
			emods = append(emods, etherconn.WithEtherTypes(etherconn.DefaultEtherTypes))
		} else {
			emods = append(emods, etherconn.WithEtherTypes(c.A.ETypes))
		}
		if c.A.defaultConn {
			emods = append(emods, etherconn.WithDefault())
		}
		econnA := etherconn.NewEtherConn(c.A.mac, peerA, emods...)
		defer econnA.Close()
		emods = []etherconn.EtherConnOption{
			etherconn.WithVLANs(c.B.vlans),
			etherconn.WithRecvMulticast(c.B.recvMulticast),
		}
		if len(c.B.ETypes) == 0 {
			emods = append(emods, etherconn.WithEtherTypes(etherconn.DefaultEtherTypes))
		} else {
			emods = append(emods, etherconn.WithEtherTypes(c.B.ETypes))
		}
		if c.B.defaultConn {
			emods = append(emods, etherconn.WithDefault())
		}
		econnB := etherconn.NewEtherConn(c.B.mac, peerB, emods...)
		defer econnB.Close()

		if len(c.C.mac) > 0 {
			t.Logf("create endpoint C")
			emods = []etherconn.EtherConnOption{
				etherconn.WithVLANs(c.C.vlans),
				etherconn.WithRecvMulticast(c.C.recvMulticast),
			}
			if len(c.C.ETypes) == 0 {
				emods = append(emods, etherconn.WithEtherTypes(etherconn.DefaultEtherTypes))
			} else {
				emods = append(emods, etherconn.WithEtherTypes(c.C.ETypes))
			}
			if c.C.defaultConn {
				emods = append(emods, etherconn.WithDefault())
			}
			econnC := etherconn.NewEtherConn(c.C.mac, peerB, emods...)
			defer econnC.Close()
		}
		maxSize := 1000
		for i := 0; i < 10; i++ {
			fmt.Printf("send pkt %d\n", i)
			pktSize := maxSize - mathrand.Intn(maxSize-63)
			p := testGenDummyIPbytes(pktSize, i%2 == 0)
			var dst net.HardwareAddr
			switch c.A.dstMACFlag {
			case macTestCorrect:
				dst = c.B.mac
			case macTestBD:
				dst = etherconn.BroadCastMAC
			default:
				dst = net.HardwareAddr{0, 0, 0, 0, 0, 0}
			}
			fmt.Printf("send packet with length %d to %v\n content %v\n", len(p), dst, p)
			_, err := econnA.WriteIPPktTo(p, dst)
			if err != nil {
				return err
			}
			rcvdbuf := make([]byte, maxSize+100)
			//set read timeout
			err = econnB.SetReadDeadline(time.Now().Add(10 * time.Second))
			if err != nil {
				return err
			}
			good := false
			for i := 0; i < 6; i++ {
				n, rep, err := econnB.ReadPktFrom(rcvdbuf)
				if err != nil {
					return err
				}
				if !bytes.Equal(p, rcvdbuf[:n]) {
					if !c.B.defaultConn {
						return fmt.Errorf("recvied bytes is different from sent for pkt %d, sent %v, recv %v", i, p, rcvdbuf[:n])
					}
				} else {
					if cerr := checkEP(rep, econnA); cerr != nil {
						return cerr
					}
					fmt.Printf("recved a good  pkt\n")
					good = true
					break
				}
			}
			if !good {
				return fmt.Errorf("didn't get expected packet")
			}
		}

		return nil
	}
	for i, c := range testCaseList {
		// if i != 2 {
		// 	continue
		// }
		rtlist := []etherconn.RelayType{etherconn.RelayTypeAFP, etherconn.RelayTypePCAP}
		if runtime.GOOS == "windows" {
			rtlist = []etherconn.RelayType{etherconn.RelayTypePCAP}
		}
		for _, rtype := range rtlist {
			t.Logf("TestEtherConn: run case %d with %v", i, rtype)
			err := testFunc(c, rtype)
			if err != nil {
				if c.shouldFail {
					fmt.Printf("case %d failed as expected,%v\n", i, err)
				} else {
					t.Fatalf("case %d failed,%v", i, err)
				}
			} else {
				if c.shouldFail {
					t.Fatalf("case %d succeed but should fail", i)
				}
			}

		}
	}
}

func TestRUDPConn(t *testing.T) {
	testCaseList := []testRUDPConnSingleCase{
		{
			AEther: testEtherConnEndpoint{
				mac: net.HardwareAddr{0x12, 0x11, 0x11, 0x11, 0x11, 0x1},
				vlans: []*etherconn.VLAN{
					{
						ID:        100,
						EtherType: 0x8100,
					},
				},
			},
			BEther: testEtherConnEndpoint{
				mac: net.HardwareAddr{0x12, 0x11, 0x11, 0x11, 0x11, 0x2},
				vlans: []*etherconn.VLAN{
					{
						ID:        100,
						EtherType: 0x8100,
					},
				},
			},
			AIP:   net.ParseIP("1.1.1.1"),
			BIP:   net.ParseIP("1.1.1.100"),
			APort: 1999,
			BPort: 2999,
		},

		{
			AEther: testEtherConnEndpoint{
				mac: net.HardwareAddr{0x12, 0x11, 0x11, 0x11, 0x11, 0x1},
				vlans: []*etherconn.VLAN{
					{
						ID:        100,
						EtherType: 0x8100,
					},
				},
			},
			BEther: testEtherConnEndpoint{
				mac: net.HardwareAddr{0x12, 0x11, 0x11, 0x11, 0x11, 0x2},
				vlans: []*etherconn.VLAN{
					{
						ID:        100,
						EtherType: 0x8100,
					},
				},
			},
			AIP:   net.ParseIP("2001:dead::1"),
			BIP:   net.ParseIP("2001:beef::1"),
			APort: 1999,
			BPort: 2999,
		},
	}

	testFunc := func(c testRUDPConnSingleCase, relayType etherconn.RelayType) error {
		err := testCreateVETHLink(testifA, testifB)
		if err != nil {
			return err
		}
		peerA, err := getRawRelay(context.Background(), relayType, testifA,
			etherconn.WithDebug(true))
		// peerA, err := etherconn.NewRawSocketRelay(context.Background(), testifA,
		// 	etherconn.WithDebug(true))
		if err != nil {
			return err
		}
		defer peerA.Stop()
		peerB, err := getRawRelay(context.Background(), relayType, testifB,
			etherconn.WithDebug(true))
		// peerB, err := etherconn.NewRawSocketRelay(context.Background(), testifB,
		// 	etherconn.WithDebug(true))
		if err != nil {
			return err
		}
		defer peerB.Stop()

		resolvMacFunc := func(net.IP) net.HardwareAddr {
			switch c.AEther.dstMACFlag {
			case macTestCorrect:
				return c.BEther.mac
			case macTestBD:
				return etherconn.BroadCastMAC
			default:
				return net.HardwareAddr{0, 0, 0, 0, 0, 0}
			}
		}
		econnA := etherconn.NewEtherConn(c.AEther.mac, peerA, etherconn.WithVLANs(c.AEther.vlans))
		econnB := etherconn.NewEtherConn(c.BEther.mac, peerB, etherconn.WithVLANs(c.BEther.vlans),
			etherconn.WithRecvMulticast(c.BEther.recvMulticast))
		rudpA, err := etherconn.NewRUDPConn(myaddr.GenConnectionAddrStr("", c.AIP, c.APort), econnA,
			etherconn.WithResolveNextHopMacFunc(resolvMacFunc))
		if err != nil {
			return err
		}
		rudpB, err := etherconn.NewRUDPConn(myaddr.GenConnectionAddrStr("", c.BIP, c.BPort), econnB)
		if err != nil {
			return err
		}
		maxSize := 1000
		for i := 0; i < 10; i++ {
			p := testGenDummyIPbytes(maxSize-mathrand.Intn(maxSize-100), true)
			fmt.Printf("send packet with length %d\n", len(p))
			_, err := rudpA.WriteTo(p, &net.UDPAddr{IP: c.BIP, Zone: "udp", Port: c.BPort})
			if err != nil {
				return err
			}
			rcvdbuf := make([]byte, maxSize+100)
			//set read timeout
			err = rudpB.SetReadDeadline(time.Now().Add(time.Second))
			if err != nil {
				return err
			}
			n, _, err := rudpB.ReadFrom(rcvdbuf)
			if err != nil {
				return err
			}
			if !bytes.Equal(p, rcvdbuf[:n]) {
				return fmt.Errorf("recvied bytes is different from sent")
			}
		}
		return nil
	}
	for i, c := range testCaseList {
		rtlist := []etherconn.RelayType{etherconn.RelayTypeAFP, etherconn.RelayTypePCAP}
		if runtime.GOOS == "windows" {
			rtlist = []etherconn.RelayType{etherconn.RelayTypePCAP}
		}
		for _, rtype := range rtlist {
			t.Logf("runing case %d with %v", i, rtype)
			err := testFunc(c, rtype)
			if err != nil {
				if c.shouldFail {
					fmt.Printf("case %d failed as expected,%v\n", i, err)
				} else {
					t.Fatalf("case %d failed,%v", i, err)
				}
			} else {
				if c.shouldFail {
					t.Fatalf("case %d succeed but should fail", i)
				}
			}
		}
	}
}

// v is the orignal value, vs is the orignal string
// newIDs is the value for SetIDs, newv is the new VLANs after setIDs
type testVLANsCase struct {
	v          etherconn.VLANs
	vbs        []byte
	vs         string
	umvs       string
	newIDs     []uint16
	newv       etherconn.VLANs
	shouldFail bool
}

func TestVLANs(t *testing.T) {
	testCaseList := []testVLANsCase{
		{
			v: etherconn.VLANs{
				&etherconn.VLAN{
					ID:        300,
					EtherType: 0x8100,
				},
			},
			vs:     "|300",
			vbs:    []byte{0x1, 0x2c, 0x81, 0},
			newIDs: []uint16{111},
			newv: etherconn.VLANs{
				&etherconn.VLAN{
					ID:        111,
					EtherType: 0x8100,
				},
			},
		},
		{
			v: etherconn.VLANs{
				&etherconn.VLAN{
					ID:        300,
					EtherType: 0x8100,
				},
			},
			vs:     "|300",
			umvs:   ".300",
			newIDs: []uint16{111},
			newv: etherconn.VLANs{
				&etherconn.VLAN{
					ID:        111,
					EtherType: 0x8100,
				},
			},
		},
		{
			v: etherconn.VLANs{
				&etherconn.VLAN{
					ID:        300,
					EtherType: 0x8100,
				},
			},
			vs:     "|300",
			umvs:   "300",
			newIDs: []uint16{111},
			newv: etherconn.VLANs{
				&etherconn.VLAN{
					ID:        111,
					EtherType: 0x8100,
				},
			},
		},
		{
			v: etherconn.VLANs{
				&etherconn.VLAN{
					ID:        100,
					EtherType: 0x8100,
				},
				&etherconn.VLAN{
					ID:        200,
					EtherType: 0x8200,
				},
			},
			vs:     "|100|200",
			umvs:   "100.200",
			newIDs: []uint16{111, 222},
			newv: etherconn.VLANs{
				&etherconn.VLAN{
					ID:        111,
					EtherType: 0x8100,
				},
				&etherconn.VLAN{
					ID:        222,
					EtherType: 0x8200,
				},
			},
		},
		{
			v: etherconn.VLANs{
				&etherconn.VLAN{
					ID:        100,
					EtherType: 0x8100,
				},
				&etherconn.VLAN{
					ID:        200,
					EtherType: 0x8200,
				},
			},
			vbs:    []byte{0, 100, 0x81, 0, 0, 200, 0x82, 0},
			vs:     "|100|200",
			umvs:   "100|200",
			newIDs: []uint16{111, 222},
			newv: etherconn.VLANs{
				&etherconn.VLAN{
					ID:        111,
					EtherType: 0x8100,
				},
				&etherconn.VLAN{
					ID:        222,
					EtherType: 0x8200,
				},
			},
		},
		{
			shouldFail: true,
			v: etherconn.VLANs{
				&etherconn.VLAN{
					ID:        100,
					EtherType: 0x8100,
				},
				&etherconn.VLAN{
					ID:        200,
					EtherType: 0x8200,
				},
			},
			vbs:    []byte{0, 100, 0x81, 0, 0, 200, 0x82},
			vs:     "|100|200",
			umvs:   "100|200",
			newIDs: []uint16{111, 222},
			newv: etherconn.VLANs{
				&etherconn.VLAN{
					ID:        111,
					EtherType: 0x8100,
				},
				&etherconn.VLAN{
					ID:        222,
					EtherType: 0x8200,
				},
			},
		},
		{
			v: etherconn.VLANs{
				&etherconn.VLAN{
					ID:        100,
					EtherType: 0x8100,
				},
				&etherconn.VLAN{
					ID:        200,
					EtherType: 0x8200,
				},
			},
			vs:     "|100|200",
			newIDs: []uint16{111, 222},
			newv: etherconn.VLANs{
				&etherconn.VLAN{
					ID:        111,
					EtherType: 0x8100,
				},
				&etherconn.VLAN{
					ID:        220,
					EtherType: 0x8200,
				},
			},
			shouldFail: true,
		},
		{
			v:          etherconn.VLANs{},
			vs:         "",
			newIDs:     []uint16{},
			newv:       etherconn.VLANs{},
			shouldFail: false,
		},
	}
	testFunc := func(c testVLANsCase) error {
		if len(c.vbs) != 0 {
			buf, err := c.v.MarshalBinary()
			if err != nil {
				return err
			}
			if !bytes.Equal(buf, c.vbs) {
				return fmt.Errorf("%v marshalbinary result %v is different from expected %v", c.v, buf, c.vbs)
			}
			newv := new(etherconn.VLANs)
			err = newv.UnmarshalBinary(buf)
			if err != nil {
				return err
			}
			if !newv.Equal(c.v) {
				return fmt.Errorf("%v unmarshalbinary result %v is different", c.v, newv)
			}

		}

		if c.v.String() != c.vs {
			return fmt.Errorf("c.v string %v is different from expected %v", c.v.String(), c.vs)
		}
		ustr := c.vs
		if c.umvs != "" {
			ustr = c.umvs
		}
		newvlan := new(etherconn.VLANs)
		if err := newvlan.UnmarshalText([]byte(ustr)); err != nil {
			return fmt.Errorf("failed to unmarshal %v, %w", c.vs, err)
		}
		if newvlan.String() != c.v.String() {
			return fmt.Errorf("unmarshaled vlan %v is different from expected %v", newvlan.String(), c.v.String())
		}

		err := c.v.SetIDs(c.newIDs)
		if err != nil {
			return err
		}
		if !c.newv.Equal(c.v) {
			return fmt.Errorf("c.newv %v is different from expected %v", c.v, c.newv)
		}
		return nil
	}
	for i, c := range testCaseList {
		err := testFunc(c)
		if err != nil {
			if c.shouldFail {
				fmt.Printf("case %d failed as expected,%v\n", i, err)
			} else {
				t.Fatalf("case %d failed,%v", i, err)
			}
		} else {
			if c.shouldFail {
				t.Fatalf("case %d succeed but should fail", i)
			}
		}
	}

}

type testVLANsMarshalCase struct {
	inputs         string
	expectedResult etherconn.VLANs
	shouldFail     bool
}

func (tvlanc *testVLANsMarshalCase) dotest() error {
	r := new(etherconn.VLANs)
	err := r.UnmarshalText([]byte(tvlanc.inputs))
	if err != nil {
		return err
	}
	if !r.Equal(tvlanc.expectedResult) {
		return fmt.Errorf("result %v is different from expected: %v", r, tvlanc.expectedResult)
	}
	return nil
}

func TestVLANMarshalBinary(t *testing.T) {
	type tcase struct {
		vlan            etherconn.VLAN
		expectedMarshal []byte
		unmarshalBytes  []byte
		shouldFail      bool
	}
	testcaseList := []tcase{
		{
			vlan: etherconn.VLAN{
				ID:        33,
				EtherType: etherconn.DefaultVLANEtype,
			},
			expectedMarshal: []byte{0, 33, 0x81, 0},
		},
		{
			vlan:            etherconn.VLAN{},
			expectedMarshal: []byte{0, 0, 0, 0},
		},
		{
			vlan:            etherconn.VLAN{},
			expectedMarshal: []byte{0, 0, 0, 0},
			unmarshalBytes:  []byte{},
		},
	}
	testFunc := func(c tcase) error {
		buf, err := c.vlan.MarshalBinary()
		if err != nil {
			return err
		}
		if !bytes.Equal(buf, c.expectedMarshal) {
			return fmt.Errorf("marshal result %v is different from expected %v", buf, c.expectedMarshal)
		}
		if c.unmarshalBytes != nil {
			newv := new(etherconn.VLAN)
			err = newv.UnmarshalBinary(c.unmarshalBytes)
			if err != nil {
				return err
			}
			if newv == nil {
				t.Log("newv is nil")
			}
			if !newv.Equal(c.vlan) {
				return fmt.Errorf("unmarshaled result %v is different from original one %v", newv, c.vlan)
			}

		}
		return nil
	}
	for i, c := range testcaseList {
		t.Logf("test case %d", i)
		err := testFunc(c)
		if err != nil {
			if !c.shouldFail {
				t.Fatalf("test case %d fails, %v", i, err)
			} else {
				t.Logf("case %d fails as expected, %v", i, err)
			}
		}
	}
}

func TestVLANsUnMarhal(t *testing.T) {
	testCaseList := []testVLANsMarshalCase{
		//case 0,qinq with .
		{
			inputs: "33.22",
			expectedResult: etherconn.VLANs{
				&etherconn.VLAN{
					ID:        33,
					EtherType: etherconn.DefaultVLANEtype,
				},
				&etherconn.VLAN{
					ID:        22,
					EtherType: etherconn.DefaultVLANEtype,
				},
			},
		},
		//case 0,qinq with |
		{
			inputs: "33|22",
			expectedResult: etherconn.VLANs{
				&etherconn.VLAN{
					ID:        33,
					EtherType: etherconn.DefaultVLANEtype,
				},
				&etherconn.VLAN{
					ID:        22,
					EtherType: etherconn.DefaultVLANEtype,
				},
			},
		},
		//case 2,dot1q
		{
			inputs: "499",
			expectedResult: etherconn.VLANs{
				&etherconn.VLAN{
					ID:        499,
					EtherType: etherconn.DefaultVLANEtype,
				},
			},
		},
		//case 3,negative case: out of range
		{
			inputs:     "4929.30",
			shouldFail: true,
		},
		//case 3,negative case: not a number
		{
			inputs:     "33.aa",
			shouldFail: true,
		},
	}
	for i, c := range testCaseList {
		t.Logf("test case %d", i)
		err := c.dotest()
		if err != nil {
			if !c.shouldFail {
				t.Fatalf("test case %d fails, %v", i, err)
			} else {
				t.Logf("case %d fails as expected, %v", i, err)
			}
		}
	}
}
