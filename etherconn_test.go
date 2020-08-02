// etherconn_test

/*
Test setup reuqirements:
  - two interfaces name specified by argument testifA and testifB, these two interfaces are connected together
*/
package etherconn

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"os"
	"testing"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/hujun-open/myaddr"
)

var testifA = flag.String("testifA", "", "test interface A")
var testifB = flag.String("testifB", "", "test interface B")

type testEtherConnEndpoint struct {
	mac           net.HardwareAddr
	vlans         []*VLAN
	dstMACFlag    int
	recvMulticast bool
}

type testEtherConnSingleCase struct {
	A          testEtherConnEndpoint
	B          testEtherConnEndpoint
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

func TestEtherConn(t *testing.T) {
	testCaseList := []testEtherConnSingleCase{
		testEtherConnSingleCase{
			A: testEtherConnEndpoint{
				mac: net.HardwareAddr{0x12, 0x11, 0x11, 0x11, 0x11, 0x1},
				vlans: []*VLAN{
					&VLAN{
						ID:        100,
						EtherType: 0x8100,
					},
					&VLAN{
						ID:        222,
						EtherType: 0x8100,
					},
				},
			},
			B: testEtherConnEndpoint{
				mac: net.HardwareAddr{0x12, 0x11, 0x11, 0x11, 0x11, 0x2},
				vlans: []*VLAN{
					&VLAN{
						ID:        100,
						EtherType: 0x8100,
					},
					&VLAN{
						ID:        222,
						EtherType: 0x8100,
					},
				},
			},
		},
		//negative case, different vlan
		testEtherConnSingleCase{
			A: testEtherConnEndpoint{
				mac: net.HardwareAddr{0x12, 0x11, 0x11, 0x11, 0x11, 0x1},
				vlans: []*VLAN{
					&VLAN{
						ID:        100,
						EtherType: 0x8100,
					},
				},
			},
			B: testEtherConnEndpoint{
				mac: net.HardwareAddr{0x12, 0x11, 0x11, 0x11, 0x11, 0x2},
				vlans: []*VLAN{
					&VLAN{
						ID:        101,
						EtherType: 0x8100,
					},
				},
			},
			shouldFail: true,
		},

		//negative case, wrong mac
		testEtherConnSingleCase{
			A: testEtherConnEndpoint{
				mac: net.HardwareAddr{0x12, 0x11, 0x11, 0x11, 0x11, 0x1},
				vlans: []*VLAN{
					&VLAN{
						ID:        100,
						EtherType: 0x8100,
					},
				},
				dstMACFlag: macTestWrong,
			},
			B: testEtherConnEndpoint{
				mac: net.HardwareAddr{0x12, 0x11, 0x11, 0x11, 0x11, 0x2},
				vlans: []*VLAN{
					&VLAN{
						ID:        100,
						EtherType: 0x8100,
					},
				},
			},
			shouldFail: true,
		},

		//send to broadcast good case, even recv has wrong vlan id
		testEtherConnSingleCase{
			A: testEtherConnEndpoint{
				mac: net.HardwareAddr{0x12, 0x11, 0x11, 0x11, 0x11, 0x1},
				vlans: []*VLAN{
					&VLAN{
						ID:        100,
						EtherType: 0x8100,
					},
				},
				dstMACFlag: macTestBD,
			},
			B: testEtherConnEndpoint{
				mac: net.HardwareAddr{0x12, 0x11, 0x11, 0x11, 0x11, 0x2},
				vlans: []*VLAN{
					&VLAN{
						ID:        101,
						EtherType: 0x8100,
					},
				},
				recvMulticast: true,
			},
			shouldFail: false,
		},

		//send to broadcast negative case, recv doesn't accept multicast
		testEtherConnSingleCase{
			A: testEtherConnEndpoint{
				mac: net.HardwareAddr{0x12, 0x11, 0x11, 0x11, 0x11, 0x1},
				vlans: []*VLAN{
					&VLAN{
						ID:        100,
						EtherType: 0x8100,
					},
				},
				dstMACFlag: macTestBD,
			},
			B: testEtherConnEndpoint{
				mac: net.HardwareAddr{0x12, 0x11, 0x11, 0x11, 0x11, 0x2},
				vlans: []*VLAN{
					&VLAN{
						ID:        101,
						EtherType: 0x8100,
					},
				},
				recvMulticast: false,
			},
			shouldFail: true,
		},
	}

	testFunc := func(c testEtherConnSingleCase) error {
		peerA, err := NewRawSocketRelay(context.Background(), *testifA, WithDebug(true))
		if err != nil {
			return err
		}
		defer peerA.Stop()
		peerB, err := NewRawSocketRelay(context.Background(), *testifB, WithDebug(true))
		if err != nil {
			return err
		}
		defer peerB.Stop()
		econnA := NewEtherConn(c.A.mac, peerA, WithVLANs(c.A.vlans))
		econnB := NewEtherConn(c.B.mac, peerB, WithVLANs(c.B.vlans), WithRecvMulticasat(c.B.recvMulticast))
		maxSize := 1000
		for i := 0; i < 10; i++ {
			pktSize := maxSize - rand.Intn(maxSize-63)

			p := testGenDummyIPbytes(pktSize, i%2 == 0)
			fmt.Printf("send packet with length %d\n", len(p))

			var dst net.HardwareAddr
			switch c.A.dstMACFlag {
			case macTestCorrect:
				dst = c.B.mac
			case macTestBD:
				dst = BroadCastMAC
			default:
				dst = net.HardwareAddr{0, 0, 0, 0, 0, 0}
			}
			_, err := econnA.WriteIPPktTo(p, dst)
			if err != nil {
				return err
			}
			rcvdbuf := make([]byte, maxSize+100)
			//set read timeout
			err = econnB.SetReadDeadline(time.Now().Add(time.Second))
			if err != nil {
				return err
			}
			n, _, err := econnB.ReadPktFrom(rcvdbuf)
			if err != nil {
				return err
			}
			if !bytes.Equal(p, rcvdbuf[:n]) {
				return fmt.Errorf("recvied bytes is different from sent, sent %v, recv %v", p, rcvdbuf[:n])
			}
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

func TestRUDPConn(t *testing.T) {
	testCaseList := []testRUDPConnSingleCase{
		testRUDPConnSingleCase{
			AEther: testEtherConnEndpoint{
				mac: net.HardwareAddr{0x12, 0x11, 0x11, 0x11, 0x11, 0x1},
				vlans: []*VLAN{
					&VLAN{
						ID:        100,
						EtherType: 0x8100,
					},
				},
			},
			BEther: testEtherConnEndpoint{
				mac: net.HardwareAddr{0x12, 0x11, 0x11, 0x11, 0x11, 0x2},
				vlans: []*VLAN{
					&VLAN{
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

		testRUDPConnSingleCase{
			AEther: testEtherConnEndpoint{
				mac: net.HardwareAddr{0x12, 0x11, 0x11, 0x11, 0x11, 0x1},
				vlans: []*VLAN{
					&VLAN{
						ID:        100,
						EtherType: 0x8100,
					},
				},
			},
			BEther: testEtherConnEndpoint{
				mac: net.HardwareAddr{0x12, 0x11, 0x11, 0x11, 0x11, 0x2},
				vlans: []*VLAN{
					&VLAN{
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

	testFunc := func(c testRUDPConnSingleCase) error {
		peerA, err := NewRawSocketRelay(context.Background(), *testifA, WithDebug(true))
		if err != nil {
			return err
		}
		defer peerA.Stop()
		peerB, err := NewRawSocketRelay(context.Background(), *testifB, WithDebug(true))
		if err != nil {
			return err
		}
		defer peerB.Stop()

		resolvMacFunc := func(net.IP) net.HardwareAddr {
			switch c.AEther.dstMACFlag {
			case macTestCorrect:
				return c.BEther.mac
			case macTestBD:
				return BroadCastMAC
			default:
				return net.HardwareAddr{0, 0, 0, 0, 0, 0}
			}
		}
		econnA := NewEtherConn(c.AEther.mac, peerA, WithVLANs(c.AEther.vlans))
		econnB := NewEtherConn(c.BEther.mac, peerB, WithVLANs(c.BEther.vlans), WithRecvMulticasat(c.BEther.recvMulticast))
		rudpA, err := NewRUDPConn(myaddr.GenConnectionAddrStr("", c.AIP, c.APort), econnA, WithResolveNextHopMacFunc(resolvMacFunc))
		if err != nil {
			return err
		}
		rudpB, err := NewRUDPConn(myaddr.GenConnectionAddrStr("", c.BIP, c.BPort), econnB)
		if err != nil {
			return err
		}
		maxSize := 1000
		for i := 0; i < 10; i++ {
			p := testGenDummyIPbytes(maxSize-rand.Intn(maxSize-100), true)
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

func TestMain(m *testing.M) {
	flag.Parse()
	if *testifA == "" || *testifB == "" {
		fmt.Printf("error: two test interface name must be specified")
		os.Exit(1)
	}
	result := m.Run()
	os.Exit(result)
}
