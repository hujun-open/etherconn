// tests for SharedEtherConn and SharingRUDPConn
package etherconn_test

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"math/rand"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/hujun-open/etherconn"
)

type testUDPEndpoint struct {
	IP   net.IP
	Port int
}

const (
	afRelay int = iota
	xdpRelay
)

type testSharedEtherConnSingleCase struct {
	Aconn, Bconn       testEtherConnEndpoint
	AUDPList, BUDPList []testUDPEndpoint
	relayType          int
	shouldFail         bool
}

// TestSharedEtherConn tests both RawSocketRelay and XDPRelay
func TestSharedEtherConn(t *testing.T) {
	testCaseList := []testSharedEtherConnSingleCase{
		//good case, no Q
		{
			Aconn: testEtherConnEndpoint{
				mac:         net.HardwareAddr{0x14, 0x11, 0x11, 0x11, 0x11, 0x1},
				vlans:       []*etherconn.VLAN{},
				defaultConn: false,
			},
			Bconn: testEtherConnEndpoint{
				mac:         net.HardwareAddr{0x14, 0x11, 0x11, 0x11, 0x11, 0x2},
				vlans:       []*etherconn.VLAN{},
				defaultConn: false,
			},
			AUDPList: []testUDPEndpoint{
				{
					IP:   net.ParseIP("1.1.1.1"),
					Port: 100,
				},
				{
					IP:   net.ParseIP("1.1.1.2"),
					Port: 100,
				},
			},
			BUDPList: []testUDPEndpoint{
				{
					IP:   net.ParseIP("2.1.1.1"),
					Port: 100,
				},
				{
					IP:   net.ParseIP("2.1.1.2"),
					Port: 100,
				},
			},
		},

		//good case, vlan
		{
			Aconn: testEtherConnEndpoint{
				mac: net.HardwareAddr{0x14, 0x11, 0x11, 0x11, 0x11, 0x1},
				vlans: []*etherconn.VLAN{
					{
						ID:        100,
						EtherType: 0x8100,
					},
				},
				defaultConn: true,
			},
			Bconn: testEtherConnEndpoint{
				mac: net.HardwareAddr{0x14, 0x11, 0x11, 0x11, 0x11, 0x2},
				vlans: []*etherconn.VLAN{
					{
						ID:        100,
						EtherType: 0x8100,
					},
				},
				defaultConn: true,
			},
			AUDPList: []testUDPEndpoint{
				{
					IP:   net.ParseIP("1.1.1.1"),
					Port: 100,
				},
				{
					IP:   net.ParseIP("1.1.1.2"),
					Port: 100,
				},
			},
			BUDPList: []testUDPEndpoint{
				{
					IP:   net.ParseIP("2.1.1.1"),
					Port: 100,
				},
				{
					IP:   net.ParseIP("2.1.1.2"),
					Port: 100,
				},
			},
		},

		//good case, QinQ
		{
			Aconn: testEtherConnEndpoint{
				mac: net.HardwareAddr{0x14, 0x11, 0x11, 0x11, 0x11, 0x1},
				vlans: []*etherconn.VLAN{
					{
						ID:        100,
						EtherType: 0x8100,
					},
					{
						ID:        200,
						EtherType: 0x8100,
					},
				},
				defaultConn: false,
			},
			Bconn: testEtherConnEndpoint{
				mac: net.HardwareAddr{0x14, 0x11, 0x11, 0x11, 0x11, 0x2},
				vlans: []*etherconn.VLAN{
					{
						ID:        100,
						EtherType: 0x8100,
					},
					{
						ID:        200,
						EtherType: 0x8100,
					},
				},
				defaultConn: false,
			},
			AUDPList: []testUDPEndpoint{
				{
					IP:   net.ParseIP("1.1.1.1"),
					Port: 100,
				},
				{
					IP:   net.ParseIP("1.1.1.2"),
					Port: 333,
				},
			},
			BUDPList: []testUDPEndpoint{
				{
					IP:   net.ParseIP("2.1.1.1"),
					Port: 222,
				},
				{
					IP:   net.ParseIP("2.1.1.2"),
					Port: 444,
				},
			},
		},
	}

	testFunc := func(c testSharedEtherConnSingleCase) error {
		const lifetime = 10 * time.Minute

		rootctx, cancelf := context.WithDeadline(context.Background(), time.Now().Add(lifetime))
		defer cancelf()
		_, _, err := testCreateVETHLink(testifA, testifB)
		if err != nil {
			return err
		}
		//create pkt relay
		var peerA, peerB etherconn.PacketRelay
		switch c.relayType {
		case afRelay:
			mods := []etherconn.RelayOption{
				etherconn.WithDebug(true),
			}
			if c.Aconn.defaultConn {
				mods = append(mods, etherconn.WithDefaultReceival(c.Aconn.defaultConnMirror))
			}
			peerA, err = etherconn.NewRawSocketRelay(rootctx, testifA, mods...)
			if err != nil {
				return err
			}
			mods = []etherconn.RelayOption{
				etherconn.WithDebug(true),
			}
			if c.Bconn.defaultConn {
				mods = append(mods, etherconn.WithDefaultReceival(c.Bconn.defaultConnMirror))
			}
			peerB, err = etherconn.NewRawSocketRelay(rootctx, testifB, mods...)
			if err != nil {
				return err
			}
		case xdpRelay:

			mods := []etherconn.XDPRelayOption{
				etherconn.WithQueueID([]int{0}),
				etherconn.WithXDPUMEMNumOfTrunk(32768),
				// etherconn.WithXDPPerClntRecvChanDepth(32768),
				etherconn.WithXDPDebug(true),
				etherconn.WithXDPUMEMChunkSize(4096),
			}
			if c.Aconn.defaultConn {
				mods = append(mods, etherconn.WithXDPDefaultReceival(c.Aconn.defaultConnMirror))
			}
			peerA, err = etherconn.NewXDPRelay(rootctx, testifA, mods...)
			if err != nil {
				return err
			}
			mods = []etherconn.XDPRelayOption{
				etherconn.WithXDPDebug(true),
				etherconn.WithQueueID([]int{0}),
			}
			if c.Bconn.defaultConn {
				mods = append(mods, etherconn.WithXDPDefaultReceival(c.Bconn.defaultConnMirror))
			}
			peerB, err = etherconn.NewXDPRelay(rootctx, testifB, mods...)
			if err != nil {
				return err
			}
		}
		// defer fmt.Printf("A stats: %+v\n B stats: %+v\n", peerA.GetStats(), peerB.GetStats())
		defer peerA.Stop()
		defer peerB.Stop()

		emods := []etherconn.EtherConnOption{
			etherconn.WithVLANs(c.Aconn.vlans),
		}
		if len(c.Aconn.ETypes) == 0 {
			emods = append(emods, etherconn.WithEtherTypes(etherconn.DefaultEtherTypes))
		} else {
			emods = append(emods, etherconn.WithEtherTypes(c.Aconn.ETypes))
		}
		if c.Aconn.defaultConn {
			emods = append(emods, etherconn.WithDefault())
		}
		econnA := etherconn.NewSharedEtherConn(rootctx, c.Aconn.mac, peerA, emods)
		defer econnA.Close()
		emods = []etherconn.EtherConnOption{
			etherconn.WithVLANs(c.Bconn.vlans),
			etherconn.WithRecvMulticast(c.Bconn.recvMulticast),
		}
		if len(c.Bconn.ETypes) == 0 {
			emods = append(emods, etherconn.WithEtherTypes(etherconn.DefaultEtherTypes))
		} else {
			emods = append(emods, etherconn.WithEtherTypes(c.Bconn.ETypes))
		}
		if c.Bconn.defaultConn {
			emods = append(emods, etherconn.WithDefault())
		}
		econnB := etherconn.NewSharedEtherConn(rootctx, c.Bconn.mac, peerB, emods)
		defer econnB.Close()

		//create rudpconns
		var AUDPConnList, BUDPConnList []*etherconn.SharingRUDPConn
		createuconnFunc := func(e testUDPEndpoint,
			ec *etherconn.SharedEtherConn, dstmac net.HardwareAddr) (*etherconn.SharingRUDPConn, error) {
			return etherconn.NewSharingRUDPConn(
				fmt.Sprintf("%v:%d", e.IP, e.Port),
				ec,
				[]etherconn.RUDPConnOption{
					etherconn.WithResolveNextHopMacFunc(
						func(net.IP) net.HardwareAddr {
							return dstmac
						},
					),
				},
			)
		}
		if len(c.AUDPList) != len(c.BUDPList) {
			return fmt.Errorf("case doesn't have same number of AUDPList and BUDPList")
		}
		for _, e := range c.AUDPList {
			newconn, err := createuconnFunc(e, econnA, c.Bconn.mac)
			if err != nil {
				return err
			}
			AUDPConnList = append(AUDPConnList, newconn)
		}
		for _, e := range c.BUDPList {
			newconn, err := createuconnFunc(e, econnB, c.Aconn.mac)
			if err != nil {
				return err
			}
			BUDPConnList = append(BUDPConnList, newconn)
		}
		testuconnFunc := func(rudpA, rudpB *etherconn.SharingRUDPConn, dst net.IP, dstport int) error {
			maxSize := 1000
			for i := 0; i < 10; i++ {
				p := testGenDummyIPbytes(maxSize-rand.Intn(maxSize-100), true)
				t.Logf("send packet with length %d\n", len(p))
				_, err := rudpA.WriteTo(p,
					&net.UDPAddr{IP: dst, Zone: "udp", Port: dstport})
				if err != nil {
					return err
				}
				rcvdbuf := make([]byte, maxSize+100)
				//set read timeout
				err = rudpB.SetReadDeadline(time.Now().Add(5 * time.Second))
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
		time.Sleep(3 * time.Second)
		for i, e := range c.BUDPList {
			err := testuconnFunc(AUDPConnList[i], BUDPConnList[i], e.IP, e.Port)
			if err != nil {
				return fmt.Errorf("testing UDP pair %d faild,%w", i, err)
			}
		}
		err = testuconnFunc(AUDPConnList[0], BUDPConnList[1], c.BUDPList[0].IP, c.BUDPList[0].Port)
		if err != nil {
			t.Log("negative test pass")
		} else {
			return fmt.Errorf("negative test failed,%w", err)
		}
		return nil
	}
	runTestFunc := func(c testSharedEtherConnSingleCase, i int) {
		err := testFunc(c)
		if err != nil {
			if c.shouldFail {
				fmt.Printf("case %d failed as expected,%v\n", i, err)
			} else {
				t.Fatalf("case %d failed,%v\n", i, err)
			}
		} else {
			if c.shouldFail {
				t.Fatalf("case %d succeed but should fail", i)
			}
		}

	}
	for i, c := range testCaseList {
		// if i != 2 {
		// 	continue
		// }
		t.Logf("====> run case %d with RawSocketRelay", i)
		c.relayType = afRelay
		runTestFunc(c, i)
		t.Logf("====> run case %d with XDPRelay", i)
		c.relayType = xdpRelay
		runTestFunc(c, i)
	}

}
func TestMain(m *testing.M) {
	runtime.SetBlockProfileRate(1000000000)
	go func() {
		log.Println(http.ListenAndServe("0.0.0.0:6060", nil))
	}()
	result := m.Run()
	os.Exit(result)
}
