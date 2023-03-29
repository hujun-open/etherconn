package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log"
	"net"
	"runtime"
	"sync"
	"time"

	"github.com/google/gopacket/layers"
	"github.com/hujun-open/etherconn"
	"github.com/vishvananda/netlink"
)

const defaultMaxXDPFrameSize = 4096
const defaultNumXDPUMEMChunk = 16384

type ECInterface struct {
	relay         etherconn.PacketRelay
	econnRcvDepth uint
}

func NewECInterface(ctx context.Context, ifname string,
	maxFrameSize uint, numchunk uint, numeng uint, relayRcvDepth, econnRcvDepth uint, doulbeQ bool, driver etherconn.RelayType, debug bool, txbatch bool) (*ECInterface, error) {
	var err error
	var intf netlink.Link
	if intf, err = netlink.LinkByName(ifname); err != nil {
		return nil, err
	}
	if intf.Attrs().OperState != netlink.OperUp {
		return nil, fmt.Errorf("interface %v is not oper up", ifname)
	}
	log.Printf("%v type is %v", ifname, intf.Type())
	var numQ int
	numQ, err = etherconn.GetIFQueueNum(ifname)
	if err != nil {
		return nil, fmt.Errorf("failed to get number of queue for interface %v, %w", ifname, err)
	}
	r := new(ECInterface)
	r.econnRcvDepth = econnRcvDepth
	switch driver {
	default:
		return nil, fmt.Errorf("unsupported driver for etherconn %v", driver)
	case etherconn.RelayTypePCAP:
		r.relay, err = etherconn.NewRawSocketRelayPcap(ctx, ifname,
			etherconn.WithDebug(debug),
			etherconn.WithMaxEtherFrameSize(maxFrameSize),
			etherconn.WithPerClntChanRecvDepth(numchunk),
			etherconn.WithSendChanDepth(relayRcvDepth),
			etherconn.WithMultiEngine(numeng),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create %v relay for interface %v, %w", etherconn.RelayTypePCAP, ifname, err)
		}
		return r, nil
	case etherconn.RelayTypeAFP:
		r.relay, err = etherconn.NewRawSocketRelay(ctx, ifname,
			etherconn.WithDebug(debug),
			etherconn.WithMaxEtherFrameSize(maxFrameSize),
			etherconn.WithPerClntChanRecvDepth(numchunk),
			etherconn.WithSendChanDepth(relayRcvDepth),
			etherconn.WithMultiEngine(numeng),
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create %v relay for interface %v, %w", etherconn.RelayTypeAFP, ifname, err)
		}
		return r, nil
	case etherconn.RelayTypeXDP:
		if doulbeQ {
			numQ *= 2
		}
		qidList := []int{}
		for i := 0; i < numQ; i++ {
			qidList = append(qidList, i)
		}
		txmode := etherconn.XDPSendingModeSingle
		if txbatch {
			txmode = etherconn.XDPSendingModeBatch
		}
		r.relay, err = etherconn.NewXDPRelay(ctx, ifname,
			etherconn.WithSendingMode(txmode),
			etherconn.WithQueueID(qidList),
			etherconn.WithXDPUMEMNumOfTrunk(numchunk),
			etherconn.WithXDPPerClntRecvChanDepth(relayRcvDepth),
			etherconn.WithXDPDebug(debug),
			etherconn.WithXDPUMEMChunkSize(maxFrameSize))
		if err != nil {
			return nil, fmt.Errorf("failed to create xdp relay for interface %v, %w", ifname, err)
		}
		return r, nil
	}
}

func (ecif *ECInterface) Send(ctx context.Context,
	bcfg *BatchTrafficConfig, srcMAC, dstMAC net.HardwareAddr,
	wg *sync.WaitGroup) {
	//creating shareEtherConn
	ec := etherconn.NewSharedEtherConn(ctx, srcMAC, ecif.relay,
		[]etherconn.EtherConnOption{
			etherconn.WithEtherTypes([]uint16{uint16(layers.EthernetTypeIPv4)}),
		},
		etherconn.WithSharedEConnPerClntRecvChanDepth(ecif.econnRcvDepth),
	)
	//creating ShareRUDPConn
	pktCfgList, err := generatePktConfigs(bcfg)
	if err != nil {
		log.Fatalf("failed to generate pkt config list, %v", err)
	}
	// udpList := []*etherconn.SharingRUDPConn{}
	wg.Add(len(pktCfgList))
	// ecif.sendCounterList = make([]uint64, len(pktCfgList))
	for i, pcfg := range pktCfgList {
		uc, err := etherconn.NewSharingRUDPConn(
			fmt.Sprintf("%v:%d", pcfg.SrcIP, pcfg.SrcPort), ec,
			[]etherconn.RUDPConnOption{
				etherconn.WithResolveNextHopMacFunc(func(net.IP) net.HardwareAddr { return dstMAC }),
			})
		if err != nil {
			log.Fatalf("failed to create sharingUDPConn, %v", err)
		}
		// udpList = append(udpList, uc)
		payload := make([]byte, pcfg.Len)
		rand.Read(payload)

		go func(ctx context.Context, ruc *etherconn.SharingRUDPConn, spayload []byte, index int, cfg *PktConfig, uwg *sync.WaitGroup) {
			var serr error
			runtime.LockOSThread()
			defer uwg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				default:
				}
				_, serr = ruc.WriteTo(spayload, &net.UDPAddr{IP: cfg.DstIP, Port: int(cfg.DstPort)})
				if serr != nil {
					log.Fatalf("send err: %v", serr)
				}
				// ecif.sendCounterList[index]++
				time.Sleep(bcfg.Interval)

			}
		}(ctx, uc, payload, i, pcfg, wg)
	}

}

func (ecif *ECInterface) Recv(ctx context.Context, bcfg *BatchTrafficConfig,
	ownMAC net.HardwareAddr,
	wg *sync.WaitGroup) {
	//creating shareEtherConn
	ec := etherconn.NewSharedEtherConn(ctx, ownMAC, ecif.relay,
		[]etherconn.EtherConnOption{
			etherconn.WithEtherTypes([]uint16{uint16(layers.EthernetTypeIPv4)})},
		etherconn.WithSharedEConnPerClntRecvChanDepth(ecif.econnRcvDepth),
	)
	//creating ShareRUDPConn
	pktCfgList, err := generatePktConfigs(bcfg)
	if err != nil {
		log.Fatalf("failed to generate pkt config list, %v", err)
	}
	// udpList := []*etherconn.SharingRUDPConn{}
	wg.Add(len(pktCfgList))
	for _, pcfg := range pktCfgList {
		uc, err := etherconn.NewSharingRUDPConn(
			fmt.Sprintf("%v:%d", pcfg.DstIP, pcfg.DstPort), ec,
			[]etherconn.RUDPConnOption{})
		if err != nil {
			log.Fatalf("failed to create sharingUDPConn, %v", err)
		}
		buf := make([]byte, pcfg.Len)

		go func(ctx context.Context, uwg *sync.WaitGroup) {
			defer uwg.Done()
			select {
			case <-ctx.Done():
				return
			default:
			}
			uc.SetReadDeadline(time.Now().Add(5 * time.Second))
			_, _, err := uc.ReadFrom(buf)
			if err != nil {
				if !errors.Is(err, etherconn.ErrTimeOut) {
					log.Fatalf("sharingRUDPConn %v read failed, %v", uc.LocalAddr(), err)
				}
			}
		}(ctx, wg)
	}
}

func (ecif *ECInterface) GetCounters() (numSend, numRcv uint64) {
	stats := ecif.relay.GetStats()
	return *stats.Tx, *stats.Rx
}
func (ecif *ECInterface) Stop() {
	ecif.relay.Stop()
}
