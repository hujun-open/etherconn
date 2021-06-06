// xdpconn
package etherconn

import (
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	// "golang.org/x/sys/unix"

	"github.com/asavie/xdp"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"

	// "github.com/hujun-open/xdp"
	"github.com/safchain/ethtool"
	"github.com/vishvananda/netlink"
)

type xdpsock struct {
	sock          *xdp.Socket
	qid           int
	toSendChan    chan []byte //own channel
	recvBytesChan chan []byte //refered to XDPRelay's recvBytesChan
	wg            *sync.WaitGroup
	logger        *log.Logger
}

// getNumQ use ethtool to get number of combined Q, return 1 if failed to get channel info
func getNumQ(ifname string) (int, error) {
	ethHandle, err := ethtool.NewEthtool()
	if err != nil {
		return -1, err
	}
	defer ethHandle.Close()

	// Retrieve channels
	chans, err := ethHandle.GetChannels(ifname)
	if err != nil {
		return 1, nil
	}
	return int(chans.CombinedCount), nil
}

func newXdpsock(ctx context.Context, ifindex, qid int, sockopt *xdp.SocketOptions,
	prog *xdp.Program, sendchan_depth uint,
	recvchan chan []byte, wg *sync.WaitGroup,
	logger *log.Logger) (*xdpsock, error) {
	var sock *xdp.Socket
	var err error
	if sock, err = xdp.NewSocket(ifindex, qid, sockopt); err != nil {
		return nil, fmt.Errorf("failed to create new XDP socket for queue %d, %w", qid, err)
	}
	if err = prog.Register(qid, sock.FD()); err != nil {
		return nil, fmt.Errorf("failed to register xdp socekt to program for queue %d, %w", qid, err)
	}
	r := &xdpsock{
		sock:          sock,
		recvBytesChan: recvchan,
		toSendChan:    make(chan []byte, sendchan_depth),
		wg:            wg,
		qid:           qid,
		logger:        logger,
	}
	go r.poll(ctx)
	return r, nil

}

func (s *xdpsock) log(format string, a ...interface{}) {
	if s.logger == nil {
		return
	}
	msg := fmt.Sprintf(format, a...)
	_, fname, linenum, _ := runtime.Caller(1)
	s.logger.Print(fmt.Sprintf("%v:%v:Q%d:%v", filepath.Base(fname), linenum, s.qid, msg))
}

func (s *xdpsock) poll(ctx context.Context) {
	defer s.wg.Done()
	var needSending bool
	var data []byte
	for {
		if n := s.sock.NumFreeFillSlots(); n > 0 {
			// ...then fetch up to that number of not-in-use
			// descriptors and push them onto the Fill ring queue
			// for the kernel to fill them with the received
			// frames.
			// xr.log("filling for %d slots", n)
			s.sock.Fill(s.sock.GetDescs(n))
		}
		needSending = false
		select {
		case data = <-s.toSendChan:
			needSending = true
		default:
		}
		if needSending {
			descs := s.sock.GetDescs(1)
			if len(descs) < 1 {
				continue
			}
			copy(s.sock.GetFrame(descs[0]), data)
			descs[0].Len = uint32(len(data))
			s.sock.Transmit(descs)
		}
		numRx, _, err := s.sock.Poll(1)
		if err != nil {
			if errors.Is(err, syscall.ETIMEDOUT) {

				select {
				case <-ctx.Done():
					return
				default:
					continue
				}
			} else {
				s.log("poll error, abort, %v", err)
				return
			}
		} else {
			if numRx > 0 {
				// Consume the descriptors filled with received frames
				// from the Rx ring queue.
				rxDescs := s.sock.Receive(numRx)
				s.log("xdp consume rxring %v", len(rxDescs))
				for i := 0; i < len(rxDescs); i++ {
					pktData := make([]byte, len(s.sock.GetFrame(rxDescs[i])))
					copy(pktData, s.sock.GetFrame(rxDescs[i]))
					s.recvBytesChan <- pktData
				}
			}
		}
	}
}

type XDPRelay struct {
	sockList             []*xdpsock
	qIDList              []int
	bpfProg              *xdp.Program
	toSendChan           chan []byte
	stopToSendChan       chan struct{}
	recvList             *chanMap
	wg                   *sync.WaitGroup
	cancelFunc           context.CancelFunc
	recvTimeout          time.Duration
	multicastList        *chanMap
	perClntRecvChanDepth uint
	sendChanDepth        uint
	maxEtherFrameSize    uint
	stats                *RelayPacketStats
	logger               *log.Logger
	ifName               string
	ifLink               netlink.Link
	defaultRecvChan      chan *RelayReceival
	mirrorToDefault      bool
	recvBytesChan        chan []byte
}
type XDPRelayOption func(xr *XDPRelay)

func WithQueueID(qidlist []int) XDPRelayOption {
	return func(xr *XDPRelay) {
		if xr.qIDList == nil {
			xr.qIDList = []int{}
		}
		xr.qIDList = append(xr.qIDList, qidlist...)
	}
}

func WithXDPDefaultReceival(mirroring bool) XDPRelayOption {
	return func(xr *XDPRelay) {
		xr.defaultRecvChan = make(chan *RelayReceival, xr.perClntRecvChanDepth)
		xr.mirrorToDefault = mirroring
	}
}

// WithDebug enable/disable debug log output
func WithXDPDebug(debug bool) XDPRelayOption {
	return func(relay *XDPRelay) {
		if debug {
			relay.logger = log.New(os.Stderr, "", log.Ldate|log.Ltime)
		} else {
			relay.logger = nil
		}
	}
}

func NewXDPRelay(parentctx context.Context, ifname string, options ...XDPRelayOption) (*XDPRelay, error) {
	r := &XDPRelay{
		ifName:               ifname,
		stopToSendChan:       make(chan struct{}),
		perClntRecvChanDepth: DefaultPerClntRecvChanDepth,
		sendChanDepth:        DefaultSendChanDepth,
		maxEtherFrameSize:    DefaultMaxEtherFrameSize,
		recvList:             newchanMap(),
		multicastList:        newchanMap(),
		stats:                newRelayPacketStats(),
		wg:                   new(sync.WaitGroup),
		recvBytesChan:        make(chan []byte, 1024),
	}
	var err error
	if r.ifLink, err = netlink.LinkByName(ifname); err != nil {
		return nil, err
	}

	for _, o := range options {
		o(r)
	}
	//generate qIDList
	if len(r.qIDList) == 0 {
		numQ, err := getNumQ(ifname)
		if err != nil {
			return nil, err
		}
		for i := 0; i < numQ; i++ {
			r.qIDList = append(r.qIDList, i)
		}
	}
	r.toSendChan = make(chan []byte, r.sendChanDepth)
	if r.bpfProg, err = xdp.NewProgram(len(r.qIDList)); err != nil {
		return nil, fmt.Errorf("failed to create new program, %w", err)
	}
	if err = r.bpfProg.Attach(r.ifLink.Attrs().Index); err != nil {
		return nil, fmt.Errorf("failed to attach new program, %w", err)
	}

	numFrame := 16384
	socket_option := &xdp.SocketOptions{
		NumFrames:              numFrame,
		FrameSize:              2048,
		FillRingNumDescs:       numFrame / 2,
		CompletionRingNumDescs: numFrame / 2,
		RxRingNumDescs:         numFrame / 2,
		TxRingNumDescs:         numFrame / 2,
	}
	var ctx context.Context
	ctx, r.cancelFunc = context.WithCancel(parentctx)
	for _, qid := range r.qIDList {
		r.wg.Add(1)
		xsk, err := newXdpsock(ctx, r.ifLink.Attrs().Index, qid, socket_option,
			r.bpfProg, r.sendChanDepth, r.recvBytesChan, r.wg, r.logger)
		if err != nil {
			return nil, err
		}
		r.sockList = append(r.sockList, xsk)
	}
	r.wg.Add(2)
	go r.handleRecvBytes(ctx)
	go r.handleEgress(ctx)
	return r, nil
}
func (xr *XDPRelay) log(format string, a ...interface{}) {
	if xr.logger == nil {
		return
	}
	msg := fmt.Sprintf(format, a...)
	_, fname, linenum, _ := runtime.Caller(1)
	xr.logger.Print(fmt.Sprintf("%v:%v:%v:%v", filepath.Base(fname), linenum, xr.ifName, msg))
}
func (xr *XDPRelay) cleanup() {
	for _, qid := range xr.qIDList {
		xr.bpfProg.Unregister(qid)
	}
	xr.bpfProg.Detach(xr.ifLink.Attrs().Index)
}

// Stop implements PacketRelay interface
func (xr *XDPRelay) Stop() {
	xr.log("relay stopping")
	xr.cancelFunc()
	// this ticker is to make sure relay stop in case poll timeout is not supported by kernel(need TPacketV3)
	// ticker time can't be too small, otherwise, if the xr.conn.Close before recv or send routine quit, it might cause panic
	ticker := time.NewTicker(xr.recvTimeout + 3*time.Second)
	defer ticker.Stop()
	done := make(chan bool)
	go func(d chan bool) {
		xr.wg.Wait()
		d <- true

	}(done)
	select {
	case <-done:
	case <-ticker.C:
	}
	xr.log(fmt.Sprintf("XDPRelay stats:\n%v", xr.stats.String()))
	xr.cleanup()
}

// IfName implements PacketRelay interface;
func (xr *XDPRelay) IfName() string {
	return xr.ifName
}

// Register implements PacketRelay interface;
func (xr *XDPRelay) Register(ks []L2EndpointKey, recvMulticast bool) (chan *RelayReceival, chan []byte, chan struct{}) {
	ch := make(chan *RelayReceival, xr.perClntRecvChanDepth)
	list := make([]interface{}, len(ks))
	for i := range ks {
		list[i] = ks[i]
	}
	xr.recvList.SetList(list, ch)
	if recvMulticast {
		//NOTE: only set one key in multicast, otherwise the EtherConn will receive multiple copies
		xr.multicastList.Set(ks[0], ch)
	}
	return ch, xr.toSendChan, xr.stopToSendChan
}

// RegisterDefault implements PacketRelay interface
func (xr *XDPRelay) RegisterDefault() (chan *RelayReceival, chan []byte, chan struct{}) {
	return xr.defaultRecvChan, xr.toSendChan, xr.stopToSendChan
}

// Deregister implements PacketRelay interface;
func (xr *XDPRelay) Deregister(ks []L2EndpointKey) {
	list := make([]interface{}, len(ks))
	for i := range ks {
		list[i] = ks[i]
	}
	xr.recvList.DelList(list)
	xr.multicastList.DelList(list)
}

func (xr *XDPRelay) GetStats() *RelayPacketStats {
	return xr.stats
}

// func (xr *XDPRelay) poll(ctx context.Context) {
// 	defer xr.wg.Done()
// 	var needSending bool
// 	var data []byte
// 	for {
// 		if n := xr.sock.NumFreeFillSlots(); n > 0 {
// 			// ...then fetch up to that number of not-in-use
// 			// descriptors and push them onto the Fill ring queue
// 			// for the kernel to fill them with the received
// 			// frames.
// 			// xr.log("filling for %d slots", n)
// 			xr.sock.Fill(xr.sock.GetDescs(n))

// 		}
// 		needSending = false
// 		select {
// 		case data = <-xr.toSendChan:
// 			needSending = true
// 		default:
// 		}
// 		if needSending {
// 			descs := xr.sock.GetDescs(1)
// 			if len(descs) < 1 {
// 				continue
// 			}
// 			copy(xr.sock.GetFrame(descs[0]), data)
// 			descs[0].Len = uint32(len(data))
// 			xr.sock.Transmit(descs)
// 		}
// 		// xr.log("polling, need sending %v", needSending)
// 		numRx, _, err := xr.sock.Poll(1)
// 		if err != nil {
// 			// xr.log("poll err, %v", err)
// 			if errors.Is(err, syscall.ETIMEDOUT) {

// 				select {
// 				case <-ctx.Done():
// 					return
// 				default:
// 					continue
// 				}
// 			} else {
// 				xr.log("poll error, abort, %v", err)
// 				return
// 			}
// 		} else {
// 			// xr.log("numRx %d numTX %d", numRx, numTx)
// 			if numRx > 0 {
// 				// Consume the descriptors filled with received frames
// 				// from the Rx ring queue.
// 				rxDescs := xr.sock.Receive(numRx)
// 				xr.log("xdp consume rxring %v", len(rxDescs))
// 				for i := 0; i < len(rxDescs); i++ {
// 					pktData := make([]byte, len(xr.sock.GetFrame(rxDescs[i])))
// 					copy(pktData, xr.sock.GetFrame(rxDescs[i]))
// 					xr.recvBytesChan <- pktData
// 				}
// 			}
// 			// if numComp > 0 {
// 			// 	// go func() {
// 			// 	// 	xr.xskSendChan <- numComp
// 			// 	// }()
// 			// }
// 		}

// 	}
// }

func (xr *XDPRelay) handleEgress(ctx context.Context) {
	defer xr.wg.Done()
	i := 0
	max := len(xr.sockList)
	for {
		select {
		case <-ctx.Done():
			return
		case data := <-xr.toSendChan:
			xr.sockList[0].toSendChan <- data
			if i+1 >= max {
				i = 0
			} else {
				i++
			}
		}
	}
}

func (xr *XDPRelay) handleRecvBytes(ctx context.Context) {
	defer xr.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case pktData := <-xr.recvBytesChan:
			atomic.AddUint64(xr.stats.RxOffered, 1)
			if checkPacketBytes(pktData) != nil {
				atomic.AddUint64(xr.stats.RxInvalid, 1)
				continue
			}
			gpacket := gopacket.NewPacket(pktData, layers.LayerTypeEthernet, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
			l2ep, rmac := getEtherAdrrInfoFromPacket(gpacket, false)
			receival := newRelayReceival()
			xr.log("got pkt with l2epkey %v", l2ep.GetKey().String())
			if rcvchan := xr.recvList.Get(l2ep.GetKey()); rcvchan != nil {
				receival.EtherBytes = pktData
				//NOTE: create go routine here since sendToChanWithCounter will parse the pkt, need some CPU
				go sendToChanWithCounter(receival, rmac, rcvchan, gpacket, xr.stats.Rx, xr.stats.RxBufferFull)
				if xr.mirrorToDefault && xr.defaultRecvChan != nil {
					go sendToChanWithCounter(receival, rmac, xr.defaultRecvChan, gpacket, xr.stats.Rx, xr.stats.RxBufferFull)
				}
			} else {
				if l2ep.HwAddr[0]&0x1 == 1 { //multicast traffic
					mList := xr.multicastList.GetList()
					zeroMList := false
					if len(mList) > 0 {
						for _, mrcvchan := range mList {
							newbuf := make([]byte, len(pktData))
							copy(newbuf, pktData)
							receival.EtherBytes = newbuf
							//TODO: might need also a new gpacket here
							go sendToChanWithCounter(receival, rmac, mrcvchan, gpacket, xr.stats.RxNonHitMulticast, xr.stats.RxBufferFull)
						}
					} else {
						zeroMList = true
					}
					if xr.defaultRecvChan != nil {
						receival.EtherBytes = pktData
						go sendToChanWithCounter(receival, rmac, xr.defaultRecvChan, gpacket, xr.stats.Rx, xr.stats.RxBufferFull)

					} else {
						if zeroMList {
							xr.log("ignored a multicast pkt")
							atomic.AddUint64(xr.stats.RxMulticastIgnored, 1)
						}
					}
				} else { //unicast but can't find reciver
					if xr.defaultRecvChan != nil {
						receival.EtherBytes = pktData
						go sendToChanWithCounter(receival, rmac, xr.defaultRecvChan, gpacket, xr.stats.Rx, xr.stats.RxBufferFull)
					} else {
						xr.log(fmt.Sprintf("can't find match l2ep %v", l2ep.GetKey().String()))
						atomic.AddUint64(xr.stats.RxMiss, 1)
					}
				}
			}
		}
	}
}
