// XDPRelay uses Linux AF_XDP socket as the underlying forwarding mechinism, so it achives higher performance than RawSocketRelay;
// XDPRelay usage notes:
//	1. for virtio interface, the number of queues provisioned needs to be 2x of number CPU cores VM has, binding will fail otherwise.
//	2. AF_XDP is still relative new, see XDP kernel&driver support status: https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md#xdp
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

	"golang.org/x/sys/unix"

	"github.com/asavie/xdp"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
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
	prog *xdp.Program, sendchanDepth uint,
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
		toSendChan:    make(chan []byte, sendchanDepth),
		wg:            wg,
		qid:           qid,
		logger:        logger,
	}
	go r.recv(ctx)
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

func (s *xdpsock) sendPkt(data []byte) error {
	s.sock.Complete(s.sock.NumCompleted())
	descs := s.sock.GetDescs(1)
	if len(descs) < 1 {
		return fmt.Errorf("unable to get xdp desc")
	}
	copy(s.sock.GetFrame(descs[0]), data)
	descs[0].Len = uint32(len(data))
	if s.sock.Transmit(descs) != 1 {
		return fmt.Errorf("failed to submit pkt to xdp tx ring")
	}
	return nil
}

func (s *xdpsock) mypollrecv(timeout int) (int, error) {
	events := int16(unix.POLLIN)
	// if xsk.numFilled > 0 {
	// 	events |= unix.POLLIN
	// }
	// if xsk.numTransmitted > 0 {
	// 	events |= unix.POLLOUT
	// }
	// if events == 0 {
	// 	return
	// }

	var pfds [1]unix.PollFd
	pfds[0].Fd = int32(s.sock.FD())
	pfds[0].Events = events
	var err error
	for err = unix.EINTR; err == unix.EINTR; {
		_, err = unix.Poll(pfds[:], timeout)
	}
	if err != nil {
		return 0, err
	}
	return s.sock.NumReceived(), nil
}

func (s *xdpsock) recv(ctx context.Context) {
	defer s.wg.Done()
	var numRx int
	var err error
	for {
		if n := s.sock.NumFreeFillSlots(); n > 0 {
			s.sock.Fill(s.sock.GetDescs(n))
		}
		numRx, err = s.mypollrecv(1)
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
				rxDescs := s.sock.Receive(numRx)
				for i := 0; i < len(rxDescs); i++ {
					pktData := make([]byte, len(s.sock.GetFrame(rxDescs[i])))
					copy(pktData, s.sock.GetFrame(rxDescs[i]))
					s.recvBytesChan <- pktData
				}
			}
		}
	}
}

func (s *xdpsock) poll2(ctx context.Context) {
	// runtime.LockOSThread()
	// defer runtime.UnlockOSThread()
	defer s.wg.Done()
	var needSending bool
	var data []byte
	var numRx, round int
	for {
		round++
		if round%100 == 0 {
			select {
			case <-ctx.Done():
				return
			default:
			}
		}
		//complets
		s.sock.Complete(s.sock.NumCompleted())
		//prepare fill buffer for recving
		if n := s.sock.NumFreeFillSlots(); n > 0 {
			s.sock.Fill(s.sock.GetDescs(n))
		}
		//sending
		if s.sock.NumFreeTxSlots() > 0 {
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
		}
		numRx = s.sock.NumReceived()
		if numRx > 0 {
			rxDescs := s.sock.Receive(numRx)
			for i := 0; i < len(rxDescs); i++ {
				pktData := make([]byte, len(s.sock.GetFrame(rxDescs[i])))
				copy(pktData, s.sock.GetFrame(rxDescs[i]))
				s.recvBytesChan <- pktData
			}
		}
	}
}

func (s *xdpsock) poll(ctx context.Context) {
	// runtime.LockOSThread()
	// defer runtime.UnlockOSThread()
	defer s.wg.Done()
	var datasToSend [][]byte
	var sendBatchSize = 100
	var batchSize int

	for {

		if n := s.sock.NumFreeFillSlots(); n > 0 {
			s.sock.Fill(s.sock.GetDescs(n))
		}
		datasToSend = [][]byte{}
		for i := 0; i < sendBatchSize; i++ {
			select {
			case data := <-s.toSendChan:
				datasToSend = append(datasToSend, data)
			default:
				break
			}
		}
		batchSize = len(datasToSend)
		if batchSize > 0 {
			descs := s.sock.GetDescs(batchSize)
			if len(descs) < batchSize {
				continue
			}
			for i, data := range datasToSend {
				copy(s.sock.GetFrame(descs[i]), data)
				descs[i].Len = uint32(len(data))
			}
			s.sock.Transmit(descs)
		}
		numRx, _, err := s.sock.Poll(0)
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
				rxDescs := s.sock.Receive(numRx)
				for i := 0; i < len(rxDescs); i++ {
					pktData := make([]byte, len(s.sock.GetFrame(rxDescs[i])))
					copy(pktData, s.sock.GetFrame(rxDescs[i]))
					s.recvBytesChan <- pktData
				}
			}
		}
	}
}

// XDPRelay is a PacketRelay implementation that uses AF_XDP Socket
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
	umemNumofTrunk       uint
	stats                *RelayPacketStats
	logger               *log.Logger
	ifName               string
	ifLink               netlink.Link
	defaultRecvChan      chan *RelayReceival
	mirrorToDefault      bool
	recvBytesChan        chan []byte
}

// XDPRelayOption could be used in NewXDPRelay to customize XDPRelay upon creation
type XDPRelayOption func(xr *XDPRelay)

// WithQueueID specifies a list of interface queue id (start from 0) that the XDPRelay binds to;
// note: only use this option if you know what you are doing, since this could cause XDPRelay unable to receive some of packets.
func WithQueueID(qidlist []int) XDPRelayOption {
	return func(xr *XDPRelay) {
		if xr.qIDList == nil {
			xr.qIDList = []int{}
		}
		xr.qIDList = append(xr.qIDList, qidlist...)
	}
}

// WithXDPUMEMNumOfTrunk specifies the number of UMEM trunks,
// must be power of 2.
// the Fill/Completion/TX/RX ring size is half of specified value;
func WithXDPUMEMNumOfTrunk(num uint) XDPRelayOption {
	if num%2 != 0 {
		return nil
	}
	return func(xr *XDPRelay) {
		xr.umemNumofTrunk = num
	}
}

// WithXDPMaxEtherFrameSize specifies the maximum ethernet packet size could be received by XDPRelay,
// must be power of 2.
func WithXDPMaxEtherFrameSize(fsize uint) XDPRelayOption {
	if fsize%2 != 0 {
		return nil
	}
	return func(xr *XDPRelay) {
		xr.maxEtherFrameSize = fsize
	}
}

// WithXDPDefaultReceival creates a default receiving channel,
// all received pkt doesn't match any explicit EtherConn, will be sent to this channel;
// using RegisterDefault to get the default receiving channel.
// if mirroring is true, then every received pkt will be sent to this channel.
func WithXDPDefaultReceival(mirroring bool) XDPRelayOption {
	return func(xr *XDPRelay) {
		xr.defaultRecvChan = make(chan *RelayReceival, xr.perClntRecvChanDepth)
		xr.mirrorToDefault = mirroring
	}
}

// WithXDPDebug enable/disable debug log output
func WithXDPDebug(debug bool) XDPRelayOption {
	return func(relay *XDPRelay) {
		if debug {
			relay.logger = log.New(os.Stderr, "", log.Ldate|log.Ltime)
		} else {
			relay.logger = nil
		}
	}
}

// WithXDPSendChanDepth set the dep  th in sending channel
func WithXDPSendChanDepth(depth uint) XDPRelayOption {
	return func(relay *XDPRelay) {
		relay.sendChanDepth = depth
	}
}

// WithXDPRecvChanDepth set the depth in recving channel
func WithXDPRecvChanDepth(depth uint) XDPRelayOption {
	return func(relay *XDPRelay) {
		relay.perClntRecvChanDepth = depth
	}
}

// DefaultXDPUMEMNumOfTrunk is the default number of UMEM trunks
const DefaultXDPUMEMNumOfTrunk = 16384

// NewXDPRelay creates a new instance of XDPRelay,
// by default, the XDPRelay binds to all queues of the specified interface
func NewXDPRelay(parentctx context.Context, ifname string, options ...XDPRelayOption) (*XDPRelay, error) {
	r := &XDPRelay{
		ifName:               ifname,
		stopToSendChan:       make(chan struct{}),
		perClntRecvChanDepth: DefaultPerClntRecvChanDepth,
		sendChanDepth:        DefaultSendChanDepth,
		maxEtherFrameSize:    DefaultMaxEtherFrameSize,
		umemNumofTrunk:       DefaultXDPUMEMNumOfTrunk,
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

	socketOP := &xdp.SocketOptions{
		NumFrames:              int(r.umemNumofTrunk),
		FrameSize:              int(r.maxEtherFrameSize),
		FillRingNumDescs:       int(r.umemNumofTrunk / 2),
		CompletionRingNumDescs: int(r.umemNumofTrunk / 2),
		RxRingNumDescs:         int(r.umemNumofTrunk / 2),
		TxRingNumDescs:         int(r.umemNumofTrunk / 2),
	}
	//xdp.DefaultSocketFlags = unix.XDP_USE_NEED_WAKEUP
	var ctx context.Context
	ctx, r.cancelFunc = context.WithCancel(parentctx)
	for _, qid := range r.qIDList {
		r.wg.Add(1)
		xsk, err := newXdpsock(ctx, r.ifLink.Attrs().Index, qid, socketOP,
			r.bpfProg, r.sendChanDepth, r.recvBytesChan, r.wg, r.logger)
		if err != nil {
			return nil, err
		}
		r.sockList = append(r.sockList, xsk)
	}
	r.wg.Add(2)
	go r.handleRecvBytes(ctx)
	go r.handleSending(ctx)
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
	defer xr.cleanup()
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

// GetStats returns the stats
func (xr *XDPRelay) GetStats() *RelayPacketStats {
	return xr.stats
}

// handleSending round-robin egress pkts via all queues
func (xr *XDPRelay) handleSending(ctx context.Context) {
	defer xr.wg.Done()
	var err error
	i := 0
	max := len(xr.sockList)
	for {
		select {
		case <-ctx.Done():
			return
		case data := <-xr.toSendChan:
			// below line is for integrated appraoch
			// xr.sockList[0].toSendChan <- data
			/// below block is for seperated approach
			if err = xr.sockList[0].sendPkt(data); err != nil {
				xr.log("failed to send pkt, %v", err)
				return
			}
			atomic.AddUint64(xr.stats.Tx, 1)
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
				// found match etherconn
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
