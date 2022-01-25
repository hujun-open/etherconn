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
	"net"
	"os"
	"path/filepath"
	"runtime"
	"sort"
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

const (
	//DefaultXDPChunkSize is the default size for XDP UMEM chunk
	DefaultXDPChunkSize = 4096
)

// XDPSocketPktHandler is a handler function could be used for rx/tx packet of a XDP socket
type XDPSocketPktHandler func(pbytes []byte, sockid int) error

type xdpSock struct {
	sock *xdp.Socket
	qid  int
	// stats *XdpSockStats
	relay *XDPRelay
}

// XdpSockStats hold per XDP socket/queue stats
type XdpSockStats struct {
	Sent, Recv uint64
}

type XdpSockStatsList map[int]*XdpSockStats

func (list XdpSockStatsList) String() string {
	var keys []int
	for k := range list {
		keys = append(keys, k)
	}
	sort.Ints(keys)
	r := ""
	for _, qid := range keys {
		r = r + fmt.Sprintf("socket %d stats: %+v\n", qid, *(list[qid]))
	}
	return r
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

func newXdpsock(ctx context.Context, qid int,
	sockopt *xdp.SocketOptions,
	xrelay *XDPRelay) (*xdpSock, error) {
	var sock *xdp.Socket
	var err error
	if sock, err = xdp.NewSocket(xrelay.ifLink.Attrs().Index, qid, sockopt); err != nil {
		return nil, fmt.Errorf("failed to create new XDP socket for queue %d, %w", qid, err)
	}
	if err = xrelay.bpfProg.Register(qid, sock.FD()); err != nil {
		return nil, fmt.Errorf("failed to register xdp socekt to program for queue %d, %w", qid, err)
	}
	r := &xdpSock{
		relay: xrelay,
		sock:  sock,
		qid:   qid,
	}
	go r.recv(ctx)
	return r, nil

}

func (s *xdpSock) log(format string, a ...interface{}) {
	if s.relay.logger == nil {
		return
	}
	msg := fmt.Sprintf(format, a...)
	_, fname, linenum, _ := runtime.Caller(1)
	s.relay.logger.Print(fmt.Sprintf("%v:%v:Q%d:%v", filepath.Base(fname), linenum, s.qid, msg))
}

func (s *xdpSock) sendPkts(datas [][]byte) error {
	numToSend := len(datas)
	// completed := s.sock.NumCompleted()
	// if completed < numToSend && completed != 0 {
	// 	return fmt.Errorf("socket's numCompleted is less than needed")
	// }
	// s.sock.Complete(numToSend)
	descs := s.sock.GetDescs(numToSend, false)
	if len(descs) < numToSend {
		return fmt.Errorf("unable to get xdp desc")
	}
	for i, data := range datas {
		if s.relay.txh != nil {
			s.relay.txh(data, s.qid)
		}
		copy(s.sock.GetFrame(descs[i]), data)
		descs[i].Len = uint32(len(data))
	}
	if rnum := s.sock.Transmit(descs); rnum != numToSend {
		return fmt.Errorf("failed to submit pkt to xdp tx ring, need to send %d, only sent %d", numToSend, rnum)
	}
	if _, _, err := s.sock.Poll(1); err != nil {
		return err
	}
	return nil
}

func (s *xdpSock) mypollrecv(timeout int) (int, error) {
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

func (s *xdpSock) recv(ctx context.Context) {
	runtime.LockOSThread()
	defer s.relay.wg.Done()
	var numRx int
	var err error
	for {
		if n := s.sock.NumFreeFillSlots(); n > 0 {
			s.sock.Fill(s.sock.GetDescs(n, true))
		}
		numRx, err = s.mypollrecv(-1)
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
					if s.relay.rxh != nil {
						s.relay.rxh(pktData, s.qid)
					}
					handleRcvPkt(pktData, s.relay.stats, s.relay.log,
						s.relay.recvList, s.relay.mirrorToDefault,
						s.relay.defaultRecvChan, s.relay.multicastList, nil)
				}
			}
		}
	}
}

// XDPRelay is a PacketRelay implementation that uses AF_XDP Socket
type XDPRelay struct {
	sockList                                                                []*xdpSock
	qIDList                                                                 []int
	bpfProg                                                                 *xdp.Program
	extBPFProgFileName, extBPFProgName, extBPFQMapName, extBPFSocketMapName string
	toSendChan                                                              chan []byte
	stopToSendChan                                                          chan struct{}
	recvList                                                                *chanMap
	wg                                                                      *sync.WaitGroup
	cancelFunc                                                              context.CancelFunc
	recvTimeout                                                             time.Duration
	multicastList                                                           *chanMap
	perClntRecvChanDepth                                                    uint
	sendChanDepth                                                           uint
	//maxEtherFrameSize could only be 2048 or 4096
	maxEtherFrameSize             uint
	umemNumofTrunk                uint
	stats                         *RelayPacketStats
	logger                        *log.Logger
	ifName                        string
	ifLink                        netlink.Link
	defaultRecvChan               chan *RelayReceival
	mirrorToDefault               bool
	recvBytesChan                 chan []byte
	dedicateThread                bool
	rxh, txh                      XDPSocketPktHandler
	currentXDPSockAssignIndex     int
	currentXDPSockAssignIndexLock *sync.RWMutex
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

// WithXDPDedicateThread will use dedicate OS thread for sending/recving if dedicate is true
func WithXDPDedicateThread(dedicate bool) XDPRelayOption {
	return func(xr *XDPRelay) {
		xr.dedicateThread = dedicate
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

// WithXDPUMEMChunkSize specifies the XDP UMEM size,
// which implicitly set the max packet size could be handled by XDPRelay,
// must be either 4096 or 2048 (kernel XDP limitation)
func WithXDPUMEMChunkSize(fsize uint) XDPRelayOption {
	if fsize != 4096 && fsize != 2048 {
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

// WithXDPExtProg loads an external XDP kernel program iso using the built-in one
func WithXDPExtProg(fname, prog, qmap, xskmap string) XDPRelayOption {
	return func(relay *XDPRelay) {
		relay.extBPFProgFileName = fname
		relay.extBPFProgName = prog
		relay.extBPFQMapName = qmap
		relay.extBPFSocketMapName = xskmap
	}
}

// WithXDPRXPktHandler sets h as the rx packet handler
func WithXDPRXPktHandler(h XDPSocketPktHandler) XDPRelayOption {
	return func(relay *XDPRelay) {
		relay.rxh = h
	}
}

// WithXDPTXPktHandler sets h as the tx packet handler
func WithXDPTXPktHandler(h XDPSocketPktHandler) XDPRelayOption {
	return func(relay *XDPRelay) {
		relay.txh = h
	}
}

const (
	// DefaultXDPUMEMNumOfTrunk is the default number of UMEM trunks
	DefaultXDPUMEMNumOfTrunk = 16384
)

// NewXDPRelay creates a new instance of XDPRelay,
// by default, the XDPRelay binds to all queues of the specified interface
func NewXDPRelay(parentctx context.Context, ifname string, options ...XDPRelayOption) (*XDPRelay, error) {
	r := &XDPRelay{
		ifName:                        ifname,
		stopToSendChan:                make(chan struct{}),
		perClntRecvChanDepth:          DefaultPerClntRecvChanDepth,
		sendChanDepth:                 DefaultSendChanDepth,
		maxEtherFrameSize:             DefaultXDPChunkSize,
		umemNumofTrunk:                DefaultXDPUMEMNumOfTrunk,
		recvList:                      newchanMap(),
		multicastList:                 newchanMap(),
		stats:                         newRelayPacketStats(),
		wg:                            new(sync.WaitGroup),
		currentXDPSockAssignIndex:     0,
		currentXDPSockAssignIndexLock: new(sync.RWMutex),
	}
	var err error
	if r.ifLink, err = netlink.LinkByName(ifname); err != nil {
		return nil, err
	}
	err = setPromisc(ifname)
	if err != nil {
		return nil, fmt.Errorf("failed to set %v to Promisc mode,%w", ifname, err)

	}

	for _, o := range options {
		o(r)
	}
	r.recvBytesChan = make(chan []byte, int(r.perClntRecvChanDepth)*len(r.qIDList))
	//generate qIDList
	if len(r.qIDList) == 0 {
		numQ, err := getNumQ(ifname)
		if err != nil {
			return nil, err
		}
		fmt.Printf("creating %d queues\n", numQ)
		for i := 0; i < numQ; i++ {
			r.qIDList = append(r.qIDList, i)
		}
	}
	r.toSendChan = make(chan []byte, r.sendChanDepth)
	if r.extBPFProgFileName == "" {
		//using built-in program
		if r.bpfProg, err = xdp.NewProgram(len(r.qIDList)); err != nil {
			return nil, fmt.Errorf("failed to create built-in xdp kernel program, %w", err)
		}
	} else {
		//load external one
		if r.bpfProg, err = xdp.LoadProgram(r.extBPFProgFileName, r.extBPFProgName, r.extBPFQMapName, r.extBPFSocketMapName); err != nil {
			return nil, fmt.Errorf("failed load xdp kernel program %v, %w", r.extBPFProgFileName, err)
		}

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
		xsk, err := newXdpsock(ctx, qid, socketOP, r)
		if err != nil {
			return nil, err
		}
		r.sockList = append(r.sockList, xsk)
	}
	r.wg.Add(2)
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

//getSockAssigment is used by EtherConn to get assigned sock
func (xr *XDPRelay) getSockAssigment() *xdpSock {
	xr.currentXDPSockAssignIndexLock.Lock()
	defer xr.currentXDPSockAssignIndexLock.Unlock()
	if xr.currentXDPSockAssignIndex >= len(xr.sockList) {
		xr.currentXDPSockAssignIndex = 0
	}
	r := xr.sockList[xr.currentXDPSockAssignIndex]
	xr.currentXDPSockAssignIndex++
	return r
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

//NumSocket returns number of XDP socket
func (xr *XDPRelay) NumSocket() int {
	return len(xr.sockList)
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
	var numSend uint64 = 0
	for _, s := range xr.sockList {
		sstat, err := s.sock.Stats()
		if err == nil {
			numSend += sstat.Transmitted
		}
	}
	atomic.StoreUint64(xr.stats.Tx, numSend)
	return xr.stats
}

type LogFunc func(fmt string, a ...interface{})

//handleRcvPkt is the function handle the received pkt from underlying socket, it is shared code for both RawPacketRelay and XDPPacketRelay
func handleRcvPkt(pktData []byte, stats *RelayPacketStats,
	logf LogFunc, recvList *chanMap, mirrorToDefault bool,
	defaultRecvChan chan *RelayReceival, multicastList *chanMap,
	ancData []interface{},
) {
	atomic.AddUint64(stats.RxOffered, 1)
	if checkPacketBytes(pktData) != nil {
		atomic.AddUint64(stats.RxInvalid, 1)
		return
	}
	gpacket := gopacket.NewPacket(pktData, layers.LayerTypeEthernet, gopacket.DecodeOptions{Lazy: true, NoCopy: true})
	var l2ep *L2Endpoint
	var rmac net.HardwareAddr
	if ancData == nil {
		//XDP
		l2ep, rmac = getEtherAdrrInfoFromPacket(gpacket, false)
	} else {
		//AF_PKT socket
		l2ep, rmac = getEtherAdrrInfoFromPacketWithAUXData(gpacket, false, ancData)
	}
	receival := newRelayReceival()
	logf("got pkt with l2epkey %v", l2ep.GetKey().String())
	if rcvchan := recvList.Get(l2ep.GetKey()); rcvchan != nil {
		// found match etherconn
		receival.EtherBytes = pktData
		//NOTE: create go routine here since sendToChanWithCounter will parse the pkt, need some CPU
		//NOTE2: update @ 10/15/2021, remove creating go routine, since it will create out-of-order issue
		sendToChanWithCounter(receival, rmac, rcvchan, gpacket, stats.Rx, stats.RxBufferFull)
		if mirrorToDefault && defaultRecvChan != nil {
			sendToChanWithCounter(receival, rmac, defaultRecvChan, gpacket, stats.Rx, stats.RxBufferFull)
		}
	} else {
		//TODO: could use an optimization here, where parsing only done once iso calling sendToChanWithCounter multiple times
		if l2ep.HwAddr[0]&0x1 == 1 { //multicast traffic
			mList := multicastList.GetList()
			zeroMList := false
			if len(mList) > 0 {
				for _, mrcvchan := range mList {
					newbuf := make([]byte, len(pktData))
					copy(newbuf, pktData)
					receival.EtherBytes = newbuf
					//TODO: might need also a new gpacket here
					sendToChanWithCounter(receival, rmac, mrcvchan, gpacket, stats.RxNonHitMulticast, stats.RxBufferFull)
				}
			} else {
				zeroMList = true
			}
			if defaultRecvChan != nil {
				receival.EtherBytes = pktData
				sendToChanWithCounter(receival, rmac, defaultRecvChan, gpacket, stats.Rx, stats.RxBufferFull)

			} else {
				if zeroMList {
					logf("ignored a multicast pkt")
					atomic.AddUint64(stats.RxMulticastIgnored, 1)
				}
			}
		} else { //unicast but can't find reciver
			if defaultRecvChan != nil {
				receival.EtherBytes = pktData
				sendToChanWithCounter(receival, rmac, defaultRecvChan, gpacket, stats.Rx, stats.RxBufferFull)
			} else {
				logf(fmt.Sprintf("can't find match l2ep %v", l2ep.GetKey().String()))
				atomic.AddUint64(stats.RxMiss, 1)
			}
		}
	}
}
