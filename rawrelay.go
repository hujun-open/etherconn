package etherconn

import (
	"context"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/google/gopacket"
)

type RelayType string

const (
	RelayTypeAFP  RelayType = "afpkt"
	RelayTypePCAP RelayType = "pcap"
	RelayTypeXDP  RelayType = "xdp"
	UnknownRelay  RelayType = "unknown"
)

// MarshalText implements encoding.TextMarshaler interface
func (rt RelayType) MarshalText() (text []byte, err error) {
	return []byte(rt), nil
}

// UnmarshalText implements encoding.TextUnmarshaler interface
func (rt *RelayType) UnmarshalText(text []byte) error {
	switch string(text) {
	case "afpkt", "pcap", "xdp":
		*rt = RelayType(text)
		return nil
	}
	*rt = UnknownRelay
	return nil
}

type rawRelayConn interface {
	WritePacketData([]byte) error
	ReadPacketData() ([]byte, gopacket.CaptureInfo, error)
	setBPFFilter(string) error
	CloseMe()
	getRawStats() any
	isTimeout(error) bool
	relayType() RelayType
}

type LogFunc func(fmt string, a ...interface{})

// RawSocketRelay implements PacketRelay interface, using AF_PACKET socket or libpcap.
// use NewRawSocketRelayPcap or NewRawSocketRelay create new instances.
type RawSocketRelay struct {
	conn                 rawRelayConn
	toSendChan           chan []byte
	stopToSendChan       chan struct{}
	recvList             *ChanMap
	wg                   *sync.WaitGroup
	cancelFunc           context.CancelFunc
	recvTimeout          time.Duration
	multicastList        *ChanMap
	perClntRecvChanDepth uint
	sendChanDepth        uint
	maxEtherFrameSize    uint
	stats                *RelayPacketStats
	logger               *log.Logger
	// etherTypeList        map[uint16]struct{} //TODO: remove this , this is duplicate with bpfFilter
	ifName          string
	bpfFilter       *string
	defaultRecvChan chan *RelayReceival
	mirrorToDefault bool
	engineCount     uint
}

// RelayOption is a function use to provide customized option when creating RawSocketRelay
type RelayOption func(*RawSocketRelay)

// newRawSocketRelay creates a new RawSocketRelay instance,
// bound to the interface ifname,
// optionally along with RelayOption functions.
// This function will put the interface in promisc mode, which means it requires root privilage
func newRawSocketRelayWithRelayConn(parentctx context.Context, ifname string, conn rawRelayConn, options ...RelayOption) (*RawSocketRelay, error) {
	r := &RawSocketRelay{}
	var err error
	r.ifName = ifname
	r.recvTimeout = DefaultRelayRecvTimeout
	r.conn = conn
	r.stopToSendChan = make(chan struct{})
	// r.etherTypeList = map[uint16]struct{}{0x0800: exists, 0x86dd: exists}
	r.perClntRecvChanDepth = DefaultPerClntRecvChanDepth
	r.sendChanDepth = DefaultSendChanDepth
	r.maxEtherFrameSize = DefaultMaxEtherFrameSize
	var ctx context.Context
	ctx, r.cancelFunc = context.WithCancel(parentctx)
	r.toSendChan = make(chan []byte, r.sendChanDepth)

	r.recvList = NewChanMap()
	r.multicastList = NewChanMap()
	r.stats = newRelayPacketStats()
	r.wg = new(sync.WaitGroup)
	r.bpfFilter = nil
	r.defaultRecvChan = nil
	r.engineCount = 1
	for _, op := range options {
		op(r)
	}
	if r.bpfFilter != nil {
		// if *r.bpfFilter != "" {
		err = r.setBPFFilter(*r.bpfFilter)
		// }
	} else {
		err = r.setBPFFilter(buildPCAPFilterStrForEtherType(DefaultEtherTypes))
	}
	if err != nil {
		return nil, err
	}

	for i := 0; i < int(r.engineCount); i++ {
		r.wg.Add(2)
		go r.recv(ctx)
		go r.send(ctx)
	}
	return r, nil
}

// WithMultiEngine specifies the number of internal send/recv routine,
// count must >=1, default value is 1
func WithMultiEngine(count uint) RelayOption {
	return func(relay *RawSocketRelay) {
		if count > 0 {
			relay.engineCount = count
		}
	}
}

// WithDebug enable/disable debug log output
func WithDebug(debug bool) RelayOption {
	return func(relay *RawSocketRelay) {
		if debug {
			relay.logger = log.New(os.Stderr, "", log.Ldate|log.Ltime)
		} else {
			relay.logger = nil
		}
	}
}

// WithPerClntChanRecvDepth specifies the per Client(EtherConn) receive channel depth,
// By default, DefaultPerClntRecvChanDepth is used
func WithPerClntChanRecvDepth(depth uint) RelayOption {
	return func(relay *RawSocketRelay) {
		relay.perClntRecvChanDepth = depth
	}
}

// WithSendChanDepth specifies the send channel depth,
// by default, DefaultSendChanDepth is used
func WithSendChanDepth(depth uint) RelayOption {
	return func(relay *RawSocketRelay) {
		relay.sendChanDepth = depth
	}
}

// WithMaxEtherFrameSize specifies the max Ethernet frame size the RawSocketRelay could receive
func WithMaxEtherFrameSize(size uint) RelayOption {
	return func(relay *RawSocketRelay) {
		relay.maxEtherFrameSize = size
	}
}

// WithBPFFilter set BPF filter, which is a pcap filter string;
// if filter is an empty string, then it means no filter;
// by default, Relay will have a filter only allow traffic with specified EtherType.
func WithBPFFilter(filter string) RelayOption {
	return func(relay *RawSocketRelay) {
		relay.bpfFilter = new(string)
		*relay.bpfFilter = filter
	}
}

// WithRecvTimeout specifies the receive timeout for RawSocketRelay
func WithRecvTimeout(t time.Duration) RelayOption {
	return func(relay *RawSocketRelay) {
		relay.recvTimeout = t
	}
}

// WithDefaultReceival creates a default receiving channel,
// all received pkt doesn't match any explicit EtherConn, will be sent to this channel;
// using RegisterDefault to get the default receiving channel.
// if mirroring is true, then every received pkt will be sent to this channel.
func WithDefaultReceival(mirroring bool) RelayOption {
	return func(relay *RawSocketRelay) {
		relay.defaultRecvChan = make(chan *RelayReceival, relay.perClntRecvChanDepth)
		relay.mirrorToDefault = mirroring
	}
}

// Type returns rsr's type
func (rsr *RawSocketRelay) Type() RelayType {
	return rsr.conn.relayType()
}

func (rsr *RawSocketRelay) log(format string, a ...interface{}) {
	if rsr.logger == nil {
		return
	}
	msg := fmt.Sprintf(format, a...)
	_, fname, linenum, _ := runtime.Caller(1)
	rsr.logger.Printf("%v:%v:%v:%v", filepath.Base(fname), linenum, rsr.ifName, msg)
}

// Register implements PacketRelay interface;
func (rsr *RawSocketRelay) Register(ks []L2EndpointKey, recvMulticast bool) (chan *RelayReceival, chan []byte, chan struct{}) {
	// return nil, nil, nil
	// ch := rsr.recvList.Get(k)
	// if ch != nil {
	// 	return ch, rsr.toSendChan, rsr.stopToSendChan
	// }
	ch := make(chan *RelayReceival, rsr.perClntRecvChanDepth)
	// rsr.logger.Printf("register for %v, with recv depth %d", ks, rsr.perClntRecvChanDepth)
	list := make([]interface{}, len(ks))
	for i := range ks {
		list[i] = ks[i]
	}
	rsr.recvList.SetList(list, ch)
	if recvMulticast {
		//NOTE: only set one key in multicast, otherwise the EtherConn will receive multiple copies
		rsr.multicastList.Set(ks[0], ch)
	}
	return ch, rsr.toSendChan, rsr.stopToSendChan
}

// RegisterDefault implements PacketRelay interface
func (rsr *RawSocketRelay) RegisterDefault() (chan *RelayReceival, chan []byte, chan struct{}) {
	return rsr.defaultRecvChan, rsr.toSendChan, rsr.stopToSendChan
}

// Deregister implements PacketRelay interface;
func (rsr *RawSocketRelay) Deregister(ks []L2EndpointKey) {
	list := make([]interface{}, len(ks))
	for i := range ks {
		list[i] = ks[i]
	}
	rsr.recvList.DelList(list)
	rsr.multicastList.DelList(list)
}

func (rsr *RawSocketRelay) send(ctx context.Context) {
	runtime.LockOSThread()
	defer rsr.wg.Done()
	// defer close(rsr.stopToSendChan)
	for {
		select {
		case <-ctx.Done():
			rsr.log("relay send routine cancelled")
			return
		case data := <-rsr.toSendChan:
			err := rsr.conn.WritePacketData(data)
			if err != nil {
				rsr.log(fmt.Sprintf("relay failed to send frame, %v", err))
				return
			}
			atomic.AddUint64(rsr.stats.Tx, 1)
		}
	}
}

func checkPacketBytes(p []byte) error {
	if len(p) < 14 {
		return fmt.Errorf("ethernet frame size is smaller than 14B")
	}
	return nil
}

// IfName returns the name of the binding interface
func (rsr *RawSocketRelay) IfName() string {
	return rsr.ifName
}
func sendToChanWithCounter(receival *RelayReceival, ch chan *RelayReceival, counter, fullcounter *uint64) {
	fullcounted := false
	if len(receival.EtherPayloadBytes) == 0 {
		return
	}
	for { //keep sending until pkt is sent to channel
		select {
		case ch <- receival:
			atomic.AddUint64(counter, 1)
			return
		default:
			<-ch //channel is full, remove the oldest pkt in channel
			if !fullcounted {
				log.Printf("recv chan has cap of %d and len %d\n", cap(ch), len(ch))
				atomic.AddUint64(fullcounter, 1)
				fullcounted = true
			}
		}
	}
}

// GetStats return pkt forwarding stats as *RelayPacketStats
func (rsr *RawSocketRelay) GetStats() *RelayPacketStats {
	return rsr.stats
}

func (rsr *RawSocketRelay) recv(ctx context.Context) {
	runtime.LockOSThread()
	var logf LogFunc = nil
	if rsr.logger != nil {
		logf = rsr.log
	}
	defer rsr.wg.Done()
	// defer rsr.recvList.CloseAll() //TODO: this might create race issue, given sendToChanWithCounter will also use the ch, does this really need to be closed?
	for {
		// b := make([]byte, rsr.maxEtherFrameSize)
		// ci, err := rsr.conn.ReadPacketDataTo(b)
		b, ci, err := rsr.conn.ReadPacketData()
		if err != nil {
			if rsr.conn.isTimeout(err) {
				select {
				case <-ctx.Done():
					rsr.log("relay recv routine cancelled")
					return
				default:
					continue
				}
			} else {
				rsr.log(fmt.Sprintf("error reading from raw connection: %v", err))
				return
			}
		}
		handleRcvPkt(rsr.conn.relayType(), b[:ci.CaptureLength], rsr.stats, logf, rsr.recvList,
			rsr.mirrorToDefault, rsr.defaultRecvChan, rsr.multicastList, ci.AncillaryData)
	}
}

// Stop implements PacketRelay interface
func (rsr *RawSocketRelay) Stop() {
	rsr.log("relay stopping")
	rsr.cancelFunc()
	// this ticker is to make sure relay stop in case poll timeout is not supported by kernel(need TPacketV3)
	// ticker time can't be too small, otherwise, if the rsr.conn.Close before recv or send routine quit, it might cause panic
	ticker := time.NewTicker(rsr.recvTimeout + 5*time.Second)
	defer ticker.Stop()
	done := make(chan bool)
	go func(d chan bool) {
		rsr.wg.Wait()
		close(rsr.stopToSendChan)
		d <- true

	}(done)
	select {
	case <-done:
	case <-ticker.C:
	}
	rsr.log(fmt.Sprintf("RawSocketRelay stats:\n%v", rsr.stats.String()))
	// _, rawstat, err := rsr.conn.SocketStats()
	// if err != nil {
	// 	rsr.log("failed to get raw stats %v", err)
	// }
	rsr.log("raw stats:%+v", rsr.conn.getRawStats())
	//NOTE: without closing this, the recreating relay on same interface might cause issue
	rsr.conn.CloseMe()
}

// setBPFFilter translates a BPF filter string into BPF RawInstruction and applies them.
func (rsr *RawSocketRelay) setBPFFilter(filter string) (err error) {
	rsr.log("set BPF filter to %v", filter)
	return rsr.conn.setBPFFilter(filter)
}

type AncillaryVLAN struct {
	// The VLAN VID provided by the kernel.
	VLAN int
}

// getReceivalFromRcvPkt parse received ethernet pkt, p is a ethernet packet in byte slice,
func getReceivalFromRcvPkt(p []byte, auxdata []interface{}, relayType RelayType) *RelayReceival {
	// l2ep := newL2Endpoint()
	rcv := newRelayReceival()
	rcv.LocalEndpoint = newL2Endpoint()
	rcv.RemoteEndpoint = newL2Endpoint()
	rcv.EtherBytes = p
	copy(rcv.LocalEndpoint.HwAddr, p[:6])    //dst mac
	copy(rcv.RemoteEndpoint.HwAddr, p[6:12]) //src mac
	index := 12
	var etype, vlan2bytes uint16
	for {
		etype = binary.BigEndian.Uint16(p[index : index+2])
		if etype == 0x8100 || etype == 0x88a8 {
			vlan2bytes = binary.BigEndian.Uint16(p[index+2 : index+4])
			rcv.LocalEndpoint.VLANs = append(rcv.LocalEndpoint.VLANs, vlan2bytes&0x0fff)
		} else {
			rcv.LocalEndpoint.Etype = etype
			break
		}
		index += 4
	}
	rcv.EtherPayloadBytes = p[index+2:]
	switch relayType {
	case RelayTypeAFP:
		rcv.LocalEndpoint.VLANs = getVLANsFromAncDataAFPkt(rcv.LocalEndpoint.VLANs, auxdata)
	}

	// for _, adata := range auxdata {
	// 	if v, ok := adata.(AncillaryVLAN); ok {
	// 		rcv.LocalEndpoint.VLANs = append([]uint16{uint16(v.VLAN)}, rcv.LocalEndpoint.VLANs...)
	// 	}
	// }
	var l4index int

	switch rcv.LocalEndpoint.Etype {
	case 0x0800: //ipv4
		rcv.RemoteIP = rcv.EtherPayloadBytes[12:16]
		rcv.LocalIP = rcv.EtherPayloadBytes[16:20]
		rcv.Protocol = rcv.EtherPayloadBytes[9]
		l4index = 20 //NOTE: this means no supporting of any ipv4 options
	case 0x86dd: //ipv6
		rcv.Protocol = rcv.EtherPayloadBytes[6]
		rcv.RemoteIP = rcv.EtherPayloadBytes[8:24]
		rcv.LocalIP = rcv.EtherPayloadBytes[24:40]
		l4index = 40 //NOTE: this means no supporting of any ipv6 options
	}
	switch rcv.Protocol {
	case 17: //udp
		rcv.RemotePort = binary.BigEndian.Uint16(rcv.EtherPayloadBytes[l4index : l4index+2])
		rcv.LocalPort = binary.BigEndian.Uint16(rcv.EtherPayloadBytes[l4index+2 : l4index+4])
		rcv.TransportPayloadBytes = rcv.EtherPayloadBytes[l4index+8:]
	}
	rcv.RemoteEndpoint.Etype = rcv.LocalEndpoint.Etype
	rcv.RemoteEndpoint.VLANs = rcv.LocalEndpoint.VLANs
	return rcv
}

// handleRcvPkt is the function handle the received pkt from underlying socket, it is shared code for both RawPacketRelay and XDPPacketRelay
func handleRcvPkt(relayType RelayType, pktData []byte, stats *RelayPacketStats,
	logf LogFunc, recvList *ChanMap, mirrorToDefault bool,
	defaultRecvChan chan *RelayReceival, multicastList *ChanMap,
	ancData []interface{},
) {
	atomic.AddUint64(stats.RxOffered, 1)
	if checkPacketBytes(pktData) != nil {
		atomic.AddUint64(stats.RxInvalid, 1)
		return
	}
	// gpacket := gopacket.NewPacket(pktData, layers.LayerTypeEthernet, gopacket.DecodeOptions{Lazy: true, NoCopy: true})

	// var rmac net.HardwareAddr
	recvial := getReceivalFromRcvPkt(pktData, ancData, relayType)
	if logf != nil {
		logf("got pkt with l2epkey %v", recvial.LocalEndpoint.GetKey().String())
	}
	if rcvchan := recvList.Get(recvial.LocalEndpoint.GetKey()); rcvchan != nil {
		// found match etherconn
		//NOTE: create go routine here since sendToChanWithCounter will parse the pkt, need some CPU
		//NOTE2: update @ 10/15/2021, remove creating go routine, since it will create out-of-order issue
		sendToChanWithCounter(recvial, rcvchan, stats.Rx, stats.RxBufferFull)
		if mirrorToDefault && defaultRecvChan != nil {
			sendToChanWithCounter(recvial, defaultRecvChan, stats.RxDefault, stats.RxBufferFull)
		}
	} else {
		//TODO: could use an optimization here, where parsing only done once iso calling sendToChanWithCounter multiple times
		if recvial.LocalEndpoint.HwAddr[0]&0x1 == 1 { //multicast traffic
			mList := multicastList.GetList()
			zeroMList := false
			if len(mList) > 0 {
				for _, mrcvchan := range mList {
					//TODO: really need copy here?
					newbuf := make([]byte, len(pktData))
					copy(newbuf, pktData)
					recvial.EtherBytes = newbuf
					//TODO: might need also a new gpacket here
					sendToChanWithCounter(recvial, mrcvchan, stats.RxNonHitMulticast, stats.RxBufferFull)
				}
			} else {
				zeroMList = true
			}
			if defaultRecvChan != nil {
				sendToChanWithCounter(recvial, defaultRecvChan, stats.RxDefault, stats.RxBufferFull)

			} else {
				if zeroMList {
					if logf != nil {
						logf("ignored a multicast pkt")
					}
					atomic.AddUint64(stats.RxMulticastIgnored, 1)
				}
			}
		} else { //unicast but can't find reciver
			if defaultRecvChan != nil {
				sendToChanWithCounter(recvial, defaultRecvChan, stats.RxDefault, stats.RxBufferFull)
			} else {
				if logf != nil {
					logf(fmt.Sprintf("can't find match l2ep %v", recvial.LocalEndpoint.GetKey().String()))
				}
				atomic.AddUint64(stats.RxMiss, 1)
			}
		}
	}
}
