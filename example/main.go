package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	mv "github.com/RobinUS2/golang-moving-average"
)

type Driver int

const (
	DriverUDPSocket Driver = iota
	DriverEtherConn
	DriverEtherConnXDP
)

func (d *Driver) LoadFromStr(s string) error {
	switch s {
	case "etherxdp":
		*d = DriverEtherConnXDP
	case "raw":
		*d = DriverEtherConn
	default:
		return fmt.Errorf("unknown driver %v", s)
	}
	return nil
}

type TrafficInterface interface {
	GetCounters() (numSend, numRcv uint64)
	Recv(ctx context.Context, bcfg *BatchTrafficConfig,
		ownMAC net.HardwareAddr,
		wg *sync.WaitGroup)
	Send(ctx context.Context,
		bcfg *BatchTrafficConfig, srcMAC, dstMAC net.HardwareAddr,
		wg *sync.WaitGroup)
	Stop()
}

const (
	ModeSender = "sender"
	ModeRecv   = "recv"
)

func newBatchCFG(
	count uint,
	astep uint,
	src, dst string,
	srcprefixlen, dstprefixlen int,
	srcport, dstport uint,
	minlen, maxlen uint,
	interval time.Duration,
	hostaddronly bool,

) (*BatchTrafficConfig, error) {
	cfg := &BatchTrafficConfig{
		Count:        count,
		AddressStep:  astep,
		StartSrcIP:   net.ParseIP(src),
		StartDstIP:   net.ParseIP(dst),
		SrcMask:      net.CIDRMask(srcprefixlen, 32),
		DstMask:      net.CIDRMask(dstprefixlen, 32),
		L4SrcPort:    uint16(srcport),
		L4DstPort:    uint16(dstport),
		MinLen:       minlen,
		MaxLen:       maxlen,
		Interval:     interval,
		HostAddrOnly: hostaddronly,
	}
	if cfg.StartDstIP == nil || cfg.StartSrcIP == nil {
		return nil, fmt.Errorf("invalid src or dst IP, %v, %v ", src, dst)
	}
	if err := cfg.Check(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func main() {
	log.SetFlags(log.Ltime | log.Lshortfile)
	sendifname := flag.String("si", "", "sending interface name")
	recvifname := flag.String("ri", "", "recving interface name")
	count := flag.Uint("c", 10, "number of pkt in the batch")
	debug := flag.Bool("d", false, "enanle debug")
	addrstep := flag.Uint("step", 1, "address step")
	srcip := flag.String("srcip", "20.1.1.1", "starting src ip")
	dstip := flag.String("dstip", "20.1.2.1", "starting dst ip")
	srclen := flag.Int("srcprefixlen", 16, "source address prefix length")
	dstlen := flag.Int("dstprefixlen", 16, "dest address prefix length")
	skipBoradcast := flag.Bool("hostaddronly", true, "when generating address, skip .255 and .0 address")
	srcport := flag.Uint("sport", 2000, "L4 source port")
	dstport := flag.Uint("dport", 3000, "L4 dst port")
	minPlen := flag.Uint("minlen", 128, "min payload len")
	maxPlen := flag.Uint("maxlen", 128, "max payload len")
	interval := flag.Duration("i", time.Second, "pkt send interval")
	srcMACStr := flag.String("srcmac", "aa:bb:cc:11:11:11", "src mac")
	dstMACStr := flag.String("dstmac", "aa:bb:cc:22:22:22", "dst mac")
	doubleQ := flag.Bool("doubleQ", false, "doulbe number of xdp Q, needed for virtio inteface")
	mode := flag.String("m", ModeRecv, fmt.Sprintf("%v|%v", ModeSender, ModeRecv))
	xdpFrameSize := flag.Uint("xdpframesize", defaultMaxXDPFrameSize, "XDP UMEM chunk size, 2048 or 4096")
	xdpnumframe := flag.Uint("xdpnumchunk", defaultNumXDPUMEMChunk, "number of XDP UMEM chunk")
	useDriver := flag.String("eng", "raw", "fwd engine: raw|etherxdp")
	profiling := flag.Bool("profile", false, "enable profiling")
	numEngine := flag.Uint("numeng", 1, "number of raw engine")
	relayRcvChanDepth := flag.Uint("relayrcvchandepth", 65536, "rcv channel depth")
	econRcvChanDepth := flag.Uint("econnrcvchandepth", 65536, "rcv channel depth")
	txBatchMode := flag.Bool("batch", false, "using batch mode for TX, high pps only")

	flag.Parse()
	if *profiling {
		go func() {
			log.Println(http.ListenAndServe("localhost:6060", nil))
		}()
	}
	if *numEngine == 0 {
		log.Fatal("numeng can't be zero")
	}
	driver := new(Driver)
	if err := driver.LoadFromStr(*useDriver); err != nil {
		log.Fatal(err)
	}
	if *xdpFrameSize != 2048 && *xdpFrameSize != 4096 {
		log.Fatalf("XDP chunk size could only be either 2048 or 4096, but %d is specified", *xdpFrameSize)
	}
	srcmac, err := net.ParseMAC(*srcMACStr)
	if err != nil {
		log.Fatalf("%v is not a valid mac, %v", *srcMACStr, err)
	}
	dstmac, err := net.ParseMAC(*dstMACStr)
	if err != nil {
		log.Fatalf("%v is not a valid mac, %v", *dstMACStr, err)
	}

	switch *mode {
	case ModeRecv, ModeSender:
	default:
		log.Fatalf("unknown mode %v", *mode)
	}
	var sendIF, rcvIF TrafficInterface
	// var sendWG, rcvWG *sync.WaitGroup
	sendWG := new(sync.WaitGroup)
	rcvWG := new(sync.WaitGroup)
	bcfg, err := newBatchCFG(*count, *addrstep, *srcip, *dstip, *srclen, *dstlen,
		*srcport, *dstport, *minPlen, *maxPlen, *interval, *skipBoradcast)
	if err != nil {
		log.Fatalf("invalid parameter, %v", err)
	}
	ctx, cancelf := context.WithCancel(context.Background())
	sendCTX, cancelSend := context.WithCancel(context.Background())
	rcvCTX, cancelRCV := context.WithCancel(context.Background())
	switch *mode {
	case ModeRecv:
		log.Printf("creating receiver")
		if *recvifname == "" {
			log.Fatal("recv interface name must be specified")
		}
		rcvIF, err = NewECInterface(rcvCTX, *recvifname, *xdpFrameSize, *xdpnumframe, *numEngine, *relayRcvChanDepth, *econRcvChanDepth, *doubleQ, *driver, *debug, *txBatchMode)
		if err != nil {
			log.Fatalf("failed to create recv interface %v,%v", *recvifname, err)
		}
		rcvIF.Recv(rcvCTX, bcfg, dstmac, rcvWG)
	case ModeSender:
		log.Printf("creating sender")
		if *sendifname == "" {
			log.Fatal("send interface name must be specified")
		}
		sendIF, err = NewECInterface(sendCTX, *sendifname, *xdpFrameSize, *xdpnumframe, *numEngine, *relayRcvChanDepth, *econRcvChanDepth, *doubleQ, *driver, *debug, *txBatchMode)
		if err != nil {
			log.Fatalf("failed to create send interface %v,%v", *sendifname, err)
		}
		sendIF.Send(sendCTX, bcfg, srcmac, dstmac, sendWG)
	}
	printwg := new(sync.WaitGroup)
	defer printwg.Wait()
	printStatsFunc := func(ctx context.Context, wg *sync.WaitGroup, sif, rif TrafficInterface) {
		defer wg.Done()
		var lastrcv, lastsend, cursend, currcv uint64
		interval := time.Second
		rma := mv.New(5)
		sma := mv.New(5)
		for {
			time.Sleep(interval)
			switch *mode {
			case ModeSender:
				cursend, _ = sif.GetCounters()
				sma.Add(float64(cursend-lastsend) / (float64(interval) / float64(time.Second)))
				lastsend = cursend
			}
			switch *mode {
			case ModeRecv:
				_, currcv = rif.GetCounters()
				rma.Add(float64(currcv-lastrcv) / (float64(interval) / float64(time.Second)))
				lastrcv = currcv
			}
			switch *mode {
			case ModeSender:
				log.Printf("=== send %d send pps %.2f", cursend, sma.Avg())
			case ModeRecv:
				log.Printf("=== rcvd %d rcvd pps %.2f", currcv, rma.Avg())
			}
			select {
			case <-ctx.Done():
				return
			default:
			}
		}

	}
	go printStatsFunc(ctx, printwg, sendIF, rcvIF)
	//handle control c
	c := make(chan os.Signal, 16)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c
	//graceful stop
	//stop sending
	switch *mode {
	case ModeSender:
		log.Printf("send stopping")
		cancelSend()
		sendWG.Wait()
		sendIF.Stop()
		log.Print("sending stopped")
	case ModeRecv:
		log.Printf("recv stopping ")
		cancelRCV()
		rcvWG.Wait()
		rcvIF.Stop()
		log.Print("recv stopped")
	}
	cancelf()
}
