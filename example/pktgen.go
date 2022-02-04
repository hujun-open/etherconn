package main

import (
	"fmt"
	"math/big"
	"math/rand"
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/hujun-open/etherconn"
	"github.com/hujun-open/myaddr"
)

// BatchTrafficConfig is the configuration for a batch of traffic
type BatchTrafficConfig struct {
	StartSrcIP       net.IP
	StartDstIP       net.IP
	SrcMask, DstMask net.IPMask
	Count            uint
	AddressStep      uint
	L4SrcPort        uint16
	L4DstPort        uint16
	MinLen, MaxLen   uint
	WithMetaData     bool //means the generate packet contains meta data like pkt ID
	Interval         time.Duration
	HostAddrOnly     bool
}

//Check if bc contains any invalid config
func (bc *BatchTrafficConfig) Check() error {
	if (bc.StartDstIP.To4() == nil) != (bc.StartSrcIP.To4() == nil) {
		return fmt.Errorf("src IP %v and dst IP %v are not same IP version", bc.StartSrcIP, bc.StartDstIP)
	}
	if bc.MinLen > bc.MaxLen {
		return fmt.Errorf("minLen %d is bigger than maxLen %d", bc.MinLen, bc.MaxLen)
	}
	return nil

}

type PktConfig struct {
	SrcIP, DstIP     net.IP
	SrcPort, DstPort uint16
	Len              int //L4 payload len
}

func buildEthernetHeaderWithSrcVLAN(srcmac, dstmac net.HardwareAddr, vlans etherconn.VLANs, payloadtype uint16) []byte {
	eth := layers.Ethernet{}
	eth.SrcMAC = make(net.HardwareAddr, len(srcmac))
	copy(eth.SrcMAC, srcmac)
	eth.DstMAC = make(net.HardwareAddr, len(dstmac))
	copy(eth.DstMAC, dstmac)
	switch len(vlans) {
	case 0:
		eth.EthernetType = layers.EthernetType(payloadtype)
	default:
		eth.EthernetType = layers.EthernetType(vlans[0].EtherType)
	}
	layerList := []gopacket.SerializableLayer{&eth}
	for i, v := range vlans {
		vlan := layers.Dot1Q{
			VLANIdentifier: v.ID,
		}
		if i == len(vlans)-1 {
			vlan.Type = layers.EthernetType(payloadtype)
		} else {
			vlan.Type = layers.EthernetType(vlans[i+1].EtherType)
		}
		layerList = append(layerList, &vlan)
	}
	buf := gopacket.NewSerializeBuffer()
	//NOTE:follow padding is needed to avoid Ethernet layer serialization to pad to 60B
	const paddingLen = 60
	layerList = append(layerList, gopacket.Payload(make([]byte, paddingLen)))
	opts := gopacket.SerializeOptions{}
	gopacket.SerializeLayers(buf, opts, layerList...)
	return buf.Bytes()[:len(buf.Bytes())-paddingLen]
}

func GenBatchEtherBytes(cfg *BatchTrafficConfig, srcmac, dstmac net.HardwareAddr) ([][]byte, error) {
	IPpktList, err := GenerateBatch(cfg)
	if err != nil {
		return nil, err
	}
	rlist := [][]byte{}
	for _, ipkt := range IPpktList {
		rlist = append(rlist, append(buildEthernetHeaderWithSrcVLAN(srcmac, dstmac, nil, 0x0800), ipkt...))
	}
	return rlist, nil
}

// GenIPPktBytes generate an IP packet according the the cfg
func GenIPPktBytes(cfg *PktConfig) ([]byte, error) {
	if cfg.DstIP.To4() == nil {
		return nil, fmt.Errorf("only support v4")
	}
	payload := make([]byte, cfg.Len)
	rand.Read(payload)
	buf := gopacket.NewSerializeBuffer()
	l4layer := &layers.UDP{
		SrcPort: layers.UDPPort(cfg.SrcPort),
		DstPort: layers.UDPPort(cfg.DstPort),
	}
	iplayer := &layers.IPv4{
		Version:  4,
		SrcIP:    cfg.SrcIP,
		DstIP:    cfg.DstIP,
		Protocol: layers.IPProtocolUDP,
		TTL:      16,
	}
	l4layer.SetNetworkLayerForChecksum(iplayer)
	opts := gopacket.SerializeOptions{FixLengths: true, ComputeChecksums: true}
	gopacket.SerializeLayers(buf, opts,
		iplayer,
		l4layer,
		gopacket.Payload(payload))
	return buf.Bytes(), nil
}

func generatePktConfigs(cfg *BatchTrafficConfig) ([]*PktConfig, error) {
	rlist := []*PktConfig{}
	var err error
	if err = cfg.Check(); err != nil {
		return nil, err
	}
	var srcaddr, dstaddr net.IP
	i := -1
	for total := 0; uint(total) < cfg.Count; {
		i++
		srcaddr, err = myaddr.IncAddr(cfg.StartSrcIP, big.NewInt(int64(i*int(cfg.AddressStep))))
		if err != nil {
			return nil, err
		}

		dstaddr, err = myaddr.IncAddr(cfg.StartDstIP, big.NewInt(int64(i*int(cfg.AddressStep))))
		if err != nil {
			return nil, err
		}
		if cfg.HostAddrOnly {
			if srcaddr.To4()[3] == 255 || srcaddr.To4()[3] == 0 {
				continue
			}
			if dstaddr.To4()[3] == 255 || dstaddr.To4()[3] == 0 {
				continue
			}
		}
		plen := cfg.MinLen
		if cfg.MinLen < cfg.MaxLen {
			delta := rand.Int31n(int32(cfg.MaxLen) - int32(cfg.MinLen) + 1)
			plen += uint(delta)
		}
		pktcfg := &PktConfig{
			SrcIP:   srcaddr,
			DstIP:   dstaddr,
			SrcPort: cfg.L4SrcPort,
			DstPort: cfg.L4DstPort,
			Len:     int(plen),
		}
		rlist = append(rlist, pktcfg)
		total++
	}
	return rlist, nil
}

//GenerateBatch generates a batch of packets accordign to cfg
func GenerateBatch(cfg *BatchTrafficConfig) (rlist [][]byte, err error) {
	pktcfgList, err := generatePktConfigs(cfg)
	if err != nil {
		return nil, err
	}
	for _, pktcfg := range pktcfgList {
		var pkt []byte
		pkt, err = GenIPPktBytes(pktcfg)
		if err != nil {
			return nil, err
		}
		rlist = append(rlist, pkt)

	}
	return rlist, nil
}
