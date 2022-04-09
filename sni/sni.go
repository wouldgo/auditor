package sni

import (
	"auditor/meta"
	"fmt"

	"github.com/bradleyfalzon/tlsx"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"go.uber.org/zap"
)

type PcapConfiguration struct {
	Interface *string
}

type Handler struct {
	logger      *zap.SugaredLogger
	pcapHandler *pcap.Handle

	C chan *meta.MetaInput
}

func New(logger *zap.SugaredLogger, pcapConfs *PcapConfiguration) (*Handler, error) {
	toReturn := &Handler{
		logger: logger,
		C:      make(chan *meta.MetaInput),
	}

	handler, err := pcap.OpenLive(*pcapConfs.Interface, 65536, true, pcap.BlockForever)
	if err != nil {

		return nil, err
	}

	if err := handler.SetBPFFilter("(dst port 443)"); err != nil {

		return nil, err
	}

	toReturn.pcapHandler = handler

	return toReturn, nil
}

func (h *Handler) Close() {
	h.logger.Info("Closing sni")
	h.pcapHandler.Close()
	h.logger.Debug("Sni closed")
}

func (h *Handler) Handle() {
	source := gopacket.NewPacketSource(h.pcapHandler, h.pcapHandler.LinkType())

	for packet := range source.Packets() {
		h.logger.Debug("Got data")

		err := h.managePacket(packet)
		if err != nil {

			h.logger.Warn(err)
		}
	}
}

func (h *Handler) managePacket(packet gopacket.Packet) error {
	srcAddr := "N/A"
	dstAddr := "N/A"
	var srcPort, dstPort uint16
	hostName := "N/A"

	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ipPacket, ok := ipLayer.(*layers.IPv4)
		if !ok {
			return fmt.Errorf("could not decode IP layer")
		}
		dstIpStr := ipPacket.DstIP.String()
		srcIpStr := ipPacket.SrcIP.String()

		dstAddr = dstIpStr
		srcAddr = srcIpStr
	}

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		tcp, ok := tcpLayer.(*layers.TCP)
		if !ok {
			return fmt.Errorf("could not decode TCP layer")
		}

		if tcp.SYN {
			h.logger.Debug("Connection setup")
		} else if tcp.FIN {
			h.logger.Debug("Connection teardown")
		} else if tcp.ACK && len(tcp.LayerPayload()) == 0 {
			h.logger.Debug("Acknowledgement")
		} else if tcp.RST {
			h.logger.Debug("RST")
		} else {
			// data packet
			sniData, err := h.readData(packet)
			if err != nil {
				return err
			}
			hostName = *sniData.sni

			srcPort = uint16(*sniData.srcPort)
			dstPort = uint16(*sniData.dstPort)
		}
	}

	if hostName != "N/A" {
		h.logger.Debugf("Got data from %s:%s to %s:%s resolving %s", srcAddr, srcPort, dstAddr, dstPort, hostName)

		h.C <- &meta.MetaInput{
			SrcAddr:  srcAddr,
			DstAddr:  dstAddr,
			SrcPort:  srcPort,
			DstPort:  dstPort,
			Hostname: hostName,
		}
	}

	return nil
}

func (h *Handler) readData(packet gopacket.Packet) (*sniTCPData, error) {
	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		t, _ := tcpLayer.(*layers.TCP)

		var hello = tlsx.ClientHello{}

		err := hello.Unmarshall(t.LayerPayload())

		if err != nil {
			return nil, err
		}

		h.logger.Debugf("Client hello from port %s to %s", t.SrcPort, t.DstPort)
		return &sniTCPData{
			sni:     &hello.SNI,
			srcPort: &t.SrcPort,
			dstPort: &t.DstPort,
		}, nil
	} else {
		return nil, fmt.Errorf("client Hello Reader could not decode TCP layer")
	}
}

type sniTCPData struct {
	sni     *string
	srcPort *layers.TCPPort
	dstPort *layers.TCPPort
}
