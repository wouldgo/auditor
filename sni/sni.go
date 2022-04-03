package sni

import (
	"fmt"
	"time"

	"github.com/bradleyfalzon/tlsx"
	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/prometheus/client_golang/prometheus"
	"go.uber.org/zap"
)

type PcapConfiguration struct {
	Interface *string
}

type Handler struct {
	logger      *zap.SugaredLogger
	pcapHandler *pcap.Handle
	snisOpts    *prometheus.CounterOpts
	snis        *prometheus.CounterVec

	C chan string

	resetTicker     *time.Ticker
	resetTickerDone chan bool
}

func New(logger *zap.SugaredLogger, pcapConfs *PcapConfiguration) (*Handler, error) {
	toReturn := &Handler{
		logger: logger,
		C:      make(chan string),
	}

	handler, err := pcap.OpenLive(*pcapConfs.Interface, 65536, true, pcap.BlockForever)
	if err != nil {

		return nil, err
	}

	if err := handler.SetBPFFilter("(dst port 443)"); err != nil {

		return nil, err
	}

	toReturn.pcapHandler = handler

	toReturn.snisOpts = &prometheus.CounterOpts{
		Name: "home_snis_local",
		Help: "Home sni's value",
	}

	toReturn.snis = prometheus.NewCounterVec(*toReturn.snisOpts, []string{
		"src_addr",
		"dst_addr",

		"host_name",

		"src_port",
		"dst_port",
	})

	prometheus.MustRegister(toReturn.snis)
	toReturn.resetTicker = time.NewTicker(time.Hour)
	toReturn.resetTickerDone = make(chan bool)
	go toReturn.resetTraffic()

	return toReturn, nil
}

func (h *Handler) resetTraffic() {
	for {
		select {
		case <-h.resetTickerDone:
			return
		case t := <-h.resetTicker.C:
			if t.Hour() == 0 {
				h.logger.Infof("Resetting snis at %v:%v:%v", t.Hour(), t.Minute(), t.Second())
				h.snis.Reset()
			} else {

				h.logger.Debugf("Skip resetting snis at %v:%v:%v", t.Hour(), t.Minute(), t.Second())
			}
		}
	}
}

func (h *Handler) Close() {
	h.logger.Info("Closing sni")
	h.pcapHandler.Close()
	h.resetTicker.Stop()
	h.resetTickerDone <- true
	h.logger.Debug("Reset ticker stopped")
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
	srcPort := "N/A"
	dstPort := "N/A"
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
			srcPort = sniData.srcPort.String()
			dstPort = sniData.dstPort.String()
		}
	}

	if hostName != "N/A" {
		h.logger.Debugf("Got data from %s:%s to %s:%s resolving %s", srcAddr, srcPort, dstAddr, dstPort, hostName)

		h.snis.WithLabelValues(
			srcAddr,
			dstAddr,

			hostName,

			srcPort,
			dstPort,
		).Inc()

		h.C <- srcAddr
		h.C <- dstAddr
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
