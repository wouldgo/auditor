package sni

import (
	"auditor/model"
	"fmt"
	"strconv"
	"sync"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/yarochewsky/tlsx"

	logFacility "auditor/logger"
)

type PcapConfiguration struct {
	Interface *string
	Filter    *string
}

type Handler struct {
	logger      *logFacility.Logger
	pcapHandler *pcap.Handle

	C chan *model.Action
}

func New(logger *logFacility.Logger, pcapConfs *PcapConfiguration) (*Handler, error) {
	toReturn := &Handler{
		logger: logger,
		C:      make(chan *model.Action),
	}

	handler, err := pcap.OpenLive(*pcapConfs.Interface, 65536, true, pcap.BlockForever)
	if err != nil {

		return nil, err
	}

	if err := handler.SetBPFFilter(*pcapConfs.Filter); err != nil {

		return nil, err
	}

	toReturn.pcapHandler = handler

	return toReturn, nil
}

func (h *Handler) Close() {
	h.logger.Log.Info("Closing sni")
	h.pcapHandler.Close()
	h.logger.Log.Debug("Sni closed")
}

func (h *Handler) Handle() {
	source := gopacket.NewPacketSource(h.pcapHandler, h.pcapHandler.LinkType())

	var wg sync.WaitGroup

	for packet := range source.Packets() {
		wg.Add(1)
		go h.managePacket(packet, &wg)
	}
	wg.Wait()
}

func (h *Handler) managePacket(packet gopacket.Packet, wg *sync.WaitGroup) {
	defer wg.Done()

	if tcpLayer := packet.Layer(layers.LayerTypeTCP); tcpLayer != nil {
		// cast TCP layer
		tcp, ok := tcpLayer.(*layers.TCP)
		if !ok {
			h.logger.Log.Error("Could not decode TCP layer")
		}

		if tcp.SYN { // Connection setup
		} else if tcp.FIN { // Connection teardown
		} else if tcp.ACK && len(tcp.LayerPayload()) == 0 { // Acknowledgement packet
		} else if tcp.RST { // Unexpected packet
		} else {
			// data packet
			// process TLS client hello
			h.logger.Log.Debug("Got data")
			clientHello := tlsx.GetClientHello(packet)
			if clientHello != nil {
				srcPortUi64, err := strconv.ParseUint(packet.TransportLayer().TransportFlow().Src().String(), 10, 64)
				if err != nil {
					h.logger.Log.Errorf("src port not a number")
					return
				}

				dstPortUi64, err := strconv.ParseUint(packet.TransportLayer().TransportFlow().Dst().String(), 10, 64)
				if err != nil {
					h.logger.Log.Errorf("dst port not a number")
					return
				}

				srcAddr := packet.NetworkLayer().NetworkFlow().Src().String()
				dstAddr := packet.NetworkLayer().NetworkFlow().Dst().String()
				srcPort := uint16(srcPortUi64)
				dstPort := uint16(dstPortUi64)
				hostName := clientHello.SNI

				source := fmt.Sprintf("%s:%d", srcAddr, srcPort)
				destination := fmt.Sprintf("%s:%d", dstAddr, dstPort)

				h.logger.Log.Infof("[ %s -> %s ] | %s", source, destination, hostName)

				h.C <- &model.Action{
					SrcAddr:  &srcAddr,
					DstAddr:  &dstAddr,
					SrcPort:  &srcPort,
					DstPort:  &dstPort,
					Hostname: &hostName,
				}
			} else {

				h.logger.Log.Debug("Not clientHello packet")
			}
		}
	}
}
