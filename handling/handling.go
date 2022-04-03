package handling

import (
	"context"
	"net"

	"github.com/netsampler/goflow2/format"
	_ "github.com/netsampler/goflow2/format/protobuf"
	"github.com/netsampler/goflow2/transport"
	"github.com/netsampler/goflow2/utils"
	"go.uber.org/zap"
)

type NflowConfiguration struct {
	Workers    *int
	Hostname   *string
	Port       *uint64
	Cidr       *net.IPNet
	Exclusions []*net.IP
}

type Handler struct {
	logger      *zap.SugaredLogger
	Ips         chan string
	hostname    string
	port        int
	workers     int
	formatter   *format.Format
	transporter *transport.Transport
}

func New(ctx context.Context, logger *zap.SugaredLogger, nflowConf *NflowConfiguration) (*Handler, error) {
	logger.Infof("Searching for format driver prometheus")
	formatter, err := format.FindFormat(ctx, "format")
	if err != nil {
		return nil, err
	}
	logger.Debugf("Found format driver prometheus")

	logger.Infof("Searching for transport driver format")
	transporter, err := transport.FindTransport(ctx, "prometheus")
	if err != nil {
		return nil, err
	}
	logger.Debugf("Found transport driver format")

	port := int(*nflowConf.Port)

	return &Handler{
		logger:      logger,
		Ips:         promDriverChannel(),
		hostname:    *nflowConf.Hostname,
		port:        port,
		workers:     *nflowConf.Workers,
		formatter:   formatter,
		transporter: transporter,
	}, nil
}

func (h *Handler) Handle() error {
	sNF := &utils.StateNetFlow{
		Format:    h.formatter,
		Transport: h.transporter,
	}

	h.logger.Infof("Starting handling with %d workers on hostname %s on port %d", h.workers, h.hostname, h.port)
	err := sNF.FlowRoutine(h.workers, h.hostname, h.port, false)
	if err != nil {

		panic(err)
	}

	return nil
}

func (h *Handler) Close(ctx context.Context) {
	h.transporter.Close(ctx)
	h.logger.Debug("Handler closed")
}
