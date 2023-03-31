package handling

import (
	logFacility "auditor/logger"
	"auditor/model"
	"context"
	"net"

	"github.com/netsampler/goflow2/format"
	_ "github.com/netsampler/goflow2/format/protobuf"
	"github.com/netsampler/goflow2/transport"
	"github.com/netsampler/goflow2/utils"
	"go.uber.org/zap"
)

type NflowConfiguration struct {
	Transport *string
	Format    *string

	Workers    *int
	Hostname   *string
	Port       *uint64
	Cidr       *net.IPNet
	Exclusions []*net.IP
}

type Handler struct {
	logger      *zap.SugaredLogger
	Actions     chan *model.Action
	hostname    string
	port        int
	workers     int
	formatter   *format.Format
	transporter *transport.Transport
}

func New(ctx context.Context, logger *logFacility.Logger, nflowConf *NflowConfiguration) (*Handler, error) {
	logger.Log.Info("Initializing handler")
	formatter, err := format.FindFormat(ctx, *nflowConf.Format)
	if err != nil {
		return nil, err
	}
	logger.Log.Debug("Found format")
	transporter, err := transport.FindTransport(ctx, *nflowConf.Transport)
	if err != nil {
		return nil, err
	}
	logger.Log.Debugf("Found transport")

	port := int(*nflowConf.Port)

	return &Handler{
		logger:      logger.Log,
		Actions:     promDriverChannel(),
		hostname:    *nflowConf.Hostname,
		port:        port,
		workers:     *nflowConf.Workers,
		formatter:   formatter,
		transporter: transporter,
	}, nil
}

func (h *Handler) Handle() {
	sNF := &utils.StateNetFlow{
		Format:    h.formatter,
		Transport: h.transporter,
	}

	h.logger.Infof("Starting handling with %d workers on hostname %s on port %d", h.workers, h.hostname, h.port)
	err := sNF.FlowRoutine(h.workers, h.hostname, h.port, false)
	if err != nil {

		panic(err)
	}
}

func (h *Handler) Close(ctx context.Context) {
	h.transporter.Close(ctx)
	h.logger.Debug("Handler closed")
}
