package handling

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net"
	"time"

	flowmessage "github.com/netsampler/goflow2/pb"
	"github.com/netsampler/goflow2/transport"
	"go.uber.org/zap"
	"google.golang.org/protobuf/proto"

	"github.com/prometheus/client_golang/prometheus"
)

type key int

const (
	CxtKey key = iota
)

type promDriver struct {
	trafficOpts *prometheus.CounterOpts
	traffic     *prometheus.CounterVec

	resetTicker     *time.Ticker
	resetTickerDone chan bool

	cidr       *net.IPNet
	exclusions []*net.IP

	c      chan string
	logger *zap.SugaredLogger
}

func (d *promDriver) Prepare() error {
	d.trafficOpts = &prometheus.CounterOpts{
		Name: "home_traffic_local",
		Help: "Home traffic from netflow",
	}

	d.traffic = prometheus.NewCounterVec(*d.trafficOpts, []string{
		"src_addr",
		"dst_addr",
	})

	return nil
}

func (d *promDriver) Init(context context.Context) error {
	ctxData := context.Value(CxtKey)
	ctxDataValue, ok := ctxData.(map[string]interface{})
	if !ok {
		return fmt.Errorf("context data not found in context")
	}

	logger, loggerOk := ctxDataValue["logger"].(*zap.SugaredLogger)
	if !loggerOk {
		return fmt.Errorf("logger not found in context")
	}

	nflowConf, nflowConfOk := ctxDataValue["nflowConf"].(*NflowConfiguration)
	if !nflowConfOk {
		return fmt.Errorf("nflowConf not found in context")
	}

	d.logger = logger
	d.cidr = nflowConf.Cidr
	d.exclusions = nflowConf.Exclusions

	prometheus.MustRegister(d.traffic)

	d.resetTicker = time.NewTicker(time.Hour)
	d.resetTickerDone = make(chan bool)
	go d.resetTraffic()
	return nil
}

func (d *promDriver) resetTraffic() {
	for {
		select {
		case <-d.resetTickerDone:
			return
		case t := <-d.resetTicker.C:
			if t.Hour() == 0 {
				d.logger.Infof("Resetting traffic at %v:%v:%v", t.Hour(), t.Minute(), t.Second())
				d.traffic.Reset()
			} else {

				d.logger.Debugf("Skip resetting traffic at %v:%v:%v", t.Hour(), t.Minute(), t.Second())
			}
		}
	}
}

func (d *promDriver) Send(key, data []byte) error {
	message := &flowmessage.FlowMessage{}

	err := proto.Unmarshal(data, message)
	if err != nil {
		return fmt.Errorf("error unmarshalling message: %v", err)
	}

	hash := sha256.Sum256(data)
	d.logger.Infof("Parsing message: %x", hash[:])

	srcAddrIpv4 := net.IPv4(message.SrcAddr[0], message.SrcAddr[1], message.SrcAddr[2], message.SrcAddr[3])
	dstAddrIpv4 := net.IPv4(message.DstAddr[0], message.DstAddr[1], message.DstAddr[2], message.DstAddr[3])

	isSrcToConsider := d.cidr.Contains(srcAddrIpv4)
	isDstToConsider := d.cidr.Contains(dstAddrIpv4)

	for _, anExclusion := range d.exclusions {
		if anExclusion.Equal(srcAddrIpv4) {
			isSrcToConsider = false
		}
		if anExclusion.Equal(dstAddrIpv4) {
			isDstToConsider = false
		}
	}

	if isSrcToConsider || isDstToConsider {
		srcAddr := srcAddrIpv4.String()
		dstAddr := dstAddrIpv4.String()

		d.traffic.WithLabelValues(
			srcAddr,
			dstAddr,
		).Inc()

		d.c <- srcAddr
		d.c <- dstAddr
	} else {

		d.logger.Debugf("Ignoring message from %s to %s", srcAddrIpv4, dstAddrIpv4)
	}

	return nil
}

func (d *promDriver) Close(context.Context) error {
	d.logger.Info("Closing prom driver")
	d.resetTicker.Stop()
	d.resetTickerDone <- true
	d.logger.Debug("Reset ticker stopped")
	return nil
}

var d promDriver = promDriver{
	c: make(chan string),
}

func init() {
	transport.RegisterTransportDriver("prometheus", &d)
}

func promDriverChannel() chan string {
	return d.c
}
