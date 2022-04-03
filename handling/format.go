package handling

import (
	"context"
	"fmt"

	"google.golang.org/protobuf/proto"

	"github.com/netsampler/goflow2/format"
	"github.com/netsampler/goflow2/format/common"
)

type formatter struct{}

func (d *formatter) Prepare() error {
	common.HashFlag()
	return nil
}

func (d *formatter) Init(context.Context) error {
	return common.ManualHashInit()
}

func (d *formatter) Format(data interface{}) ([]byte, []byte, error) {
	msg, ok := data.(proto.Message)
	if !ok {
		return nil, nil, fmt.Errorf("message is not protobuf")
	}
	key := common.HashProtoLocal(msg)

	b, err := proto.Marshal(msg)
	return []byte(key), b, err
}

func init() {
	d := &formatter{}
	format.RegisterFormatDriver("format", d)
}
