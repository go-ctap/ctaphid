package device

import "C"
import (
	"context"
	"io"

	"github.com/Microsoft/go-winio"
	"github.com/fxamacker/cbor/v2"
	"github.com/sstallion/go-hid"

	"github.com/savely-krasovsky/go-ctaphid/pkg/hidproxy"
)

func Enumerate(ctx context.Context, vid, pid uint16, enumFn hid.EnumFunc) error {
	v := ctx.Value(CtxKeyUseNamedPipe)
	if v != nil {
		useNamedPipe, ok := v.(bool)
		if ok && useNamedPipe {
			dev, err := winio.DialPipeContext(ctx, hidproxy.NamedPipePath)
			if err != nil {
				return err
			}

			msg, err := hidproxy.NewMessage(hidproxy.CommandEnumerate, nil)
			if err != nil {
				return err
			}

			if _, err := msg.WriteTo(dev); err != nil {
				return err
			}

			msg, err = hidproxy.ParseMessage(dev)
			if err != nil {
				return err
			}

			devInfos := make([]*hid.DeviceInfo, 0)
			if err := cbor.Unmarshal(msg.Data, &devInfos); err != nil {
				return err
			}

			for _, info := range devInfos {
				if err := enumFn(info); err != nil {
					return err
				}
			}
		}
	}

	return hid.Enumerate(C.uint16_t(vid), C.uint16_t(pid), enumFn)
}

func OpenPath(ctx context.Context, path string) (dev io.ReadWriteCloser, err error) {
	v := ctx.Value(CtxKeyUseNamedPipe)
	if v != nil {
		useNamedPipe, ok := v.(bool)
		if ok && useNamedPipe {
			dev, err := winio.DialPipeContext(ctx, path)
			if err != nil {
				return nil, err
			}

			pMsg, err := hidproxy.NewMessage(hidproxy.CommandStart, path)
			if err != nil {
				return nil, err
			}

			if _, err := pMsg.WriteTo(dev); err != nil {
				return nil, err
			}
		}
	}

	return hid.OpenPath(path)
}
