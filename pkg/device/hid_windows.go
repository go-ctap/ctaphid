package device

import (
	"context"
	"io"

	"github.com/Microsoft/go-winio"
	"github.com/fxamacker/cbor/v2"
	"github.com/sstallion/go-hid"

	"github.com/go-ctap/ctaphid/pkg/hidproxy"
	cgofreehid "github.com/go-ctap/hid"
)

func Enumerate(ctx context.Context, vid, pid uint16, enumFn hid.EnumFunc) error {
	if v := ctx.Value(CtxKeyUseNamedPipe); v != nil {
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

	if v := ctx.Value(CtxKeyUseCgoFreeHID); v != nil {
		useCgoFreeHID, ok := v.(bool)
		if ok && useCgoFreeHID {
			for devInfo, err := range cgofreehid.Enumerate() {
				if err != nil {
					return err
				}

				if err := enumFn(&hid.DeviceInfo{
					Path:       devInfo.Path,
					VendorID:   devInfo.VendorID,
					ProductID:  devInfo.ProductID,
					MfrStr:     devInfo.MfrStr,
					ProductStr: devInfo.ProductStr,
					UsagePage:  devInfo.UsagePage,
					Usage:      devInfo.Usage,
				}); err != nil {
					return err
				}
			}
		}
	}

	return hid.Enumerate(vid, pid, enumFn)
}

func OpenPath(ctx context.Context, path string) (dev io.ReadWriteCloser, err error) {
	if v := ctx.Value(CtxKeyUseNamedPipe); v != nil {
		useNamedPipe, ok := v.(bool)
		if ok && useNamedPipe {
			dev, err := winio.DialPipeContext(ctx, hidproxy.NamedPipePath)
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

			return dev, nil
		}
	}

	if v := ctx.Value(CtxKeyUseCgoFreeHID); v != nil {
		useCgoFreeHID, ok := v.(bool)
		if ok && useCgoFreeHID {
			return cgofreehid.OpenPath(path)
		}
	}

	return hid.OpenPath(path)
}
