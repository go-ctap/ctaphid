//go:build linux && !hid_cgo

package device

import (
	"context"
	"io"

	ghid "github.com/go-ctap/hid"
)

func Enumerate(ctx context.Context, vid, pid uint16, enumFn hid.EnumFunc) error {
	if v := ctx.Value(CtxKeyUseNamedPipe); v != nil {
		useNamedPipe, ok := v.(bool)
		if ok && useNamedPipe {
			return ErrNotSupported
		}
	}

	for devInfo, err := range ghid.Enumerate() {
		if err != nil {
			return err
		}

		if vid != 0 && devInfo.VendorID != vid {
			continue
		}
		if pid != 0 && devInfo.ProductID != pid {
			continue
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

	return nil
}

func OpenPath(ctx context.Context, path string) (dev io.ReadWriteCloser, err error) {
	if v := ctx.Value(CtxKeyUseNamedPipe); v != nil {
		useNamedPipe, ok := v.(bool)
		if ok && useNamedPipe {
			return nil, ErrNotSupported
		}
	}

	return ghid.OpenPath(path)
}

func hidExit() error { return nil }
