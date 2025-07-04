//go:build !windows

package device

import (
	"context"
	"io"

	"github.com/sstallion/go-hid"
)

func Enumerate(ctx context.Context, vid, pid uint16, enumFn hid.EnumFunc) error {
	v := ctx.Value(CtxKeyUseNamedPipe)
	if v != nil {
		useNamedPipe, ok := v.(bool)
		if ok && useNamedPipe {
			return ErrNotSupported
		}
	}

	return hid.Enumerate(vid, pid, enumFn)
}

func OpenPath(ctx context.Context, path string) (dev io.ReadWriteCloser, err error) {
	v := ctx.Value(CtxKeyUseNamedPipe)
	if v != nil {
		useNamedPipe, ok := v.(bool)
		if ok && useNamedPipe {
			return nil, ErrNotSupported
		}
	}

	return hid.OpenPath(path)
}
