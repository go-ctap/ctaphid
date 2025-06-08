package sugar

import (
	"context"
	"errors"
	"sync"

	"github.com/samber/lo"

	"github.com/savely-krasovsky/go-ctaphid/pkg/ctaptypes"
	"github.com/savely-krasovsky/go-ctaphid/pkg/device"
	"github.com/savely-krasovsky/go-ctaphid/pkg/options"

	"github.com/samber/mo"
	"github.com/sstallion/go-hid"
)

func EnumerateFIDODevices(opts ...options.Option) ([]*hid.DeviceInfo, error) {
	oo := options.NewOptions(opts...)

	devInfos := make([]*hid.DeviceInfo, 0)
	ctx := context.WithValue(oo.Context, device.CtxKeyUseNamedPipe, oo.UseNamedPipe)
	if err := device.Enumerate(ctx, hid.VendorIDAny, hid.ProductIDAny, func(info *hid.DeviceInfo) error {
		if info.UsagePage != 0xf1d0 || info.Usage != 0x01 {
			return nil
		}

		devInfos = append(devInfos, info)
		return nil
	}); err != nil {
		return nil, err
	}

	return devInfos, nil
}

// SelectDevice allows selecting a device by confirming presence;
// useful while a user has many tokens connected. Works only with FIDO 2.1 tokens (including PRE).
func SelectDevice(opts ...options.Option) (*device.Device, error) {
	oo := options.NewOptions(opts...)

	if oo.Paths == nil {
		devInfos, err := EnumerateFIDODevices(opts...)
		if err != nil {
			return nil, err
		}
		oo.Paths = lo.Map[*hid.DeviceInfo, string](devInfos, func(devInfo *hid.DeviceInfo, _ int) string {
			return devInfo.Path
		})
	}

	if len(oo.Paths) == 1 {
		return device.New(oo.Paths[0], opts...)
	}

	devices := make([]*device.Device, 0)

	// Here we will receive either a device or an error from first success Selection() call.
	selection := make(chan mo.Either[*device.Device, error])

	// WaitGroup allows us to wait for all Selection() calls to finish.
	var wg sync.WaitGroup

	// It will allow us to cancel all other active Selection() calls
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for _, p := range oo.Paths {
		dev, err := device.New(p, opts...)
		if err != nil {
			return nil, err
		}

		info := dev.GetInfo()
		if !info.Versions.Supports(ctaptypes.FIDO_2_1) &&
			!info.Versions.Supports(ctaptypes.FIDO_2_1_PRE) {
			// We need to close this device because it's not supported.
			_ = dev.Close()
			continue
		}

		wg.Add(1)
		go func(dev *device.Device, ctx context.Context) {
			defer wg.Done()

			err := dev.Selection(ctx)

			if !errors.Is(ctx.Err(), context.Canceled) {
				if err != nil {
					selection <- mo.Right[*device.Device, error](err)
				}
				selection <- mo.Left[*device.Device, error](dev)
			}
		}(dev, ctx)

		devices = append(devices, dev)
	}

	if len(devices) == 0 {
		return nil, errors.New("no supported devices found")
	}

	selectedDev, ok := (<-selection).Left()
	if ok {
		cancel()
		wg.Wait()
	}

	for _, dev := range devices {
		if ok && selectedDev.Path == dev.Path {
			continue
		}

		if err := dev.Close(); err != nil {
			return nil, err
		}
	}

	return selectedDev, nil
}
