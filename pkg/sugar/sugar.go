package sugar

import (
	"context"
	"errors"
	"sync"

	"github.com/go-ctap/ctaphid/pkg/ctaptypes"
	"github.com/go-ctap/ctaphid/pkg/device"
	"github.com/go-ctap/ctaphid/pkg/options"
	ghid "github.com/go-ctap/hid"
	"github.com/samber/lo"

	"github.com/samber/mo"
)

func EnumerateFIDODevices(opts ...options.Option) ([]*ghid.DeviceInfo, error) {
	oo := options.NewOptions(opts...)

	devInfos := make([]*ghid.DeviceInfo, 0)
	ctx := context.WithValue(oo.Context, device.CtxKeyUseNamedPipe, oo.UseNamedPipe)
	for devInfo, err := range device.Enumerate(ctx) {
		if err != nil {
			return nil, err
		}

		if devInfo.UsagePage != 0xf1d0 || devInfo.Usage != 0x01 {
			continue
		}

		devInfos = append(devInfos, devInfo)
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
		oo.Paths = lo.Map[*ghid.DeviceInfo, string](devInfos, func(devInfo *ghid.DeviceInfo, _ int) string {
			return devInfo.Path
		})
	}

	if len(oo.Paths) == 1 {
		return device.New(oo.Paths[0], opts...)
	}

	devices := make([]*device.Device, 0)

	// Here we will receive either a device or an error from first success Selection() call.
	selection := make(chan mo.Either[*device.Device, error], len(oo.Paths))

	// WaitGroup allows us to wait for all Selection() calls to finish.
	var wg sync.WaitGroup
	// Return only first successful Selection() call.
	var once sync.Once

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
		go func(dev *device.Device) {
			defer wg.Done()

			// Selection() will block until ctx is canceled or a device is selected.
			err := dev.Selection(ctx)

			if !errors.Is(ctx.Err(), context.Canceled) {
				once.Do(func() {
					cancel()
					if err != nil {
						selection <- mo.Right[*device.Device, error](err)
						return
					}
					selection <- mo.Left[*device.Device, error](dev)
				})
			}
		}(dev)

		devices = append(devices, dev)
	}

	if len(devices) == 0 {
		return nil, errors.New("no supported devices found")
	}

	wg.Wait()

	sel := <-selection
	err, ok := sel.Right()
	if ok {
		return nil, err
	}
	selectedDev := sel.MustLeft()

	for _, dev := range devices {
		if selectedDev.Path == dev.Path {
			continue
		}

		if err := dev.Close(); err != nil {
			return nil, err
		}
	}

	return selectedDev, nil
}
