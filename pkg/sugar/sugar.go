package sugar

import (
	"context"
	"errors"
	"sync"

	"github.com/savely-krasovsky/go-ctaphid/pkg/ctap"
	"github.com/savely-krasovsky/go-ctaphid/pkg/ctaptypes"
	"github.com/savely-krasovsky/go-ctaphid/pkg/device"

	"github.com/samber/mo"
	"github.com/sstallion/go-hid"
)

func EnumerateFIDODevices() ([]*hid.DeviceInfo, error) {
	var devInfos []*hid.DeviceInfo
	if err := hid.Enumerate(hid.VendorIDAny, hid.ProductIDAny, func(info *hid.DeviceInfo) error {
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

type Options struct {
	DevInfos       []*hid.DeviceInfo
	CTAPClientOpts []ctap.ClientOption
}

type Option func(*Options)

func WithDeviceInfos(devInfos []*hid.DeviceInfo) Option {
	return func(o *Options) {
		o.DevInfos = devInfos
	}
}

func WithCTAPClientOpts(opts ...ctap.ClientOption) Option {
	return func(o *Options) {
		o.CTAPClientOpts = opts
	}
}

// SelectDevice allows selecting a device by confirming presence;
// useful while a user has many tokens connected. Works only with FIDO 2.1 tokens (including PRE).
func SelectDevice(opts ...Option) (*device.Device, error) {
	options := new(Options)
	for _, opt := range opts {
		opt(options)
	}

	if options.DevInfos == nil {
		var err error
		options.DevInfos, err = EnumerateFIDODevices()
		if err != nil {
			return nil, err
		}
	}

	if len(options.DevInfos) == 1 {
		return device.New(options.DevInfos[0].Path, options.CTAPClientOpts...)
	}

	devices := make([]*device.Device, 0)

	// Here we will receive either a device or an error from first success Selection() call.
	selection := make(chan mo.Either[*device.Device, error])

	// WaitGroup allows us to wait for all Selection() calls to finish.
	var wg sync.WaitGroup

	// It will allow us to cancel all other active Selection() calls
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	for _, info := range options.DevInfos {
		dev, err := device.New(info.Path, options.CTAPClientOpts...)
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
