package options

import (
	"context"
	"log/slog"

	"github.com/fxamacker/cbor/v2"
)

type Options struct {
	Logger       *slog.Logger
	EncMode      cbor.EncMode
	Context      context.Context
	Paths        []string
	UseNamedPipe bool
}

type Option func(*Options)

func WithLogger(logger *slog.Logger) Option {
	return func(opts *Options) {
		opts.Logger = logger
	}
}

func WithEncMode(encMode cbor.EncMode) Option {
	return func(opts *Options) {
		opts.EncMode = encMode
	}
}

func WithContext(ctx context.Context) Option {
	return func(opts *Options) {
		opts.Context = ctx
	}
}

func WithPaths(paths ...string) Option {
	return func(opts *Options) {
		opts.Paths = paths
	}
}

func WithUseNamedPipes() Option {
	return func(opts *Options) {
		opts.UseNamedPipe = true
	}
}

func NewOptions(opts ...Option) *Options {
	encMode, _ := cbor.CTAP2EncOptions().EncMode()
	oo := &Options{
		Logger:  slog.Default(),
		EncMode: encMode,
		Context: context.Background(),
	}

	for _, opt := range opts {
		opt(oo)
	}

	return oo
}
