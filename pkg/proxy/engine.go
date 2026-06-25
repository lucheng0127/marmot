package proxy

import (
	"context"
	"fmt"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
)

// Engine wraps a sing-box Box instance as an outbound engine only.
// Per ADR-003/008: sing-box handles outbound protocols, Marmot handles inbound.
type Engine struct {
	box    *box.Box
	ctx    context.Context
	cancel context.CancelFunc
}

// New creates a new Engine from the given sing-box options.
func New(ctx context.Context, options option.Options) (*Engine, error) {
	instance, err := box.New(box.Options{
		Context: include.Context(ctx),
		Options: options,
	})
	if err != nil {
		return nil, fmt.Errorf("sing-box new: %w", err)
	}
	subCtx, cancel := context.WithCancel(ctx)
	return &Engine{
		box:    instance,
		ctx:    subCtx,
		cancel: cancel,
	}, nil
}

func (e *Engine) Start() error {
	return e.box.Start()
}

func (e *Engine) Close() error {
	e.cancel()
	return e.box.Close()
}
