package proxy

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/lucheng0127/marmot/pkg/log"
)

type Engine struct {
	box    *box.Box
	ctx    context.Context
	cancel context.CancelFunc
	dialer N.Dialer
}

func New(ctx context.Context, options option.Options) (*Engine, error) {
	sboxCtx := include.Context(ctx)
	instance, err := box.New(box.Options{
		Context: sboxCtx,
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
		dialer: dialer.NewDefaultOutbound(sboxCtx),
	}, nil
}

func (e *Engine) Start() error { return e.box.Start() }
func (e *Engine) Close() error { e.cancel(); return e.box.Close() }

func (e *Engine) DialTimeout(network, addr string, timeout time.Duration) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(e.ctx, timeout)
	defer cancel()
	dest := M.ParseSocksaddr(addr)
	log.Debug("sing-box dial", map[string]interface{}{
		"network":   network,
		"addr":      addr,
		"fqdn":      dest.IsFqdn(),
		"is_ip":     dest.IsIP(),
		"is_valid":  dest.IsValid(),
		"addr_str":  dest.Addr.String(),
		"addr_port": dest.Port,
	})
	conn, err := e.dialer.DialContext(ctx, network, dest)
	if err != nil {
		return nil, fmt.Errorf("sing-box dial %s: %w", addr, err)
	}
	return conn, nil
}
