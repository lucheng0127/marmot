package proxy

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/common/dialer"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	"github.com/lucheng0127/marmot/pkg/log"
)

// Engine wraps the sing-box Box with a dialer for outbound connections.
type Engine struct {
	box        *box.Box
	ctx        context.Context
	cancel     context.CancelFunc
	dialer     N.Dialer
	nodeTags   []string
	defaultTag string
}

func New(ctx context.Context, options option.Options, nodeTags []string) (*Engine, error) {
	// Override Go's default resolver to bypass ISP DNS poisoning
	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			d := net.Dialer{Timeout: 3 * time.Second}
			return d.DialContext(ctx, network, "223.5.5.5:53")
		},
	}

	sboxCtx := include.Context(ctx)
	instance, err := box.New(box.Options{
		Context: sboxCtx,
		Options: options,
	})
	if err != nil {
		return nil, fmt.Errorf("sing-box new: %w", err)
	}
	subCtx, cancel := context.WithCancel(ctx)

	defaultTag := "direct"
	if len(nodeTags) > 0 {
		defaultTag = nodeTags[0]
	}

	return &Engine{
		box:        instance,
		ctx:        subCtx,
		cancel:     cancel,
		dialer:     dialer.NewDefaultOutbound(sboxCtx),
		nodeTags:   nodeTags,
		defaultTag: defaultTag,
	}, nil
}

func (e *Engine) Start() error { return e.box.Start() }
func (e *Engine) Close() error { e.cancel(); return e.box.Close() }

// DialTimeout connects through the proxy engine with a multi-node fallback.
// Returns the connection, the tag of the outbound used, or an error.
func (e *Engine) DialTimeout(network, addr string, timeout time.Duration) (net.Conn, string, error) {
	ctx, cancel := context.WithTimeout(e.ctx, timeout)
	defer cancel()

	dest := M.ParseSocksaddr(addr)

	// First try: DefaultOutboundDialer (uses Route.Final outbound)
	conn, err := e.dialer.DialContext(ctx, network, dest)
	if err == nil {
		return conn, e.defaultTag, nil
	}

	log.Debug("sing-box dial fail", map[string]interface{}{
		"addr": addr, "tag": e.defaultTag, "error": err.Error(),
	})

	// Fallback: try each outbound in order
	ob := service.FromContext[adapter.OutboundManager](e.ctx)

	for _, tag := range e.nodeTags {
		if tag == e.defaultTag {
			continue // already tried
		}
		outbound, ok := ob.Outbound(tag)
		if !ok {
			continue
		}
		conn, err = outbound.DialContext(ctx, network, dest)
		if err == nil {
			log.Debug("sing-box dial fallback", map[string]interface{}{
				"addr": addr, "tag": tag,
			})
			return conn, tag, nil
		}
		log.Debug("sing-box dial fail", map[string]interface{}{
			"addr": addr, "tag": tag, "error": err.Error(),
		})
	}

	return nil, "", fmt.Errorf("sing-box dial %s: all outbounds failed", addr)
}
