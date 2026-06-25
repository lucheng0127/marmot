package dns

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/lucheng0127/marmot/pkg/log"
)

// Server listens for DNS queries and forwards them to the engine.
type Server struct {
	engine    *Engine
	udpAddr   string // e.g. "127.0.0.1:53"
	tcpAddr   string // e.g. "127.0.0.1:53"
	udpConn   *net.UDPConn
	tcpLn     net.Listener
	readTimeout time.Duration
	done      chan struct{}
}

func NewServer(addr string, engine *Engine) *Server {
	if addr == "" {
		addr = "127.0.0.1:53"
	}
	return &Server{
		engine:      engine,
		udpAddr:     addr,
		tcpAddr:     addr,
		readTimeout: 10 * time.Second,
		done:        make(chan struct{}),
	}
}

// Start begins listening for DNS queries on UDP and TCP.
func (s *Server) Start() error {
	// UDP listener
	udpAddr, err := net.ResolveUDPAddr("udp", s.udpAddr)
	if err != nil {
		return fmt.Errorf("resolve udp %s: %w", s.udpAddr, err)
	}
	s.udpConn, err = net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("listen udp %s: %w", s.udpAddr, err)
	}

	// TCP listener
	tcpAddr, err := net.ResolveTCPAddr("tcp", s.tcpAddr)
	if err != nil {
		return fmt.Errorf("resolve tcp %s: %w", s.tcpAddr, err)
	}
	s.tcpLn, err = net.ListenTCP("tcp", tcpAddr)
	if err != nil {
		s.udpConn.Close()
		return fmt.Errorf("listen tcp %s: %w", s.tcpAddr, err)
	}

	log.Info("DNS server listening", map[string]interface{}{
		"udp": s.udpAddr,
		"tcp": s.tcpAddr,
	})

	go s.serveUDP()
	go s.serveTCP()
	return nil
}

func (s *Server) serveUDP() {
	buf := make([]byte, 65535)
	for {
		select {
		case <-s.done:
			return
		default:
		}
		_ = s.udpConn.SetReadDeadline(time.Now().Add(s.readTimeout))
		n, clientAddr, err := s.udpConn.ReadFromUDP(buf)
		if err != nil {
			continue
		}
		go s.handleQuery(buf[:n], func(resp []byte) error {
			_, err := s.udpConn.WriteToUDP(resp, clientAddr)
			return err
		})
	}
}

func (s *Server) serveTCP() {
	for {
		select {
		case <-s.done:
			return
		default:
		}
		conn, err := s.tcpLn.Accept()
		if err != nil {
			continue
		}
		go s.handleTCPConn(conn)
	}
}

func (s *Server) handleTCPConn(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(s.readTimeout))

	// Read length-prefixed DNS message
	lenBuf := make([]byte, 2)
	if _, err := conn.Read(lenBuf); err != nil {
		return
	}
	length := int(lenBuf[0])<<8 | int(lenBuf[1])
	if length > 65535 || length < 0 {
		return
	}

	buf := make([]byte, length)
	if _, err := conn.Read(buf); err != nil {
		return
	}

	s.handleQuery(buf, func(resp []byte) error {
		respLen := make([]byte, 2)
		respLen[0] = byte(len(resp) >> 8)
		respLen[1] = byte(len(resp))
		if _, err := conn.Write(respLen); err != nil {
			return err
		}
		_, err := conn.Write(resp)
		return err
	})
}

type writeFunc func([]byte) error

func (s *Server) handleQuery(query []byte, write writeFunc) {
	ctx, cancel := context.WithTimeout(context.Background(), s.readTimeout)
	defer cancel()

	resp, err := s.engine.Resolve(ctx, query)
	if err != nil {
		log.Warn("DNS resolve error", map[string]interface{}{"error": err.Error()})
		return
	}
	if len(resp) == 0 {
		return
	}

	// Copy query ID from the original query (some upstreams may change it)
	if len(resp) >= 2 && len(query) >= 2 {
		resp[0] = query[0]
		resp[1] = query[1]
	}

	if err := write(resp); err != nil {
		log.Warn("DNS write error", map[string]interface{}{"error": err.Error()})
	}
}

// Close stops the DNS server.
func (s *Server) Close() error {
	close(s.done)
	if s.udpConn != nil {
		s.udpConn.Close()
	}
	if s.tcpLn != nil {
		s.tcpLn.Close()
	}
	return nil
}
