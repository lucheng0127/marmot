package tproxy

// TCPRelay is a placeholder for Phase 3 sing-box outbound integration.
// Phase 2 的 TProxy 在收到连接后立即关闭（仅做决策缓存）。
// Phase 3 将通过 TCPRelay 将连接转发到 sing-box outbound。
//
// TCPRelay 职责（Phase 3 实现）：
//   1. 从 TProxy 接受原始连接
//   2. 通过 sing-box outbound 建立到原始目标的连接
//   3. io.Copy 双向数据搬运
type TCPRelay struct{}

func NewTCPRelay() *TCPRelay {
	return &TCPRelay{}
}

// Relay forwards data between the client connection and the proxy outbound.
// stub — Phase 3 implementation.
func (r *TCPRelay) Relay() error {
	return nil
}
