package server

import (
	"net/netip"
	"sort"
	"time"

	"github.com/softvpn/softvpn/internal/ovpn"
)

// Read-only views of a running server, and the few actions on its sessions,
// for management interfaces (the web UI).

// SessionStatus describes one connected client.
type SessionStatus struct {
	ovpn.SessionInfo
	CommonName string
	Username   string
	Remote     string // "udp:203.0.113.5:51234"
	IP         netip.Addr
	IP6        netip.Addr // invalid without server-ipv6
	IRoutes    []netip.Prefix
	RxBytes    uint64
	TxBytes    uint64
}

// Config is the configuration the server runs with. It must not be modified.
func (s *Server) Config() *Config { return s.cfg }

// Started is when the server finished starting (zero before Start returns).
func (s *Server) Started() time.Time { return s.started }

// Listening lists the sockets the server accepts clients on.
func (s *Server) Listening() []Listening { return append([]Listening(nil), s.listening...) }

// Sessions lists the connected clients, ordered by virtual address.
func (s *Server) Sessions() []SessionStatus {
	type row struct {
		ss *ovpn.Session
		p  peer
	}
	s.mu.RLock()
	rows := make([]row, 0, len(s.sessions))
	for ss, p := range s.sessions {
		rows = append(rows, row{ss, *p})
	}
	s.mu.RUnlock()
	out := make([]SessionStatus, 0, len(rows))
	for _, r := range rows {
		out = append(out, SessionStatus{
			SessionInfo: r.ss.Info(),
			CommonName:  r.ss.CommonName(),
			Username:    r.ss.Username(),
			Remote:      r.ss.Remote(),
			IP:          r.p.ip,
			IP6:         r.p.ip6,
			IRoutes:     append([]netip.Prefix(nil), r.p.iroutes...),
			RxBytes:     r.ss.RxBytes.Load(),
			TxBytes:     r.ss.TxBytes.Load(),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IP.Less(out[j].IP) })
	return out
}

// sessionsWhere returns the connected sessions for which match is true.
func (s *Server) sessionsWhere(match func(*ovpn.Session) bool) []*ovpn.Session {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []*ovpn.Session
	for ss := range s.sessions {
		if match(ss) {
			out = append(out, ss)
		}
	}
	return out
}

// Control messages that make a stock client exit, or reconnect keeping the
// password it has cached ("[P]"), as OpenVPN's management "client-kill" and
// explicit-exit-notify send them.
const (
	msgHalt    = "HALT,disconnected by the administrator"
	msgRestart = "RESTART,[P]"
)

// DisconnectPeer ends the session with the given peer id. The client is
// told to exit ("HALT") or, with reconnect, to reconnect ("RESTART"). It
// reports whether such a session was connected.
func (s *Server) DisconnectPeer(peerID uint32, reconnect bool) bool {
	found := s.sessionsWhere(func(ss *ovpn.Session) bool { return ss.Info().PeerID == peerID })
	for _, ss := range found {
		s.log.Info("disconnecting client on request", "client", ss.CommonName(), "remote", ss.Remote(), "reconnect", reconnect)
		if reconnect {
			ss.Kick(msgRestart, "disconnected by the administrator (reconnect)")
		} else {
			ss.Kick(msgHalt, "disconnected by the administrator")
		}
	}
	return len(found) > 0
}

// RestartClients tells every connected client to reconnect and returns how
// many there were. Stock clients from OpenVPN 2.4 on reconnect at once;
// older ones when their ping-restart timer runs out.
func (s *Server) RestartClients() int {
	all := s.sessionsWhere(func(*ovpn.Session) bool { return true })
	for _, ss := range all {
		ss.Notify(msgRestart)
	}
	return len(all)
}
