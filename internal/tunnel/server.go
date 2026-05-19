package tunnel

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/hashicorp/yamux"
	"github.com/jfhack/passage/internal/auth"
	"github.com/jfhack/passage/internal/config"
	"github.com/jfhack/passage/internal/mux"
	"github.com/jfhack/passage/internal/proto"
)

const maxPendingHandshakes = 64

type Server struct {
	cfg    *config.ServerConfig
	tlsCfg *tls.Config
	log    *slog.Logger

	clientsByID  map[string]*config.ClientEntry
	clientPubs   map[string][]ed25519.PublicKey
	clientPQPubs map[string][]*mldsa65.PublicKey
	allowed      map[string]map[string]config.ServiceEntry

	handshakeSem chan struct{}

	mu       sync.Mutex
	sessions map[string]*serverSession
}

type serverSession struct {
	id        string
	clientID  string
	yam       *yamux.Session
	cancel    context.CancelFunc
	listeners []net.Listener
	streamSem chan struct{}
}

func NewServer(cfg *config.ServerConfig, logger *slog.Logger) (*Server, error) {
	tlsCfg, err := serverTLSConfig(cfg.TLS.Cert, cfg.TLS.Key)
	if err != nil {
		return nil, err
	}
	clientsByID := make(map[string]*config.ClientEntry, len(cfg.Clients))
	clientPubs := make(map[string][]ed25519.PublicKey, len(cfg.Clients))
	clientPQPubs := make(map[string][]*mldsa65.PublicKey, len(cfg.Clients))
	allowed := make(map[string]map[string]config.ServiceEntry, len(cfg.Clients))
	for i := range cfg.Clients {
		ce := &cfg.Clients[i]
		clientsByID[ce.ID] = ce
		var pubs []ed25519.PublicKey
		for _, txt := range ce.Pubkey {
			pub, err := auth.DecodePubkey(txt)
			if err != nil {
				return nil, fmt.Errorf("client %q: %w", ce.ID, err)
			}
			pubs = append(pubs, pub)
		}
		clientPubs[ce.ID] = pubs
		if len(ce.PQPubkey) == 0 {
			return nil, fmt.Errorf("client %q: pq_pubkey is required", ce.ID)
		}
		var pqPubs []*mldsa65.PublicKey
		for _, txt := range ce.PQPubkey {
			pq, err := auth.DecodePQPubkey(txt)
			if err != nil {
				return nil, fmt.Errorf("client %q: %w", ce.ID, err)
			}
			pqPubs = append(pqPubs, pq)
		}
		clientPQPubs[ce.ID] = pqPubs
		svcMap := make(map[string]config.ServiceEntry, len(ce.Services))
		for _, s := range ce.Services {
			svcMap[s.Name] = s
		}
		allowed[ce.ID] = svcMap
	}
	return &Server{
		cfg:          cfg,
		tlsCfg:       tlsCfg,
		log:          logger,
		clientsByID:  clientsByID,
		clientPubs:   clientPubs,
		clientPQPubs: clientPQPubs,
		allowed:      allowed,
		handshakeSem: make(chan struct{}, maxPendingHandshakes),
		sessions:     make(map[string]*serverSession),
	}, nil
}

func (s *Server) Run(ctx context.Context) error {
	lc := net.ListenConfig{}
	rawL, err := lc.Listen(ctx, "tcp", s.cfg.Listen)
	if err != nil {
		return fmt.Errorf("listen %s: %w", s.cfg.Listen, err)
	}
	tlsL := tls.NewListener(rawL, s.tlsCfg)
	s.log.Info("server listening", "addr", s.cfg.Listen)
	go func() {
		<-ctx.Done()
		_ = tlsL.Close()
	}()
	for {
		conn, err := tlsL.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) || ctx.Err() != nil {
				return nil
			}
			s.log.Warn("accept error", "err", err.Error())
			continue
		}
		select {
		case s.handshakeSem <- struct{}{}:
			go s.handleControl(ctx, conn)
		default:
			s.log.Warn("handshake backpressure, dropping connection",
				"remote", conn.RemoteAddr().String())
			_ = conn.Close()
		}
	}
}

func (s *Server) handleControl(ctx context.Context, raw net.Conn) {
	remote := raw.RemoteAddr().String()
	semHeld := true
	defer func() {
		if semHeld {
			<-s.handshakeSem
			_ = raw.Close()
		}
	}()
	tlsConn, ok := raw.(*tls.Conn)
	if !ok {
		s.log.Warn("non-tls conn on control listener", "remote", remote)
		return
	}
	hsCtx, cancel := context.WithTimeout(ctx, s.cfg.Limits.HandshakeTimeout)
	defer cancel()
	if err := tlsConn.HandshakeContext(hsCtx); err != nil {
		s.log.Warn("tls handshake failed", "remote", remote, "err", err.Error())
		return
	}
	cs := tlsConn.ConnectionState()
	exporter, err := cs.ExportKeyingMaterial(proto.AuthLabel, nil, proto.ExporterLength)
	if err != nil {
		s.log.Warn("exporter failed", "remote", remote, "err", err.Error())
		return
	}
	clientID, sessID, requested, err := s.runHandshake(hsCtx, tlsConn, exporter)
	if err != nil {
		return
	}
	yam, err := mux.Server(tlsConn, mux.Config{
		HeartbeatInterval: s.cfg.Limits.HeartbeatInterval,
		IdleTimeout:       s.cfg.Limits.IdleTimeout,
	})
	if err != nil {
		s.log.Warn("yamux server init failed", "remote", remote, "err", err.Error())
		return
	}
	<-s.handshakeSem
	semHeld = false
	defer tlsConn.Close()
	s.runSession(ctx, clientID, sessID, requested, yam)
}

func (s *Server) runHandshake(ctx context.Context, conn net.Conn, exporter []byte) (clientID, sessionID string, requested []string, err error) {
	deadline, _ := ctx.Deadline()
	if !deadline.IsZero() {
		_ = conn.SetDeadline(deadline)
		defer conn.SetDeadline(time.Time{})
	}
	nonce, err := auth.NewNonce()
	if err != nil {
		return "", "", nil, err
	}
	hello := proto.ServerHello{Nonce: nonce, ServerTime: time.Now().Unix()}
	if err := proto.WriteMessage(conn, hello); err != nil {
		s.log.Warn("hello write failed", "err", err.Error())
		return "", "", nil, err
	}
	var ca proto.ClientAuth
	if err := proto.ReadMessage(conn, &ca); err != nil {
		s.log.Warn("clientauth read failed", "err", err.Error())
		return "", "", nil, err
	}
	reason, ok := s.validateAuth(nonce, exporter, &ca)
	if !ok {
		s.log.Warn("auth rejected", "client_id", ca.ClientID, "reason", reason)
		_ = proto.WriteMessage(conn, proto.AuthFailed{Reason: "authentication failed"})
		return "", "", nil, errors.New(reason)
	}
	sid := newSessionID()
	if err := proto.WriteMessage(conn, proto.Accepted{SessionID: sid}); err != nil {
		s.log.Warn("accepted write failed", "err", err.Error())
		return "", "", nil, err
	}
	s.log.Info("client authenticated",
		"client_id", ca.ClientID,
		"session_id", sid,
		"requested_services", ca.RequestedServices,
	)
	return ca.ClientID, sid, ca.RequestedServices, nil
}

func (s *Server) validateAuth(nonce, exporter []byte, ca *proto.ClientAuth) (string, bool) {
	if err := auth.CheckClockSkew(time.Now(), ca.ClientTime); err != nil {
		return "clock skew", false
	}
	pubs, ok := s.clientPubs[ca.ClientID]
	if !ok {
		return "unknown client id", false
	}
	if err := auth.Verify(pubs, ca.Signature, nonce, exporter, ca.ClientID, ca.ClientTime); err != nil {
		return "bad signature", false
	}
	if len(ca.RequestedServices) == 0 {
		return "no services requested", false
	}
	allowed := s.allowed[ca.ClientID]
	for _, name := range ca.RequestedServices {
		if _, ok := allowed[name]; !ok {
			return "service " + name + " not allowed", false
		}
	}
	pqPubs := s.clientPQPubs[ca.ClientID]
	if ca.PQAlgorithm == "" || len(ca.PQSignature) == 0 {
		return "pq signature required", false
	}
	if ca.PQAlgorithm != auth.PQAlgorithmMLDSA {
		return "unknown pq_algorithm " + ca.PQAlgorithm, false
	}
	if err := auth.PQVerify(pqPubs, ca.PQSignature, nonce, exporter, ca.ClientID, ca.ClientTime, ca.RequestedServices); err != nil {
		return "bad pq signature", false
	}
	return "", true
}

func newSessionID() string {
	var b [12]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

func (s *Server) runSession(ctx context.Context, clientID, sessionID string, requested []string, yam *yamux.Session) {
	sessCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer yam.Close()

	sess := &serverSession{
		id:        sessionID,
		clientID:  clientID,
		yam:       yam,
		cancel:    cancel,
		streamSem: make(chan struct{}, s.cfg.Limits.MaxStreamsPerClient),
	}
	if old := s.replaceSession(clientID, sess); old != nil {
		s.log.Info("replacing prior session", "client_id", clientID, "old_session_id", old.id)
		old.shutdown()
	}
	defer s.removeSession(clientID, sess)

	allowed := s.allowed[clientID]
	for _, name := range requested {
		svc, ok := allowed[name]
		if !ok {
			continue
		}
		ln, err := net.Listen("tcp", svc.Listen)
		if err != nil {
			s.log.Error("service listen failed",
				"client_id", clientID, "service", svc.Name, "listen", svc.Listen, "err", err.Error())
			return
		}
		sess.listeners = append(sess.listeners, ln)
		go func(svc config.ServiceEntry, ln net.Listener) {
			s.acceptUsers(sessCtx, sess, svc, ln)
		}(svc, ln)
	}

	<-yam.CloseChan()
	s.log.Info("session closed", "client_id", clientID, "session_id", sessionID)
}

func (s *Server) acceptUsers(ctx context.Context, sess *serverSession, svc config.ServiceEntry, ln net.Listener) {
	go func() {
		<-ctx.Done()
		_ = ln.Close()
	}()
	allowed := parseCIDRs(svc.AllowedUserCIDRs)
	s.log.Info("service ready", "client_id", sess.clientID, "service", svc.Name, "listen", svc.Listen)
	for {
		uc, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			s.log.Warn("user accept error", "service", svc.Name, "err", err.Error())
			continue
		}
		if !cidrAllowed(uc.RemoteAddr(), allowed) {
			s.log.Warn("user rejected by cidr",
				"service", svc.Name, "remote", uc.RemoteAddr().String())
			_ = uc.Close()
			continue
		}
		go s.proxyUser(sess, svc, uc)
	}
}

func (s *Server) proxyUser(sess *serverSession, svc config.ServiceEntry, uc net.Conn) {
	defer uc.Close()
	select {
	case sess.streamSem <- struct{}{}:
		defer func() { <-sess.streamSem }()
	default:
		s.log.Warn("max streams reached, dropping user",
			"client_id", sess.clientID, "service", svc.Name)
		return
	}
	stream, err := sess.yam.OpenStream()
	if err != nil {
		s.log.Warn("open stream failed",
			"client_id", sess.clientID, "service", svc.Name, "err", err.Error())
		return
	}
	defer stream.Close()
	open := proto.Open{
		Type:        proto.TypeOpen,
		StreamID:    uint64(stream.StreamID()),
		ServiceName: svc.Name,
	}
	if err := proto.WriteMessage(stream, open); err != nil {
		s.log.Warn("open header write failed",
			"client_id", sess.clientID, "service", svc.Name, "err", err.Error())
		return
	}
	s.log.Info("stream opened",
		"client_id", sess.clientID, "service", svc.Name,
		"stream_id", open.StreamID, "user_remote", uc.RemoteAddr().String())
	relay(uc, stream)
	s.log.Info("stream closed",
		"client_id", sess.clientID, "service", svc.Name, "stream_id", open.StreamID)
}

func (s *Server) replaceSession(clientID string, ns *serverSession) *serverSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	old := s.sessions[clientID]
	s.sessions[clientID] = ns
	return old
}

func (s *Server) removeSession(clientID string, ns *serverSession) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if cur, ok := s.sessions[clientID]; ok && cur == ns {
		delete(s.sessions, clientID)
	}
	for _, ln := range ns.listeners {
		_ = ln.Close()
	}
}

func (ss *serverSession) shutdown() {
	if ss.cancel != nil {
		ss.cancel()
	}
	for _, ln := range ss.listeners {
		_ = ln.Close()
	}
	if ss.yam != nil {
		_ = ss.yam.Close()
	}
}

func parseCIDRs(in []string) []netip.Prefix {
	if len(in) == 0 {
		return nil
	}
	out := make([]netip.Prefix, 0, len(in))
	for _, c := range in {
		if p, err := netip.ParsePrefix(c); err == nil {
			out = append(out, p)
		}
	}
	return out
}

func cidrAllowed(addr net.Addr, prefixes []netip.Prefix) bool {
	if len(prefixes) == 0 {
		return true
	}
	host, _, err := net.SplitHostPort(addr.String())
	if err != nil {
		return false
	}
	a, err := netip.ParseAddr(host)
	if err != nil {
		return false
	}
	for _, p := range prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

func relay(a, b io.ReadWriteCloser) {
	done := make(chan struct{}, 2)
	go func() {
		_, _ = io.Copy(a, b)
		_ = a.Close()
		done <- struct{}{}
	}()
	go func() {
		_, _ = io.Copy(b, a)
		_ = b.Close()
		done <- struct{}{}
	}()
	<-done
	<-done
}
