package tunnel

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net"
	"time"

	"github.com/cloudflare/circl/sign/mldsa/mldsa65"
	"github.com/hashicorp/yamux"
	"github.com/jfhack/passage/internal/auth"
	"github.com/jfhack/passage/internal/config"
	"github.com/jfhack/passage/internal/mux"
	"github.com/jfhack/passage/internal/proto"
)

type Client struct {
	cfg    *config.ClientConfig
	tlsCfg *tls.Config
	priv   ed25519.PrivateKey
	pqPriv *mldsa65.PrivateKey
	log    *slog.Logger
}

func NewClient(cfg *config.ClientConfig, logger *slog.Logger) (*Client, error) {
	priv, err := auth.LoadPrivkeyPEM(cfg.Identity.PrivkeyFile)
	if err != nil {
		return nil, fmt.Errorf("load privkey: %w", err)
	}
	_, pqPriv, err := auth.LoadPQPrivkeyPEM(cfg.Identity.PQPrivkeyFile)
	if err != nil {
		return nil, fmt.Errorf("load pq privkey: %w", err)
	}
	tlsCfg, err := clientTLSConfig(cfg.ServerFingerprint)
	if err != nil {
		return nil, err
	}
	return &Client{cfg: cfg, tlsCfg: tlsCfg, priv: priv, pqPriv: pqPriv, log: logger}, nil
}

func (c *Client) Run(ctx context.Context) error {
	backoff := c.cfg.Reconnect.InitialBackoff
	for {
		if ctx.Err() != nil {
			return nil
		}
		err := c.connectAndServe(ctx)
		if err == nil || ctx.Err() != nil {
			return nil
		}
		c.log.Warn("session ended, will reconnect", "err", err.Error(), "backoff", backoff.String())
		if !sleepCtx(ctx, jitterDelay(backoff, c.cfg.Reconnect.Jitter)) {
			return nil
		}
		backoff *= 2
		if backoff > c.cfg.Reconnect.MaxBackoff {
			backoff = c.cfg.Reconnect.MaxBackoff
		}
	}
}

func (c *Client) VerifyOnce(ctx context.Context) error {
	d := net.Dialer{Timeout: 10 * time.Second}
	raw, err := d.DialContext(ctx, "tcp", c.cfg.Remote)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	defer raw.Close()
	tlsConn := tls.Client(raw, c.tlsCfg)
	hsCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := tlsConn.HandshakeContext(hsCtx); err != nil {
		return fmt.Errorf("tls handshake: %w", err)
	}
	cs := tlsConn.ConnectionState()
	exporter, err := cs.ExportKeyingMaterial(proto.AuthLabel, nil, proto.ExporterLength)
	if err != nil {
		return fmt.Errorf("exporter: %w", err)
	}
	if _, err := c.runHandshake(tlsConn, exporter); err != nil {
		return err
	}
	return nil
}

func (c *Client) connectAndServe(ctx context.Context) error {
	d := net.Dialer{Timeout: 10 * time.Second}
	raw, err := d.DialContext(ctx, "tcp", c.cfg.Remote)
	if err != nil {
		return fmt.Errorf("dial: %w", err)
	}
	tlsConn := tls.Client(raw, c.tlsCfg)
	hsCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := tlsConn.HandshakeContext(hsCtx); err != nil {
		_ = raw.Close()
		return fmt.Errorf("tls handshake: %w", err)
	}
	cs := tlsConn.ConnectionState()
	exporter, err := cs.ExportKeyingMaterial(proto.AuthLabel, nil, proto.ExporterLength)
	if err != nil {
		_ = tlsConn.Close()
		return fmt.Errorf("exporter: %w", err)
	}
	sessID, err := c.runHandshake(tlsConn, exporter)
	if err != nil {
		_ = tlsConn.Close()
		return err
	}
	yam, err := mux.Client(tlsConn, mux.Config{
		HeartbeatInterval: 30 * time.Second,
		IdleTimeout:       5 * time.Minute,
	})
	if err != nil {
		_ = tlsConn.Close()
		return fmt.Errorf("yamux client: %w", err)
	}
	defer yam.Close()
	c.log.Info("session established", "remote", c.cfg.Remote, "session_id", sessID)
	return c.acceptStreams(ctx, yam)
}

func (c *Client) runHandshake(conn net.Conn, exporter []byte) (string, error) {
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	defer conn.SetDeadline(time.Time{})

	var hello proto.ServerHello
	if err := proto.ReadMessage(conn, &hello); err != nil {
		return "", fmt.Errorf("read hello: %w", err)
	}
	now := time.Now().Unix()
	id := c.cfg.Identity.ID
	requested := c.cfg.ServiceNames()
	sig := auth.Sign(c.priv, hello.Nonce, exporter, id, now)
	pqSig, err := auth.PQSign(c.pqPriv, hello.Nonce, exporter, id, now, requested)
	if err != nil {
		return "", fmt.Errorf("pq sign: %w", err)
	}
	ca := proto.ClientAuth{
		ClientID:          id,
		ClientTime:        now,
		Signature:         sig,
		RequestedServices: requested,
		PQAlgorithm:       auth.PQAlgorithmMLDSA,
		PQSignature:       pqSig,
	}
	if err := proto.WriteMessage(conn, ca); err != nil {
		return "", fmt.Errorf("write auth: %w", err)
	}
	var acc proto.Accepted
	if err := proto.ReadMessage(conn, &acc); err != nil {
		return "", fmt.Errorf("read accepted: %w", err)
	}
	if acc.SessionID == "" {
		return "", errors.New("server response missing session id (auth likely failed)")
	}
	return acc.SessionID, nil
}

func (c *Client) acceptStreams(ctx context.Context, yam *yamux.Session) error {
	go func() {
		<-ctx.Done()
		_ = yam.Close()
	}()
	for {
		stream, err := yam.AcceptStream()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return fmt.Errorf("accept stream: %w", err)
		}
		go c.handleStream(stream)
	}
}

func (c *Client) handleStream(stream *yamux.Stream) {
	defer stream.Close()
	_ = stream.SetReadDeadline(time.Now().Add(10 * time.Second))
	var open proto.Open
	if err := proto.ReadMessage(stream, &open); err != nil {
		c.log.Warn("read open header failed", "err", err.Error())
		return
	}
	_ = stream.SetReadDeadline(time.Time{})
	target, ok := c.cfg.Services[open.ServiceName]
	if !ok {
		c.log.Warn("server opened unknown service",
			"stream_id", open.StreamID, "service", open.ServiceName)
		return
	}
	c.log.Info("dialing local target",
		"stream_id", open.StreamID, "service", open.ServiceName, "target", target)
	d := net.Dialer{Timeout: 10 * time.Second}
	local, err := d.Dial("tcp", target)
	if err != nil {
		c.log.Warn("dial target failed",
			"service", open.ServiceName, "target", target, "err", err.Error())
		return
	}
	defer local.Close()
	relay(stream, local)
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}

func jitterDelay(base time.Duration, jitter bool) time.Duration {
	if !jitter || base <= 0 {
		return base
	}
	half := int64(base / 2)
	if half <= 0 {
		return base
	}
	add := rand.Int64N(int64(base))
	return time.Duration(half + add)
}
