package mux

import (
	"io"
	"log"
	"net"
	"time"

	"github.com/hashicorp/yamux"
)

type Config struct {
	HeartbeatInterval time.Duration
	IdleTimeout       time.Duration
}

func toYamuxConfig(c Config) *yamux.Config {
	cfg := yamux.DefaultConfig()
	if c.HeartbeatInterval > 0 {
		cfg.KeepAliveInterval = c.HeartbeatInterval
	}
	if c.IdleTimeout > 0 {
		cfg.ConnectionWriteTimeout = c.IdleTimeout
	}
	cfg.LogOutput = nil
	cfg.Logger = log.New(io.Discard, "", 0)
	return cfg
}

func Server(conn net.Conn, c Config) (*yamux.Session, error) {
	return yamux.Server(conn, toYamuxConfig(c))
}

func Client(conn net.Conn, c Config) (*yamux.Session, error) {
	return yamux.Client(conn, toYamuxConfig(c))
}
