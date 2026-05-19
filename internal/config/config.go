package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type ServerConfig struct {
	Listen  string        `yaml:"listen"`
	TLS     TLSConfig     `yaml:"tls"`
	Clients []ClientEntry `yaml:"clients"`
	Limits  LimitsConfig  `yaml:"limits"`
}

type TLSConfig struct {
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
}

type ClientEntry struct {
	ID       string         `yaml:"id"`
	Pubkey   StringOrSlice  `yaml:"pubkey"`
	PQPubkey StringOrSlice  `yaml:"pq_pubkey"`
	Services []ServiceEntry `yaml:"services"`
}

type ServiceEntry struct {
	Name             string   `yaml:"name"`
	Listen           string   `yaml:"listen"`
	AllowedUserCIDRs []string `yaml:"allowed_user_cidrs"`
}

type LimitsConfig struct {
	MaxStreamsPerClient int           `yaml:"max_streams_per_client"`
	HandshakeTimeout    time.Duration `yaml:"handshake_timeout"`
	IdleTimeout         time.Duration `yaml:"idle_timeout"`
	HeartbeatInterval   time.Duration `yaml:"heartbeat_interval"`
}

type ClientConfig struct {
	Remote            string            `yaml:"remote"`
	ServerFingerprint string            `yaml:"server_fingerprint"`
	Identity          IdentityConfig    `yaml:"identity"`
	Services          map[string]string `yaml:"services"`
	Reconnect         ReconnectConfig   `yaml:"reconnect"`
}

type IdentityConfig struct {
	ID            string `yaml:"id"`
	PrivkeyFile   string `yaml:"privkey_file"`
	PQPrivkeyFile string `yaml:"pq_privkey_file"`
}

type ReconnectConfig struct {
	InitialBackoff time.Duration `yaml:"initial_backoff"`
	MaxBackoff     time.Duration `yaml:"max_backoff"`
	Jitter         bool          `yaml:"jitter"`
}

type StringOrSlice []string

func (s *StringOrSlice) UnmarshalYAML(value *yaml.Node) error {
	switch value.Kind {
	case yaml.ScalarNode:
		var single string
		if err := value.Decode(&single); err != nil {
			return err
		}
		*s = []string{single}
	case yaml.SequenceNode:
		var many []string
		if err := value.Decode(&many); err != nil {
			return err
		}
		*s = many
	default:
		return fmt.Errorf("expected string or list, got kind %d", value.Kind)
	}
	return nil
}

func LoadServer(path string) (*ServerConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c ServerConfig
	if err := strictUnmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("config: %s: %w", path, err)
	}
	c.applyDefaults()
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("config: %s: %w", path, err)
	}
	return &c, nil
}

func LoadClient(path string) (*ClientConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c ClientConfig
	if err := strictUnmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("config: %s: %w", path, err)
	}
	c.applyDefaults()
	if err := c.Validate(); err != nil {
		return nil, fmt.Errorf("config: %s: %w", path, err)
	}
	return &c, nil
}

func strictUnmarshal(data []byte, into any) error {
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(into); err != nil {
		return err
	}
	return nil
}

func (c *ServerConfig) applyDefaults() {
	if c.Limits.MaxStreamsPerClient == 0 {
		c.Limits.MaxStreamsPerClient = 256
	}
	if c.Limits.HandshakeTimeout == 0 {
		c.Limits.HandshakeTimeout = 10 * time.Second
	}
	if c.Limits.IdleTimeout == 0 {
		c.Limits.IdleTimeout = 5 * time.Minute
	}
	if c.Limits.HeartbeatInterval == 0 {
		c.Limits.HeartbeatInterval = 30 * time.Second
	}
}

func (c *ClientConfig) applyDefaults() {
	if c.Reconnect.InitialBackoff == 0 {
		c.Reconnect.InitialBackoff = 1 * time.Second
	}
	if c.Reconnect.MaxBackoff == 0 {
		c.Reconnect.MaxBackoff = 60 * time.Second
	}
}

func (c *ServerConfig) Validate() error {
	if c.Listen == "" {
		return errors.New("listen is required")
	}
	if _, _, err := net.SplitHostPort(c.Listen); err != nil {
		return fmt.Errorf("listen: %w", err)
	}
	if c.TLS.Cert == "" || c.TLS.Key == "" {
		return errors.New("tls.cert and tls.key are required")
	}
	if len(c.Clients) == 0 {
		return errors.New("at least one client must be configured")
	}
	seenIDs := map[string]struct{}{}
	listens := map[string]string{}
	for i := range c.Clients {
		ce := &c.Clients[i]
		if ce.ID == "" {
			return fmt.Errorf("clients[%d].id is required", i)
		}
		if _, dup := seenIDs[ce.ID]; dup {
			return fmt.Errorf("duplicate client id %q", ce.ID)
		}
		seenIDs[ce.ID] = struct{}{}
		if len(ce.Pubkey) == 0 {
			return fmt.Errorf("client %q: at least one pubkey required", ce.ID)
		}
		for _, pk := range ce.Pubkey {
			if !strings.HasPrefix(pk, "ed25519:") {
				return fmt.Errorf("client %q: pubkey must be prefixed ed25519:", ce.ID)
			}
		}
		if len(ce.PQPubkey) == 0 {
			return fmt.Errorf("client %q: at least one pq_pubkey required", ce.ID)
		}
		for _, pk := range ce.PQPubkey {
			if !strings.HasPrefix(pk, "mldsa:") {
				return fmt.Errorf("client %q: pq_pubkey must be prefixed mldsa:", ce.ID)
			}
		}
		if len(ce.Services) == 0 {
			return fmt.Errorf("client %q: at least one service required", ce.ID)
		}
		seenSvc := map[string]struct{}{}
		for j := range ce.Services {
			s := &ce.Services[j]
			if s.Name == "" {
				return fmt.Errorf("client %q services[%d].name required", ce.ID, j)
			}
			if _, dup := seenSvc[s.Name]; dup {
				return fmt.Errorf("client %q: duplicate service %q", ce.ID, s.Name)
			}
			seenSvc[s.Name] = struct{}{}
			if _, _, err := net.SplitHostPort(s.Listen); err != nil {
				return fmt.Errorf("client %q service %q listen: %w", ce.ID, s.Name, err)
			}
			if owner, dup := listens[s.Listen]; dup {
				return fmt.Errorf("listen %q is reused (already used by %q)", s.Listen, owner)
			}
			listens[s.Listen] = ce.ID + "/" + s.Name
			for _, cidr := range s.AllowedUserCIDRs {
				if _, err := netip.ParsePrefix(cidr); err != nil {
					return fmt.Errorf("client %q service %q cidr %q: %w", ce.ID, s.Name, cidr, err)
				}
			}
		}
	}
	if c.Limits.MaxStreamsPerClient < 1 {
		return errors.New("limits.max_streams_per_client must be > 0")
	}
	if c.Limits.HandshakeTimeout <= 0 {
		return errors.New("limits.handshake_timeout must be > 0")
	}
	if c.Limits.IdleTimeout <= 0 {
		return errors.New("limits.idle_timeout must be > 0")
	}
	if c.Limits.HeartbeatInterval <= 0 {
		return errors.New("limits.heartbeat_interval must be > 0")
	}
	if c.Limits.HeartbeatInterval >= c.Limits.IdleTimeout {
		return errors.New("heartbeat_interval must be less than idle_timeout")
	}
	return nil
}

func (c *ClientConfig) Validate() error {
	if c.Remote == "" {
		return errors.New("remote is required")
	}
	if _, _, err := net.SplitHostPort(c.Remote); err != nil {
		return fmt.Errorf("remote: %w", err)
	}
	if !strings.HasPrefix(c.ServerFingerprint, "sha256:") {
		return errors.New("server_fingerprint must be prefixed sha256:")
	}
	if len(c.ServerFingerprint) != len("sha256:")+64 {
		return errors.New("server_fingerprint must be sha256: followed by 64 hex chars")
	}
	if c.Identity.ID == "" {
		return errors.New("identity.id is required")
	}
	if c.Identity.PrivkeyFile == "" {
		return errors.New("identity.privkey_file is required")
	}
	if c.Identity.PQPrivkeyFile == "" {
		return errors.New("identity.pq_privkey_file is required")
	}
	if len(c.Services) == 0 {
		return errors.New("at least one service must be configured")
	}
	for name, target := range c.Services {
		if name == "" {
			return errors.New("service name must not be empty")
		}
		if _, _, err := net.SplitHostPort(target); err != nil {
			return fmt.Errorf("service %q target: %w", name, err)
		}
	}
	if c.Reconnect.InitialBackoff <= 0 {
		return errors.New("reconnect.initial_backoff must be > 0")
	}
	if c.Reconnect.MaxBackoff <= 0 {
		return errors.New("reconnect.max_backoff must be > 0")
	}
	if c.Reconnect.MaxBackoff < c.Reconnect.InitialBackoff {
		return errors.New("reconnect.max_backoff must be >= reconnect.initial_backoff")
	}
	return nil
}

func (c *ClientConfig) ServiceNames() []string {
	out := make([]string, 0, len(c.Services))
	for name := range c.Services {
		out = append(out, name)
	}
	return out
}
