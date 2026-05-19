package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatalf("write: %v", err)
	}
	return p
}

func TestLoadServer_Valid(t *testing.T) {
	const yml = `
listen: 0.0.0.0:5679
tls:
  cert: /etc/passage/server.crt
  key:  /etc/passage/server.key
clients:
  - id: a
    pubkey: ed25519:AAAA
    pq_pubkey: mldsa:AAAA
    services:
      - name: ssh
        listen: 0.0.0.0:3022
limits:
  heartbeat_interval: 5s
  idle_timeout: 60s
`
	p := writeFile(t, "s.yaml", yml)
	c, err := LoadServer(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.Listen != "0.0.0.0:5679" {
		t.Errorf("listen mismatch: %q", c.Listen)
	}
	if len(c.Clients) != 1 || c.Clients[0].ID != "a" {
		t.Errorf("clients mismatch: %+v", c.Clients)
	}
	if len(c.Clients[0].Pubkey) != 1 {
		t.Errorf("pubkey not normalized")
	}
	if len(c.Clients[0].PQPubkey) != 1 {
		t.Errorf("pq_pubkey not normalized")
	}
}

func TestLoadServer_PubkeyAsList(t *testing.T) {
	const yml = `
listen: 0.0.0.0:5679
tls: { cert: a, key: b }
clients:
  - id: a
    pubkey:
      - ed25519:OLD
      - ed25519:NEW
    pq_pubkey: mldsa:K
    services:
      - { name: ssh, listen: 0.0.0.0:3022 }
`
	p := writeFile(t, "s.yaml", yml)
	c, err := LoadServer(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(c.Clients[0].Pubkey) != 2 {
		t.Errorf("got %d pubkeys, want 2", len(c.Clients[0].Pubkey))
	}
}

func TestLoadServer_UnknownField(t *testing.T) {
	const yml = `
listen: 0.0.0.0:5679
tls: { cert: a, key: b }
clients:
  - id: a
    pubkey: ed25519:AAAA
    pq_pubkey: mldsa:AAAA
    services: [ { name: ssh, listen: 0.0.0.0:3022 } ]
not_a_real_field: nope
`
	p := writeFile(t, "s.yaml", yml)
	if _, err := LoadServer(p); err == nil {
		t.Fatal("expected unknown-field error")
	}
}

func TestLoadServer_TableErrors(t *testing.T) {
	cases := []struct {
		name string
		yml  string
		want string
	}{
		{
			"missing listen",
			`tls: { cert: a, key: b }
clients:
  - id: a
    pubkey: ed25519:K
    pq_pubkey: mldsa:K
    services: [ { name: x, listen: 0.0.0.0:1 } ]`,
			"listen is required",
		},
		{
			"bad listen",
			`listen: not-a-port
tls: { cert: a, key: b }
clients:
  - id: a
    pubkey: ed25519:K
    pq_pubkey: mldsa:K
    services: [ { name: x, listen: 0.0.0.0:1 } ]`,
			"listen:",
		},
		{
			"missing tls",
			`listen: 0.0.0.0:5
clients:
  - id: a
    pubkey: ed25519:K
    pq_pubkey: mldsa:K
    services: [ { name: x, listen: 0.0.0.0:1 } ]`,
			"tls.cert and tls.key",
		},
		{
			"duplicate client id",
			`listen: 0.0.0.0:5
tls: { cert: a, key: b }
clients:
  - id: a
    pubkey: ed25519:K
    pq_pubkey: mldsa:K
    services: [ { name: x, listen: 0.0.0.0:1 } ]
  - id: a
    pubkey: ed25519:K
    pq_pubkey: mldsa:K
    services: [ { name: y, listen: 0.0.0.0:2 } ]`,
			"duplicate client id",
		},
		{
			"pubkey wrong prefix",
			`listen: 0.0.0.0:5
tls: { cert: a, key: b }
clients:
  - id: a
    pubkey: rsa:K
    pq_pubkey: mldsa:K
    services: [ { name: x, listen: 0.0.0.0:1 } ]`,
			"pubkey must be prefixed",
		},
		{
			"missing pq_pubkey",
			`listen: 0.0.0.0:5
tls: { cert: a, key: b }
clients:
  - id: a
    pubkey: ed25519:K
    services: [ { name: x, listen: 0.0.0.0:1 } ]`,
			"pq_pubkey required",
		},
		{
			"pq_pubkey wrong prefix",
			`listen: 0.0.0.0:5
tls: { cert: a, key: b }
clients:
  - id: a
    pubkey: ed25519:K
    pq_pubkey: ed25519:K
    services: [ { name: x, listen: 0.0.0.0:1 } ]`,
			"pq_pubkey must be prefixed",
		},
		{
			"service listen reused",
			`listen: 0.0.0.0:5
tls: { cert: a, key: b }
clients:
  - id: a
    pubkey: ed25519:K
    pq_pubkey: mldsa:K
    services:
      - { name: x, listen: 0.0.0.0:1 }
      - { name: y, listen: 0.0.0.0:1 }`,
			"reused",
		},
		{
			"bad cidr",
			`listen: 0.0.0.0:5
tls: { cert: a, key: b }
clients:
  - id: a
    pubkey: ed25519:K
    pq_pubkey: mldsa:K
    services:
      - { name: x, listen: 0.0.0.0:1, allowed_user_cidrs: [garbage] }`,
			"cidr",
		},
		{
			"hb >= idle",
			`listen: 0.0.0.0:5
tls: { cert: a, key: b }
clients:
  - id: a
    pubkey: ed25519:K
    pq_pubkey: mldsa:K
    services: [ { name: x, listen: 0.0.0.0:1 } ]
limits: { heartbeat_interval: 60s, idle_timeout: 60s }`,
			"heartbeat_interval",
		},
		{
			"negative max_streams",
			`listen: 0.0.0.0:5
tls: { cert: a, key: b }
clients:
  - id: a
    pubkey: ed25519:K
    pq_pubkey: mldsa:K
    services: [ { name: x, listen: 0.0.0.0:1 } ]
limits: { max_streams_per_client: -1 }`,
			"max_streams_per_client",
		},
		{
			"negative handshake_timeout",
			`listen: 0.0.0.0:5
tls: { cert: a, key: b }
clients:
  - id: a
    pubkey: ed25519:K
    pq_pubkey: mldsa:K
    services: [ { name: x, listen: 0.0.0.0:1 } ]
limits: { handshake_timeout: -1s }`,
			"handshake_timeout",
		},
		{
			"negative idle_timeout",
			`listen: 0.0.0.0:5
tls: { cert: a, key: b }
clients:
  - id: a
    pubkey: ed25519:K
    pq_pubkey: mldsa:K
    services: [ { name: x, listen: 0.0.0.0:1 } ]
limits: { idle_timeout: -1s }`,
			"idle_timeout",
		},
		{
			"negative heartbeat_interval",
			`listen: 0.0.0.0:5
tls: { cert: a, key: b }
clients:
  - id: a
    pubkey: ed25519:K
    pq_pubkey: mldsa:K
    services: [ { name: x, listen: 0.0.0.0:1 } ]
limits: { heartbeat_interval: -1s, idle_timeout: 60s }`,
			"heartbeat_interval",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p := writeFile(t, "s.yaml", tc.yml)
			_, err := LoadServer(p)
			if err == nil {
				t.Fatalf("expected error containing %q", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("error %q does not contain %q", err.Error(), tc.want)
			}
		})
	}
}

func TestLoadClient_Valid(t *testing.T) {
	yml := `
remote: example.com:5679
server_fingerprint: sha256:` + strings.Repeat("ab", 32) + `
identity:
  id: dirac-prod
  privkey_file: /etc/passage/client.ed25519
  pq_privkey_file: /etc/passage/client.mldsa
services:
  ssh: 192.168.2.34:22
  pg:  192.168.2.41:5432
reconnect:
  initial_backoff: 1s
  max_backoff: 60s
  jitter: true
`
	p := writeFile(t, "c.yaml", yml)
	c, err := LoadClient(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(c.Services) != 2 {
		t.Errorf("services: %+v", c.Services)
	}
}

func TestLoadClient_NegativeBackoff(t *testing.T) {
	yml := `
remote: example.com:5679
server_fingerprint: sha256:` + strings.Repeat("ab", 32) + `
identity: { id: a, privkey_file: /tmp/k, pq_privkey_file: /tmp/k.mldsa }
services: { ssh: 1.2.3.4:22 }
reconnect: { initial_backoff: -1s, max_backoff: 60s }
`
	p := writeFile(t, "c.yaml", yml)
	if _, err := LoadClient(p); err == nil || !strings.Contains(err.Error(), "initial_backoff") {
		t.Fatalf("want initial_backoff error, got %v", err)
	}
}

func TestLoadServer_PQPubkey(t *testing.T) {
	const yml = `
listen: 0.0.0.0:5679
tls: { cert: a, key: b }
clients:
  - id: a
    pubkey: ed25519:K
    pq_pubkey: mldsa:AAAA
    services: [ { name: ssh, listen: 0.0.0.0:3022 } ]
`
	p := writeFile(t, "s.yaml", yml)
	c, err := LoadServer(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(c.Clients[0].PQPubkey) != 1 {
		t.Fatalf("expected 1 pq_pubkey, got %d", len(c.Clients[0].PQPubkey))
	}
}

func TestLoadServer_PQPubkeyAsList(t *testing.T) {
	const yml = `
listen: 0.0.0.0:5679
tls: { cert: a, key: b }
clients:
  - id: a
    pubkey: ed25519:K
    pq_pubkey:
      - mldsa:OLD
      - mldsa:NEW
    services: [ { name: ssh, listen: 0.0.0.0:3022 } ]
`
	p := writeFile(t, "s.yaml", yml)
	c, err := LoadServer(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(c.Clients[0].PQPubkey) != 2 {
		t.Fatalf("expected 2 pq_pubkeys, got %d", len(c.Clients[0].PQPubkey))
	}
}

func TestLoadClient_PQPrivkey(t *testing.T) {
	yml := `
remote: example.com:5679
server_fingerprint: sha256:` + strings.Repeat("ab", 32) + `
identity:
  id: a
  privkey_file: /tmp/k
  pq_privkey_file: /tmp/k.mldsa
services: { ssh: 1.2.3.4:22 }
`
	p := writeFile(t, "c.yaml", yml)
	c, err := LoadClient(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if c.Identity.PQPrivkeyFile != "/tmp/k.mldsa" {
		t.Errorf("pq_privkey_file mismatch: %q", c.Identity.PQPrivkeyFile)
	}
}

func TestLoadClient_MissingPQPrivkey(t *testing.T) {
	yml := `
remote: example.com:5679
server_fingerprint: sha256:` + strings.Repeat("ab", 32) + `
identity: { id: a, privkey_file: /tmp/k }
services: { ssh: 1.2.3.4:22 }
`
	p := writeFile(t, "c.yaml", yml)
	if _, err := LoadClient(p); err == nil || !strings.Contains(err.Error(), "pq_privkey_file is required") {
		t.Fatalf("want pq_privkey_file required error, got %v", err)
	}
}

func TestLoadClient_BadFingerprint(t *testing.T) {
	yml := `
remote: example.com:5679
server_fingerprint: foo
identity: { id: a, privkey_file: /tmp/k, pq_privkey_file: /tmp/k.mldsa }
services: { ssh: 1.2.3.4:22 }
`
	p := writeFile(t, "c.yaml", yml)
	if _, err := LoadClient(p); err == nil || !strings.Contains(err.Error(), "fingerprint") {
		t.Fatalf("want fingerprint error, got %v", err)
	}
}
