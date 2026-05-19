package quickdocker

import (
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/jfhack/passage/internal/auth"
)

const Image = "ghcr.io/jfhack/passage:latest"

type GenerateOptions struct {
	OutDir string
	Force  bool
}

type GenerateResult struct {
	ServerDir     string
	ClientDir     string
	Fingerprint   string
	PubKey        string
	PQPubKey      string
	ServerProject string
	ClientProject string
}

func Generate(spec *Spec, opts GenerateOptions) (*GenerateResult, error) {
	serverDir := filepath.Join(opts.OutDir, "server")
	clientDir := filepath.Join(opts.OutDir, "client")
	if err := ensureFreshDir(serverDir, opts.Force); err != nil {
		return nil, err
	}
	if err := ensureFreshDir(clientDir, opts.Force); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(serverDir, "keys"), 0o755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Join(clientDir, "keys"), 0o755); err != nil {
		return nil, err
	}

	tls, err := generateSelfSignedTLS()
	if err != nil {
		return nil, fmt.Errorf("tls keypair: %w", err)
	}
	if err := os.WriteFile(filepath.Join(serverDir, "keys", "server.crt"), tls.CertPEM, 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(serverDir, "keys", "server.key"), tls.KeyPEM, 0o644); err != nil {
		return nil, err
	}

	pub, priv, err := auth.GenerateKeypair()
	if err != nil {
		return nil, fmt.Errorf("ed25519 keypair: %w", err)
	}
	clientKeyPath := filepath.Join(clientDir, "keys", "client.ed25519")
	if err := auth.WritePrivkeyPEM(clientKeyPath, priv); err != nil {
		return nil, err
	}
	if err := os.Chmod(clientKeyPath, 0o644); err != nil {
		return nil, err
	}
	pubEnc := auth.EncodePubkey(pub)

	pqPub, _, pqSeed, err := auth.GeneratePQKeypair()
	if err != nil {
		return nil, fmt.Errorf("ml-dsa keypair: %w", err)
	}
	clientPQKeyPath := filepath.Join(clientDir, "keys", "client.mldsa")
	if err := auth.WritePQPrivkeyPEM(clientPQKeyPath, pqSeed); err != nil {
		return nil, err
	}
	if err := os.Chmod(clientPQKeyPath, 0o644); err != nil {
		return nil, err
	}
	pqPubEnc := auth.EncodePQPubkey(pqPub)

	if err := os.WriteFile(filepath.Join(serverDir, "server.yaml"), []byte(renderServerYAML(spec, pubEnc, pqPubEnc)), 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(serverDir, "docker-compose.yml"), []byte(renderServerCompose(spec)), 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(clientDir, "client.yaml"), []byte(renderClientYAML(spec, tls.Fingerprint)), 0o644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filepath.Join(clientDir, "docker-compose.yml"), []byte(renderClientCompose(spec)), 0o644); err != nil {
		return nil, err
	}

	return &GenerateResult{
		ServerDir:     serverDir,
		ClientDir:     clientDir,
		Fingerprint:   tls.Fingerprint,
		PubKey:        pubEnc,
		PQPubKey:      pqPubEnc,
		ServerProject: composeProjectName(spec, "server"),
		ClientProject: composeProjectName(spec, "client"),
	}, nil
}

func ensureFreshDir(path string, force bool) error {
	info, err := os.Stat(path)
	if err == nil {
		if !info.IsDir() {
			return fmt.Errorf("output path %q exists and is not a directory", path)
		}
		if !force {
			return fmt.Errorf("output dir %q already exists (pass -force to overwrite)", path)
		}
		if err := os.RemoveAll(path); err != nil {
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	return os.MkdirAll(path, 0o755)
}

func renderServerYAML(spec *Spec, clientPubkey, clientPQPubkey string) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "listen: %s\n\n", spec.Server.Listen)
	sb.WriteString("tls:\n")
	sb.WriteString("  cert: /etc/passage/server.crt\n")
	sb.WriteString("  key:  /etc/passage/server.key\n\n")
	sb.WriteString("clients:\n")
	fmt.Fprintf(&sb, "  - id: %s\n", spec.Client.Identity.ID)
	fmt.Fprintf(&sb, "    pubkey: %s\n", clientPubkey)
	fmt.Fprintf(&sb, "    pq_pubkey: %s\n", clientPQPubkey)
	sb.WriteString("    services:\n")
	for _, name := range sortedServiceNames(spec.Services) {
		fmt.Fprintf(&sb, "      - name: %s\n", name)
		fmt.Fprintf(&sb, "        listen: %s\n", serverListenForService(spec, spec.Services[name]))
	}
	sb.WriteString("\nlimits:\n")
	sb.WriteString("  max_streams_per_client: 256\n")
	sb.WriteString("  handshake_timeout: 10s\n")
	sb.WriteString("  idle_timeout: 5m\n")
	sb.WriteString("  heartbeat_interval: 30s\n")
	return sb.String()
}

func serverListenForService(spec *Spec, sv ServiceEntry) string {
	if spec.Server.Mode == "host" {
		return sv.Server
	}
	_, port, _ := net.SplitHostPort(sv.Server)
	return "0.0.0.0:" + port
}

func renderClientYAML(spec *Spec, fingerprint string) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "remote: %s\n\n", spec.Server.Address)
	fmt.Fprintf(&sb, "server_fingerprint: %s\n\n", fingerprint)
	sb.WriteString("identity:\n")
	fmt.Fprintf(&sb, "  id: %s\n", spec.Client.Identity.ID)
	sb.WriteString("  privkey_file: /etc/passage/client.ed25519\n")
	sb.WriteString("  pq_privkey_file: /etc/passage/client.mldsa\n\n")
	sb.WriteString("services:\n")
	for _, name := range sortedServiceNames(spec.Services) {
		fmt.Fprintf(&sb, "  %s: %s\n", name, spec.Services[name].Client)
	}
	sb.WriteString("\nreconnect:\n")
	sb.WriteString("  initial_backoff: 1s\n")
	sb.WriteString("  max_backoff: 60s\n")
	sb.WriteString("  jitter: true\n")
	return sb.String()
}

func renderServerCompose(spec *Spec) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "name: %s\n\n", composeProjectName(spec, "server"))
	sb.WriteString("services:\n")
	sb.WriteString("  passage:\n")
	fmt.Fprintf(&sb, "    image: %s\n", Image)
	fmt.Fprintf(&sb, "    container_name: %s\n", containerName(spec, "server"))
	sb.WriteString("    restart: unless-stopped\n")
	if spec.Server.Mode == "host" {
		sb.WriteString("    network_mode: host\n")
	} else {
		sb.WriteString("    ports:\n")
		for _, mapping := range serverPublishedPorts(spec) {
			fmt.Fprintf(&sb, "      - %q\n", mapping)
		}
	}
	sb.WriteString("    volumes:\n")
	sb.WriteString("      - ./keys/server.crt:/etc/passage/server.crt:ro\n")
	sb.WriteString("      - ./keys/server.key:/etc/passage/server.key:ro\n")
	sb.WriteString("      - ./server.yaml:/etc/passage/server.yaml:ro\n")
	sb.WriteString("    command: [\"server\", \"-config\", \"/etc/passage/server.yaml\"]\n")
	return sb.String()
}

func serverPublishedPorts(spec *Spec) []string {
	out := []string{hostPortMapping(spec.Server.Listen)}
	for _, name := range sortedServiceNames(spec.Services) {
		out = append(out, hostPortMapping(spec.Services[name].Server))
	}
	return out
}

func hostPortMapping(addr string) string {
	host, port, _ := net.SplitHostPort(addr)
	if host == "" || host == "0.0.0.0" || host == "::" {
		return port + ":" + port
	}
	return host + ":" + port + ":" + port
}

func renderClientCompose(spec *Spec) string {
	var sb strings.Builder
	fmt.Fprintf(&sb, "name: %s\n\n", composeProjectName(spec, "client"))
	sb.WriteString("services:\n")
	sb.WriteString("  passage:\n")
	fmt.Fprintf(&sb, "    image: %s\n", Image)
	fmt.Fprintf(&sb, "    container_name: %s\n", containerName(spec, "client"))
	sb.WriteString("    restart: unless-stopped\n")
	if spec.Client.Mode == "host" {
		sb.WriteString("    network_mode: host\n")
	}
	sb.WriteString("    volumes:\n")
	sb.WriteString("      - ./keys/client.ed25519:/etc/passage/client.ed25519:ro\n")
	sb.WriteString("      - ./keys/client.mldsa:/etc/passage/client.mldsa:ro\n")
	sb.WriteString("      - ./client.yaml:/etc/passage/client.yaml:ro\n")
	sb.WriteString("    command: [\"client\", \"-config\", \"/etc/passage/client.yaml\"]\n")
	return sb.String()
}

func containerName(spec *Spec, role string) string {
	base := "passage-" + role
	if spec.ProjectName == "" {
		return base
	}
	return spec.ProjectName + "-" + base
}

func composeProjectName(spec *Spec, role string) string {
	return containerName(spec, role)
}

func sortedServiceNames(m map[string]ServiceEntry) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
