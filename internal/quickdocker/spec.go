package quickdocker

import (
	"errors"
	"fmt"
	"net"
	"os"
	"regexp"
	"strings"

	"gopkg.in/yaml.v3"
)

type Spec struct {
	Server      ServerSection           `yaml:"server"`
	Client      ClientSection           `yaml:"client"`
	ProjectName string                  `yaml:"project_name"`
	Services    map[string]ServiceEntry `yaml:"services"`
}

type ServerSection struct {
	Listen  string `yaml:"listen"`
	Address string `yaml:"address"`
	Mode    string `yaml:"mode"`
}

type ClientSection struct {
	Identity ClientIdentity `yaml:"identity"`
	Mode     string         `yaml:"mode"`
}

type ClientIdentity struct {
	ID string `yaml:"id"`
}

type ServiceEntry struct {
	Client string `yaml:"client"`
	Server string `yaml:"server"`
}

func Load(path string) (*Spec, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var s Spec
	dec := yaml.NewDecoder(strings.NewReader(string(data)))
	dec.KnownFields(true)
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("quick-docker spec %s: %w", path, err)
	}
	if err := s.Validate(); err != nil {
		return nil, fmt.Errorf("quick-docker spec %s: %w", path, err)
	}
	return &s, nil
}

func (s *Spec) Validate() error {
	if s.Server.Listen == "" {
		return errors.New("server.listen is required")
	}
	if _, _, err := net.SplitHostPort(s.Server.Listen); err != nil {
		return fmt.Errorf("server.listen: %w", err)
	}
	if s.Server.Address == "" {
		return errors.New("server.address is required")
	}
	if _, _, err := net.SplitHostPort(s.Server.Address); err != nil {
		return fmt.Errorf("server.address: %w", err)
	}
	if err := validateMode(s.Server.Mode, "server.mode"); err != nil {
		return err
	}
	if err := validateMode(s.Client.Mode, "client.mode"); err != nil {
		return err
	}
	if s.Client.Identity.ID == "" {
		return errors.New("client.identity.id is required")
	}
	if s.ProjectName != "" && !projectNameRE.MatchString(s.ProjectName) {
		return fmt.Errorf("project_name %q must match [a-z0-9][a-z0-9_-]*", s.ProjectName)
	}
	if len(s.Services) == 0 {
		return errors.New("at least one service is required")
	}
	seenServerListen := map[string]string{}
	for name, sv := range s.Services {
		if name == "" {
			return errors.New("service name must not be empty")
		}
		if sv.Client == "" {
			return fmt.Errorf("services.%s.client is required", name)
		}
		if _, _, err := net.SplitHostPort(sv.Client); err != nil {
			return fmt.Errorf("services.%s.client: %w", name, err)
		}
		if sv.Server == "" {
			return fmt.Errorf("services.%s.server is required", name)
		}
		if _, _, err := net.SplitHostPort(sv.Server); err != nil {
			return fmt.Errorf("services.%s.server: %w", name, err)
		}
		if owner, dup := seenServerListen[sv.Server]; dup {
			return fmt.Errorf("services.%s.server %q is reused (already used by %q)", name, sv.Server, owner)
		}
		seenServerListen[sv.Server] = name
	}
	return nil
}

var projectNameRE = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]*$`)

func validateMode(mode, field string) error {
	switch mode {
	case "host", "isolated":
		return nil
	case "":
		return fmt.Errorf("%s is required (host or isolated)", field)
	default:
		return fmt.Errorf("%s must be 'host' or 'isolated', got %q", field, mode)
	}
}
